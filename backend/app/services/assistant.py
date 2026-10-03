"""
AEGIS AI Security Assistant service.

Responsibilities:
- Build a controlled prompt from user message + conversation history +
  optional scan context.
- Call Gemini via the shared gemini service.
- Sanitise and validate the response before returning it.

Security constraints:
- System instructions are prepended to every prompt and cannot be overridden
  by user input.
- Scan context carries safe metadata only (no raw passwords, no email bodies).
- Gemini output is treated as untrusted generated content and sanitised.
- The assistant is advisory/educational only — it cannot execute actions.
"""
from __future__ import annotations

import logging
import re

from backend.app.schemas.assistant import (
    AssistantRequest,
    AssistantResponse,
    ChatMessage,
    ScanContext,
)
from backend.app.services import gemini as gemini_svc
from backend.app.services.gemini import GeminiError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
_MAX_REPLY_LEN = 2000       # characters; longer replies are truncated
_MAX_HISTORY_TURNS = 10     # pairs kept; older turns dropped
_MAX_FOLLOWUP_LEN = 100     # characters per follow-up suggestion
_NUM_FOLLOWUPS = 3          # number of follow-up suggestions to generate

# ---------------------------------------------------------------------------
# Dangerous-pattern guard — same approach as ai_validator
# ---------------------------------------------------------------------------
_DANGEROUS_PATTERNS = re.compile(
    r"(ignore (previous|all) instructions?|"
    r"you are now|new persona|disregard|"
    r"<script|javascript:|data:text/html|"
    r"eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# System instructions — injected at the top of every prompt
# ---------------------------------------------------------------------------
_SYSTEM_INSTRUCTIONS = """\
You are the AEGIS Security Assistant — an educational cybersecurity advisor \
embedded in the AEGIS personal security dashboard.

YOUR PURPOSE:
- Educate users about cybersecurity concepts, threats, and best practices.
- Explain AEGIS scan results (URL analysis, phishing email analysis, \
password strength) in plain language.
- Give defensive, actionable recommendations.
- Answer general cybersecurity questions clearly and calmly.

STRICT RULES — YOU MUST ALWAYS FOLLOW THESE:
1. Be educational and advisory. You are NOT an agent; you cannot execute \
commands, access external systems, run code, or take actions on behalf of users.
2. Do NOT fabricate scan results, threat-intelligence data, or specific facts \
you were not given. If you are uncertain, say so explicitly.
3. Do NOT claim certainty when evidence is insufficient. Use phrases like \
"this may indicate", "this is a common pattern", "I cannot confirm without \
more information".
4. Never request, repeat, guess, or store passwords, API keys, or any \
credentials. If a user tries to paste a password, tell them not to.
5. Keep responses calm and proportionate. Do not use alarmist language.
6. Do not provide instructions for offensive hacking, malware creation, \
exploiting vulnerabilities, or any illegal activity.
7. If a question is outside cybersecurity, briefly acknowledge it and redirect \
the conversation to security topics.
8. Keep responses concise — aim for 2–4 paragraphs unless a detailed \
explanation is clearly needed.
"""

# ---------------------------------------------------------------------------
# Fallback replies — specific to each failure mode
# ---------------------------------------------------------------------------
_FALLBACK: dict[str, tuple[str, str]] = {
    # (reply shown to user, error code for the response)
    "not_configured": (
        "The AI assistant is not available because the Gemini API key has not "
        "been configured. Your scan results are produced by the deterministic "
        "heuristic engine and are fully accurate without AI.",
        "AI service not configured",
    ),
    "init_failed": (
        "The AI assistant could not start due to a configuration error. "
        "Please contact your administrator.",
        "AI service initialisation failed",
    ),
    "timeout": (
        "The AI assistant did not respond in time. This is usually a temporary "
        "network issue. Please try your question again in a moment.",
        "AI service timeout",
    ),
    "api_error": (
        "The AI assistant encountered an error communicating with the Gemini API. "
        "This may be a temporary outage. Please try again shortly.",
        "AI service API error",
    ),
    "empty_response": (
        "The AI assistant returned an empty response. "
        "Please try rephrasing your question.",
        "AI service returned empty response",
    ),
    "invalid_response": (
        "The AI assistant returned an unusable response. "
        "Please try rephrasing your question.",
        "Invalid response from AI service",
    ),
}


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def _format_history(history: list[ChatMessage]) -> str:
    """Format prior turns as a conversation block."""
    if not history:
        return ""
    lines: list[str] = ["CONVERSATION HISTORY (oldest first):"]
    # Keep only the last _MAX_HISTORY_TURNS * 2 messages
    recent = history[-(  _MAX_HISTORY_TURNS * 2):]
    for msg in recent:
        prefix = "User" if msg.role == "user" else "Assistant"
        # Truncate each history entry to 500 chars to control prompt size
        content = msg.content[:500].replace("\n", " ")
        lines.append(f"  {prefix}: {content}")
    return "\n".join(lines)


def _format_scan_context(ctx: ScanContext | None) -> str:
    """Format optional scan context as a structured block."""
    if ctx is None:
        return ""
    lines: list[str] = ["SCAN CONTEXT (from a recent AEGIS analysis):"]
    if ctx.scan_type:
        lines.append(f"  Scan type: {ctx.scan_type}")
    if ctx.risk_level:
        lines.append(f"  Risk level: {ctx.risk_level}")
    if ctx.risk_score is not None:
        lines.append(f"  Risk score: {ctx.risk_score}/100")
    if ctx.indicator_names:
        lines.append("  Detected indicators:")
        for name in ctx.indicator_names[:10]:
            lines.append(f"    - {name}")
    if ctx.safe_metadata:
        lines.append("  Metadata:")
        for k, v in list(ctx.safe_metadata.items())[:6]:
            lines.append(f"    {k}: {v}")
    lines.append(
        "NOTE: This context was produced by AEGIS heuristic analysis. "
        "Only reference it if the user's question is about this scan."
    )
    return "\n".join(lines)


def _build_prompt(req: AssistantRequest) -> str:
    """Assemble the full prompt: instructions + history + context + question."""
    parts: list[str] = [_SYSTEM_INSTRUCTIONS]

    history_block = _format_history(req.history)
    if history_block:
        parts.append(history_block)

    ctx_block = _format_scan_context(req.scan_context)
    if ctx_block:
        parts.append(ctx_block)

    parts.append(f"USER QUESTION:\n{req.message}")
    parts.append(
        "Respond as the AEGIS Security Assistant following all rules above. "
        "Plain text only — no markdown headers, no bullet symbols, no code blocks "
        "unless the user explicitly asks for code."
    )
    return "\n\n---\n\n".join(parts)


# ---------------------------------------------------------------------------
# Follow-up suggestion generation
# ---------------------------------------------------------------------------

# Topic-keyed fallback pools so we always have suggestions even without AI
_FOLLOWUP_FALLBACKS: dict[str, list[str]] = {
    "phishing": [
        "How can I verify if an email sender is legitimate?",
        "What should I do after clicking a phishing link?",
        "How do attackers spoof email addresses?",
        "What are the most common phishing red flags?",
        "How does DMARC protect against email spoofing?",
    ],
    "password": [
        "What is the safest way to store passwords?",
        "How long should a secure password be?",
        "Should I use a password manager?",
        "What makes a passphrase stronger than a password?",
        "How do brute-force attacks work?",
    ],
    "url": [
        "What makes a URL suspicious?",
        "How do URL shorteners hide malicious links?",
        "What is typosquatting?",
        "How can I safely preview a suspicious link?",
        "What does a high-risk URL score mean?",
    ],
    "general": [
        "What is two-factor authentication and why should I use it?",
        "How do I know if my accounts have been compromised?",
        "What is the difference between a virus and malware?",
        "How does HTTPS protect my data in transit?",
        "What is social engineering in cybersecurity?",
    ],
}

_FOLLOWUP_KEYWORDS: dict[str, list[str]] = {
    "phishing": ["phish", "email", "spam", "spoof", "sender", "attachment", "link"],
    "password": ["password", "passphrase", "entropy", "hash", "credential", "brute"],
    "url":      ["url", "link", "domain", "website", "redirect", "scan"],
}


def _infer_topic(text: str) -> str:
    """Heuristically pick a fallback topic from the message text."""
    lower = text.lower()
    for topic, keywords in _FOLLOWUP_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return topic
    return "general"


def _parse_followups(raw: str) -> list[str]:
    """Extract clean follow-up questions from raw Gemini output."""
    lines = [
        line.strip().lstrip("•-–—0123456789.) ").strip()
        for line in raw.splitlines()
        if line.strip()
    ]
    valid: list[str] = []
    for line in lines:
        if (
            5 < len(line) <= _MAX_FOLLOWUP_LEN
            and "?" in line
            and not _DANGEROUS_PATTERNS.search(line)
        ):
            valid.append(line)
        if len(valid) >= _NUM_FOLLOWUPS:
            break
    return valid


def _generate_followups(user_message: str, assistant_reply: str) -> list[str]:
    """
    Generate context-relevant follow-up suggestions from the curated topic pool.

    We intentionally do NOT make a second Gemini API call here — doing so
    would double the rate-limit exposure per user turn and introduce a second
    failure point that could cascade into an api_error on the next main call.
    The curated pool is topic-inferred and already high-quality.
    """
    import random

    topic = _infer_topic(user_message + " " + assistant_reply)
    pool = _FOLLOWUP_FALLBACKS[topic].copy()
    random.shuffle(pool)
    return pool[:_NUM_FOLLOWUPS]


# ---------------------------------------------------------------------------
# Response sanitisation
# ---------------------------------------------------------------------------

def _sanitise_reply(raw: str) -> str | None:
    """
    Clean the Gemini reply string.
    Returns None if the reply is unusable or dangerous.
    """
    if not isinstance(raw, str):
        return None
    # Strip null bytes and control characters (keep newlines)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw).strip()
    if not cleaned:
        return None
    if _DANGEROUS_PATTERNS.search(cleaned):
        logger.warning("Dangerous pattern in assistant reply — discarding")
        return None
    if len(cleaned) > _MAX_REPLY_LEN:
        # Truncate at the last sentence boundary within the limit
        truncated = cleaned[:_MAX_REPLY_LEN]
        last_period = max(
            truncated.rfind(". "),
            truncated.rfind(".\n"),
        )
        if last_period > _MAX_REPLY_LEN // 2:
            truncated = truncated[: last_period + 1]
        cleaned = truncated.rstrip() + "\n\n*(Response truncated for length.)*"
    return cleaned


def _make_fallback(key: str) -> AssistantResponse:
    reply, error = _FALLBACK.get(key, _FALLBACK["api_error"])
    return AssistantResponse(reply=reply, ai_available=False, error=error)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def chat(req: AssistantRequest) -> AssistantResponse:
    """
    Process one assistant turn.

    Returns AssistantResponse with ai_available=False on any failure —
    the caller should surface the error message to the user gracefully.
    The error field on the response contains a machine-readable error code.
    """
    if not gemini_svc.is_available():
        err = gemini_svc.last_error()
        key = err.value if err else "not_configured"
        logger.info("Assistant: Gemini unavailable (%s)", key)
        return _make_fallback(key)

    prompt = _build_prompt(req)
    raw, err = gemini_svc.generate(prompt)

    if err is not None:
        return _make_fallback(err.value)

    reply = _sanitise_reply(raw)
    if reply is None:
        return _make_fallback("invalid_response")

    follow_ups = _generate_followups(req.message, reply)

    return AssistantResponse(
        reply=reply,
        ai_available=True,
        follow_up_suggestions=follow_ups,
    )
