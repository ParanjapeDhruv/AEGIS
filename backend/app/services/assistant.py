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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
_MAX_REPLY_LEN = 2000       # characters; longer replies are truncated
_MAX_HISTORY_TURNS = 10     # pairs kept; older turns dropped

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
# Fallback replies
# ---------------------------------------------------------------------------
_FALLBACK_UNAVAILABLE = (
    "The AI assistant is temporarily unavailable — the Gemini API key is not "
    "configured or the service could not be reached. "
    "Your security scan results above were produced by the deterministic "
    "heuristic engine and are accurate regardless of AI availability."
)

_FALLBACK_TIMEOUT = (
    "The AI assistant did not respond in time. This is usually a temporary "
    "network issue. Please try again in a moment."
)

_FALLBACK_INVALID = (
    "The AI assistant returned an unusable response. Please try rephrasing "
    "your question."
)


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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def chat(req: AssistantRequest) -> AssistantResponse:
    """
    Process one assistant turn.

    Returns AssistantResponse with ai_available=False on any failure —
    the caller should surface the error message to the user gracefully.
    """
    if not gemini_svc.is_available():
        logger.info("Assistant: Gemini unavailable")
        return AssistantResponse(
            reply=_FALLBACK_UNAVAILABLE,
            ai_available=False,
            error="AI service not configured",
        )

    prompt = _build_prompt(req)
    raw = gemini_svc.generate(prompt)

    if raw is None:
        # generate() already logged the specific error (timeout vs API failure)
        # Distinguish timeout from other failures via the gemini module's log,
        # but present a generic safe message to the user either way.
        return AssistantResponse(
            reply=_FALLBACK_TIMEOUT,
            ai_available=False,
            error="AI service timeout or unavailable",
        )

    reply = _sanitise_reply(raw)
    if reply is None:
        return AssistantResponse(
            reply=_FALLBACK_INVALID,
            ai_available=False,
            error="Invalid response from AI service",
        )

    return AssistantResponse(reply=reply, ai_available=True)
