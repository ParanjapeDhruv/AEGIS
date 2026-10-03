"""
Prompt templates for Gemini AI security explanations.

Rules baked into every prompt:
- Only explain the provided evidence — do not invent new indicators.
- Do not request, repeat, or infer raw passwords or credentials.
- Acknowledge uncertainty; do not present guesses as facts.
- Output must follow the exact JSON structure so it can be validated.
"""
from __future__ import annotations

from backend.app.schemas.ai import AiExplainRequest

# ---------------------------------------------------------------------------
# Shared system preamble injected into every prompt
# ---------------------------------------------------------------------------
_SYSTEM_PREAMBLE = """\
You are a cybersecurity assistant for AEGIS, an AI-powered security dashboard.
Your role is to explain heuristic scan results to a non-expert user in clear, \
plain English.

STRICT RULES YOU MUST FOLLOW:
1. Only explain the evidence provided — never invent indicators or facts not present.
2. Never request, repeat, guess, or infer any password, credential, or secret.
3. Keep explanations factual and calm — avoid alarmist language.
4. If the risk is low or safe, say so clearly; do not inflate concern.
5. Acknowledge that heuristic analysis has limits; only the listed indicators \
were detected.
6. Respond ONLY with a valid JSON object in the exact structure shown below — \
no prose before or after the JSON.

REQUIRED OUTPUT FORMAT (valid JSON, no markdown fences):
{
  "overview": "<one paragraph plain-English summary of the overall risk>",
  "indicator_notes": ["<one note per significant indicator, max 5>"],
  "recommendations": ["<1–4 actionable recommendations>"]
}
"""

# ---------------------------------------------------------------------------
# Per-scan-type context builders
# ---------------------------------------------------------------------------

def _url_context(req: AiExplainRequest) -> str:
    host = req.context_fields.get("host", "unknown host")
    tld = req.context_fields.get("tld", "")
    ind_lines = "\n".join(
        f"  - [{i.severity.upper()}] {i.name}: {i.detail}"
        for i in req.indicators
    ) or "  (none)"
    return f"""\
SCAN TYPE: URL analysis
URL HOST: {host}{(' .' + tld) if tld else ''}
RISK SCORE: {req.risk_score}/100  RISK LEVEL: {req.risk_level.upper()}

DETECTED INDICATORS:
{ind_lines}

Explain to the user:
- What these indicators mean in plain language.
- Why the URL host/structure raises concern (or does not).
- What the user should do before visiting this URL.
- Remind the user that HTTPS alone does not make a site safe.
"""


def _email_context(req: AiExplainRequest) -> str:
    subject = req.context_fields.get("subject", "(no subject)")
    sender_domain = req.context_fields.get("sender_domain", "unknown")
    ind_lines = "\n".join(
        f"  - [{i.severity.upper()}] {i.name}: {i.detail}"
        for i in req.indicators
    ) or "  (none)"
    return f"""\
SCAN TYPE: Phishing email analysis
EMAIL SUBJECT: {subject}
SENDER DOMAIN: {sender_domain}
RISK SCORE: {req.risk_score}/100  RISK LEVEL: {req.risk_level.upper()}

DETECTED INDICATORS:
{ind_lines}

Explain to the user:
- What phishing techniques appear to be used based on the indicators.
- Why the sender/content raises concern (or does not).
- What the user should do (or avoid doing) with this email.
- Do NOT repeat or infer the email body content.
"""


def _password_context(req: AiExplainRequest) -> str:
    # Deliberately minimal — no password content whatsoever
    entropy = req.context_fields.get("entropy_bits", "unknown")
    length = req.context_fields.get("length", "unknown")
    ind_lines = "\n".join(
        f"  - {i.name}: {i.detail}"
        for i in req.indicators
    ) or "  (none)"
    return f"""\
SCAN TYPE: Password strength analysis
PASSWORD LENGTH: {length} characters
ENTROPY: {entropy} bits
STRENGTH LEVEL: {req.risk_level.upper()}  SCORE: {req.risk_score}/100

DETECTED WEAKNESSES:
{ind_lines}

IMPORTANT: You have NOT been given the password and must NOT ask for it, \
guess it, or reference any specific characters.

Explain to the user:
- Why the password scored at this strength level based only on the weaknesses listed.
- What entropy means and why it matters.
- Concrete steps to choose a stronger password.
"""


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------

def build_prompt(req: AiExplainRequest) -> str:
    """Construct the full prompt string for the given scan type."""
    if req.scan_type == "url":
        context = _url_context(req)
    elif req.scan_type == "email":
        context = _email_context(req)
    else:  # password
        context = _password_context(req)

    return f"{_SYSTEM_PREAMBLE}\n---\n{context}"
