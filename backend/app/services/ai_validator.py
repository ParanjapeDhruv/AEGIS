"""
Gemini response validation for AEGIS.

Gemini output is untrusted generated content. This module:
- Parses and validates the expected JSON structure.
- Sanitises string fields (length, no null bytes, printable only).
- Rejects responses that contain dangerous patterns.
- Returns None on any validation failure so the caller can fall back.
"""
from __future__ import annotations

import json
import logging
import re

from backend.app.schemas.ai import AiExplainRequest, AiExplanation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
_MAX_OVERVIEW_LEN = 800
_MAX_NOTE_LEN = 300
_MAX_REC_LEN = 300
_MAX_ITEMS = 5       # max indicator_notes / recommendations list length

# Patterns that should never appear in a security explanation
# (prompt injection attempts, code execution, HTML/script injection)
_DANGEROUS_PATTERNS = re.compile(
    r"(ignore (previous|all) instructions?|"
    r"you are now|new persona|disregard|"
    r"<script|javascript:|data:text/html|"
    r"eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)


def _sanitise(text: str, max_len: int) -> str | None:
    """
    Clean a single string field from Gemini.
    Returns None if the field is unusable.
    """
    if not isinstance(text, str):
        return None
    # Strip null bytes and non-printable control characters (keep newlines/tabs)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).strip()
    if not cleaned:
        return None
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip() + "…"
    if _DANGEROUS_PATTERNS.search(cleaned):
        logger.warning("Dangerous pattern detected in Gemini output — discarding field")
        return None
    return cleaned


def _sanitise_list(items: object, max_len: int, max_items: int) -> list[str]:
    """Clean a list of strings from Gemini."""
    if not isinstance(items, list):
        return []
    result: list[str] = []
    for item in items[:max_items]:
        clean = _sanitise(str(item), max_len)
        if clean:
            result.append(clean)
    return result


def _extract_json(raw: str) -> dict | None:
    """
    Extract a JSON object from Gemini output.
    Handles cases where Gemini wraps JSON in markdown fences.
    """
    # Strip markdown code fences if present
    stripped = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
    stripped = re.sub(r"\s*```$", "", stripped.strip())

    # Try direct parse first
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Try to extract the first {...} block
    m = re.search(r"\{[\s\S]+\}", stripped)
    if m:
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    logger.warning("Could not extract JSON from Gemini response")
    return None


def validate_ai_response(
    raw: str,
    req: AiExplainRequest,
) -> AiExplanation | None:
    """
    Validate and sanitise a raw Gemini response string.

    Returns an AiExplanation on success, or None if the response is
    malformed, dangerous, or missing required fields.
    The caller must fall back gracefully on None.
    """
    if not raw or len(raw) > 8000:
        logger.warning("Gemini response out of acceptable length range")
        return None

    data = _extract_json(raw)
    if data is None:
        return None

    overview = _sanitise(data.get("overview", ""), _MAX_OVERVIEW_LEN)
    if not overview:
        logger.warning("Gemini response missing valid 'overview' field")
        return None

    indicator_notes = _sanitise_list(
        data.get("indicator_notes", []), _MAX_NOTE_LEN, _MAX_ITEMS
    )
    recommendations = _sanitise_list(
        data.get("recommendations", []), _MAX_REC_LEN, _MAX_ITEMS
    )

    # Ensure at least one recommendation is present
    if not recommendations:
        if req.scan_type == "url":
            recommendations = ["Verify the URL carefully before proceeding."]
        elif req.scan_type == "email":
            recommendations = ["Do not click links or open attachments from this email."]
        else:
            recommendations = ["Use a password manager to generate a stronger password."]

    return AiExplanation(
        overview=overview,
        indicator_notes=indicator_notes or ["No significant indicators to highlight."],
        recommendations=recommendations,
        ai_available=True,
    )
