"""AI explanation endpoint — POST /api/v1/ai/explain

Accepts heuristic evidence (indicators, score, level) and returns a
Gemini-generated plain-English explanation.

Security constraints:
- Raw passwords are NEVER accepted or forwarded.
- The Gemini API key is server-side only; it is never sent to the frontend.
- Gemini output is validated before being returned.
- If Gemini is unavailable the endpoint returns a graceful fallback.
- Rate-limited to 10 requests / 60 s per user.
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.api.deps import get_current_user
from backend.app.models.user import User
from backend.app.schemas.ai import AiExplainRequest, AiExplanation
from backend.app.services import gemini as gemini_svc
from backend.app.services.ai_prompts import build_prompt
from backend.app.services.ai_validator import validate_ai_response

router = APIRouter(prefix="/v1/ai", tags=["ai"])

# ---------------------------------------------------------------------------
# Per-user rate limiter — 10 AI requests / 60 s (AI calls are expensive)
# ---------------------------------------------------------------------------
_RATE_LIMIT = 10
_RATE_WINDOW = 60

_rate_store: dict[int, list[float]] = defaultdict(list)
_rate_lock = Lock()


def _check_rate_limit(user_id: int) -> None:
    now = time.monotonic()
    with _rate_lock:
        window_start = now - _RATE_WINDOW
        timestamps = [t for t in _rate_store[user_id] if t > window_start]
        if len(timestamps) >= _RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"AI rate limit exceeded. Maximum {_RATE_LIMIT} explanations per minute.",
            )
        timestamps.append(now)
        _rate_store[user_id] = timestamps


# ---------------------------------------------------------------------------
# Fallback explanation when Gemini is unavailable
# ---------------------------------------------------------------------------

def _fallback(req: AiExplainRequest) -> AiExplanation:
    """Return a deterministic explanation built from heuristic data alone."""
    ind_notes = [
        f"{i.name}: {i.detail}" for i in req.indicators if i.severity in ("high", "medium")
    ][:5]
    recs: list[str] = []
    if req.risk_level in ("high", "critical"):
        recs.append("Exercise extreme caution — multiple high-severity signals were detected.")
    if req.scan_type == "url":
        recs.append("Do not visit this URL unless you can independently verify its legitimacy.")
    elif req.scan_type == "email":
        recs.append("Do not click links or open attachments from this email.")
    elif req.scan_type == "password":
        recs.append("Use a password manager to generate and store a stronger password.")

    return AiExplanation(
        overview=(
            f"The {req.scan_type} analysis returned a risk score of {req.risk_score}/100 "
            f"({req.risk_level}). {len(req.indicators)} indicator(s) were detected."
        ),
        indicator_notes=ind_notes or ["No high/medium indicators detected."],
        recommendations=recs or ["No additional recommendations at this risk level."],
        ai_available=False,
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/explain",
    response_model=AiExplanation,
    status_code=status.HTTP_200_OK,
    summary="Get an AI-generated explanation of heuristic scan results",
)
def explain(
    payload: AiExplainRequest,
    current_user: User = Depends(get_current_user),
) -> AiExplanation:
    """
    Generate a plain-English AI explanation of detected security indicators.

    - Accepts heuristic evidence only — no raw passwords, no full email bodies.
    - Gemini is called with a structured prompt built from the evidence.
    - Response is validated before being returned.
    - Falls back to a deterministic summary if Gemini is unavailable.
    """
    _check_rate_limit(current_user.id)

    if not gemini_svc.is_available():
        return _fallback(payload)

    prompt = build_prompt(payload)
    raw_response = gemini_svc.generate(prompt)

    if raw_response is None:
        return _fallback(payload)

    explanation = validate_ai_response(raw_response, payload)
    if explanation is None:
        return _fallback(payload)

    return explanation
