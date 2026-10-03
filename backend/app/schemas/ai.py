"""Pydantic schemas for the AI explanation endpoint."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class IndicatorEvidence(BaseModel):
    """A single detected indicator passed to Gemini — no raw secrets."""
    id: str | None = None
    name: str
    detail: str
    severity: str


class AiExplainRequest(BaseModel):
    """
    Evidence-only payload sent from the frontend to the AI endpoint.

    Rules enforced here:
    - scan_type identifies which analyser produced the evidence.
    - indicators is the list of detected findings (names + details only).
    - risk_score and risk_level are the heuristic outputs.
    - context_fields carries safe metadata (URL host, email subject, etc.)
      — NEVER the raw password, full email body, or full URL with credentials.
    """
    scan_type: Literal["url", "email", "password"]
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["safe", "low", "medium", "high", "critical"]
    indicators: list[IndicatorEvidence] = Field(default_factory=list, max_length=20)
    # Safe metadata only — no secrets, no raw credentials
    context_fields: dict[str, str] = Field(default_factory=dict, max_length=10)


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class AiExplanation(BaseModel):
    """Structured AI explanation returned to the caller."""
    overview: str            # one-paragraph plain-English risk summary
    indicator_notes: list[str]   # one bullet per significant indicator
    recommendations: list[str]   # actionable advice beyond heuristic recs
    ai_available: bool       # False when Gemini is unconfigured or failed
    disclaimer: str = (
        "AI explanations are generated content and may contain errors. "
        "Security decisions must be based on the detected indicators above, "
        "not solely on this explanation."
    )
