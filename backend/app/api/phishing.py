"""Phishing email analysis API route — POST /api/v1/analysis/email"""

import json
import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, get_db
from backend.app.models.scan import RiskLevel, Scan, ScanType
from backend.app.models.user import User
from backend.app.schemas.phishing import EmailAnalysisRequest, EmailAnalysisResult
from backend.app.services.phishing_analyzer import ANALYSIS_VERSION, analyse_email

router = APIRouter(prefix="/v1/analysis", tags=["analysis"])

# ---------------------------------------------------------------------------
# Per-user token-bucket rate limiter — 20 requests / 60 s
# ---------------------------------------------------------------------------
_RATE_LIMIT = 20
_RATE_WINDOW = 60  # seconds

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
                detail=f"Rate limit exceeded. Maximum {_RATE_LIMIT} email scans per minute.",
            )
        timestamps.append(now)
        _rate_store[user_id] = timestamps


@router.post(
    "/email",
    response_model=EmailAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyse an email for phishing indicators",
)
def analyse_email_endpoint(
    payload: EmailAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EmailAnalysisResult:
    """
    Deterministic phishing indicator analysis of a submitted email.

    - Email content is treated as untrusted input.
    - Attachments are never executed; links are never opened.
    - No Gemini/AI call is made — detection is fully heuristic.
    - Returns HTTP 429 when the per-user rate limit is exceeded.
    """
    _check_rate_limit(current_user.id)

    score, level, indicators, recommendations = analyse_email(
        sender=payload.sender,
        reply_to=payload.reply_to,
        subject=payload.subject,
        body=payload.body,
        links=payload.links,
        attachment_names=payload.attachment_names,
    )

    # Store only the subject as the target (safe — not the body)
    target = (payload.subject[:500] if payload.subject else "no subject")

    # Summary: list of indicator ids, JSON-truncated to fit the 500-char column
    summary_items = [i.id or i.name for i in indicators]
    summary = json.dumps(summary_items)
    while len(summary) > 500 and summary_items:
        summary_items.pop()
        summary = json.dumps(summary_items)

    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.phishing,
        target=target,
        risk_level=RiskLevel(level),
        risk_score=score,
        summary=summary,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return EmailAnalysisResult(
        scan_id=scan.id,
        risk_score=score,
        risk_level=level,
        indicators=indicators,
        recommendations=recommendations,
        scanned_at=scan.created_at,
        analysis_version=ANALYSIS_VERSION,
    )
