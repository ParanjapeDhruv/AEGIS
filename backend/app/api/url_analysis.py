"""URL analysis API route — POST /api/v1/analysis/url"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user
from backend.app.core.database import get_db
from backend.app.models.scan import RiskLevel, Scan, ScanType
from backend.app.models.user import User
from backend.app.schemas.url_analysis import UrlAnalysisRequest, UrlAnalysisResult
from backend.app.services.url_analyzer import analyse_url

router = APIRouter(prefix="/v1/analysis", tags=["analysis"])


@router.post(
    "/url",
    response_model=UrlAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyse a URL for phishing and threat indicators",
)
def analyse_url_endpoint(
    payload: UrlAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UrlAnalysisResult:
    """
    Perform deterministic risk analysis on a URL.

    - Input is validated (must be a well-formed http/https URL).
    - No external threat-intelligence APIs are called.
    - HTTPS is noted but is NOT used as a safety signal.
    - The normalised URL (not the raw input) is stored with scan metadata.
    """
    normalized, score, level, indicators, recommendations = analyse_url(payload.url)

    # Persist scan metadata — raw password is never stored here (URL only)
    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.url,
        target=normalized[:2048],
        risk_level=RiskLevel(level),
        risk_score=score,
        summary=json.dumps([i.name for i in indicators])[:500],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return UrlAnalysisResult(
        scan_id=scan.id,
        normalized_url=normalized,
        risk_score=score,
        risk_level=level,
        indicators=indicators,
        recommendations=recommendations,
        scanned_at=scan.created_at,
    )
