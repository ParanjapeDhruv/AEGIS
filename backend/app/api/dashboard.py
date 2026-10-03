"""Dashboard API — GET /api/v1/dashboard/summary

Returns a single authenticated summary object containing:
- Threat statistics (total, by risk level)
- Recent scan list (last 10, safe for display)
- Raw inputs needed for the frontend to compute the security score
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user
from backend.app.core.database import get_db
from backend.app.models.scan import RiskLevel, Scan, ScanType
from backend.app.models.user import User

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class RecentScanItem(BaseModel):
    id: int
    scan_type: str          # "url" | "phishing" | "password"
    target: str             # safe redacted target
    risk_level: str         # "safe" | "low" | "medium" | "high" | "critical"
    risk_score: int
    scanned_at: datetime


class ThreatStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    safe: int


class DashboardSummary(BaseModel):
    threat_stats: ThreatStats
    recent_scans: list[RecentScanItem]
    # Separate week count for the "recent scans" card subtitle
    scans_this_week: int


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Get authenticated user's dashboard summary",
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> DashboardSummary:
    """
    Aggregate scan statistics for the authenticated user.
    No business logic is duplicated — this only reads the scans table.
    """
    uid = current_user.id

    # --- Total counts by risk level ---
    counts: dict[str, int] = {level.value: 0 for level in RiskLevel}
    rows = (
        db.query(Scan.risk_level, func.count(Scan.id))
        .filter(Scan.user_id == uid)
        .group_by(Scan.risk_level)
        .all()
    )
    for risk_level, count in rows:
        counts[risk_level.value] = count

    total = sum(counts.values())

    threat_stats = ThreatStats(
        total=total,
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        safe=counts.get("safe", 0),
    )

    # --- Scans this week ---
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    scans_this_week: int = (
        db.query(func.count(Scan.id))
        .filter(Scan.user_id == uid, Scan.created_at >= week_ago)
        .scalar()
        or 0
    )

    # --- Recent scans (last 10, newest first) ---
    recent_rows = (
        db.query(Scan)
        .filter(Scan.user_id == uid)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    recent_scans = [
        RecentScanItem(
            id=s.id,
            scan_type=s.scan_type.value,
            target=s.target,
            risk_level=s.risk_level.value,
            risk_score=s.risk_score,
            scanned_at=s.created_at,
        )
        for s in recent_rows
    ]

    return DashboardSummary(
        threat_stats=threat_stats,
        recent_scans=recent_scans,
        scans_this_week=scans_this_week,
    )
