"""Scan database model — stores metadata for every analysis, never raw passwords."""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class ScanType(str, enum.Enum):
    url      = "url"
    phishing = "phishing"
    password = "password"


class RiskLevel(str, enum.Enum):
    safe     = "safe"
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int]         = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int]    = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    scan_type: Mapped[ScanType]   = mapped_column(Enum(ScanType), nullable=False)
    target: Mapped[str]     = mapped_column(String(2048), nullable=False)   # URL / email subject
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)        # 0-100
    summary: Mapped[str]    = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
