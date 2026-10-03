"""Pydantic schemas for URL analysis — v2."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
import re

from pydantic import BaseModel, Field, field_validator


class UrlAnalysisRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://", v, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")
        # Reject empty host after scheme
        from urllib.parse import urlsplit
        p = urlsplit(v.replace("\\", "/"))
        if not p.netloc or not p.netloc.replace("@", "").strip("/"):
            raise ValueError("URL must contain a valid host")
        return v


class Indicator(BaseModel):
    id: str | None = None                                    # stable machine key
    name: str
    detail: str
    severity: Literal["info", "low", "medium", "high"]
    weight: int | None = None                                # 0-100, informational


class UrlAnalysisResult(BaseModel):
    scan_id: int
    normalized_url: str
    risk_score: int
    risk_level: Literal["safe", "low", "medium", "high", "critical"]
    indicators: list[Indicator]
    recommendations: list[str]
    scanned_at: datetime
    analysis_version: str | None = None                     # optional, additive
