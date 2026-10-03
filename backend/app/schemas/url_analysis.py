"""Pydantic schemas for URL analysis."""

from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import re


class UrlAnalysisRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        # Must start with http:// or https://
        if not re.match(r"^https?://", v, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")
        return v


class Indicator(BaseModel):
    name: str
    detail: str
    severity: str   # "info" | "low" | "medium" | "high"


class UrlAnalysisResult(BaseModel):
    scan_id: int
    normalized_url: str
    risk_score: int          # 0-100
    risk_level: str          # "safe" | "low" | "medium" | "high" | "critical"
    indicators: list[Indicator]
    recommendations: list[str]
    scanned_at: datetime
