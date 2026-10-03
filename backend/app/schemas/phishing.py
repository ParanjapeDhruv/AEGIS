"""Pydantic schemas for phishing email analysis."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from backend.app.schemas.url_analysis import Indicator


class EmailAnalysisRequest(BaseModel):
    sender: str = Field(default="", max_length=500)
    reply_to: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    body: str = Field(min_length=1, max_length=50_000)
    links: list[str] = Field(default_factory=list, max_length=50)
    attachment_names: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("body")
    @classmethod
    def body_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("body must contain non-whitespace content")
        return v

    @field_validator("links", mode="before")
    @classmethod
    def trim_links(cls, v: list) -> list:
        return [str(link)[:2048].strip() for link in v if str(link).strip()]

    @field_validator("attachment_names", mode="before")
    @classmethod
    def trim_attachment_names(cls, v: list) -> list:
        return [str(name)[:255].strip() for name in v if str(name).strip()]


class EmailAnalysisResult(BaseModel):
    scan_id: int
    risk_score: int                          # 0-100
    risk_level: Literal["safe", "low", "medium", "high", "critical"]
    indicators: list[Indicator]
    recommendations: list[str]
    scanned_at: datetime
    analysis_version: str | None = None
