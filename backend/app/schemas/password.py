"""Pydantic schemas for password analysis."""

from pydantic import BaseModel, Field


class PasswordAnalysisRequest(BaseModel):
    # The password is received, analysed in-memory, and immediately discarded.
    # It is never stored, logged, or forwarded to any external service.
    password: str = Field(min_length=1, max_length=256)


class PasswordAnalysisResult(BaseModel):
    score: int                    # 0-100
    level: str                    # "very_weak" | "weak" | "moderate" | "strong" | "very_strong"
    entropy_bits: float
    weaknesses: list[str]
    recommendations: list[str]
    character_stats: dict         # breakdown counts — no raw password content
