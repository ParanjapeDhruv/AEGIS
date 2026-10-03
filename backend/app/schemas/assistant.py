"""Pydantic schemas for the AI Security Assistant."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Conversation history entry — one turn (user or assistant)
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


# ---------------------------------------------------------------------------
# Optional security context — attached by the frontend when the user is
# asking about a specific scan they just ran.  All fields are optional so
# the assistant can be used for general cybersecurity questions too.
#
# IMPORTANT: no raw passwords, no full email bodies, no API keys.
# ---------------------------------------------------------------------------

class ScanContext(BaseModel):
    scan_type: Literal["url", "email", "password"] | None = None
    risk_level: str | None = Field(default=None, max_length=20)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    # Human-readable indicator names only — no internal ids or raw content
    indicator_names: list[str] = Field(default_factory=list, max_length=10)
    # Safe metadata: URL host, email subject, password length/entropy only
    safe_metadata: dict[str, str] = Field(default_factory=dict, max_length=6)


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class AssistantRequest(BaseModel):
    """
    A single chat turn sent from the frontend.

    - message: the user's current question (required).
    - history: the preceding conversation turns, oldest first (max 10 pairs).
    - scan_context: optional evidence from a recent scan — never raw secrets.
    """
    message: str = Field(min_length=1, max_length=2000)
    history: list[ChatMessage] = Field(default_factory=list, max_length=20)
    scan_context: ScanContext | None = None

    @field_validator("message")
    @classmethod
    def message_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must contain non-whitespace content")
        return v.strip()


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class AssistantResponse(BaseModel):
    """Reply from the AI Security Assistant."""
    reply: str                  # Gemini's response text (sanitised)
    ai_available: bool          # False when Gemini is unconfigured or failed
    error: str | None = None    # Set only when ai_available is False
    follow_up_suggestions: list[str] = Field(
        default_factory=list,
        description="Context-relevant follow-up questions the user may want to ask next.",
        max_length=4,
    )
