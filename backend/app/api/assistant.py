"""Security assistant API endpoint — POST /api/v1/assistant/chat

Security constraints:
- Requires authenticated user (Bearer token).
- Only the message, conversation history, and safe scan metadata are accepted.
- Raw passwords, API keys, and full email bodies are never forwarded.
- Rate-limited to 15 requests / 60 s per user.
- Gemini API key is server-side only; never exposed to the frontend.
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.api.deps import get_current_user
from backend.app.models.user import User
from backend.app.schemas.assistant import AssistantRequest, AssistantResponse
from backend.app.services.assistant import chat
from backend.app.services import gemini as gemini_svc

router = APIRouter(prefix="/v1/assistant", tags=["assistant"])

# ---------------------------------------------------------------------------
# Per-user token-bucket rate limiter — 15 messages / 60 s
# ---------------------------------------------------------------------------
_RATE_LIMIT = 15
_RATE_WINDOW = 60

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
                detail=(
                    f"Assistant rate limit exceeded. "
                    f"Maximum {_RATE_LIMIT} messages per minute."
                ),
            )
        timestamps.append(now)
        _rate_store[user_id] = timestamps


@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    summary="Check AI assistant availability",
)
def assistant_status(
    _current_user: User = Depends(get_current_user),
) -> dict:
    """
    Returns whether the AI assistant is available.
    The Gemini API key itself is never included in the response.
    """
    available = gemini_svc.is_available()
    err = gemini_svc.last_error()
    return {
        "available": available,
        "error_code": err.value if err else None,
    }


@router.post(
    "/chat",
    response_model=AssistantResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a message to the AEGIS AI Security Assistant",
)
def assistant_chat(
    payload: AssistantRequest,
    current_user: User = Depends(get_current_user),
) -> AssistantResponse:
    """
    Chat with the AEGIS AI Security Assistant.

    - The assistant is educational and advisory only.
    - It cannot execute actions or access external systems.
    - Scan context (if provided) must contain safe metadata only.
    - Returns a graceful fallback if Gemini is unavailable.
    """
    _check_rate_limit(current_user.id)
    return chat(payload)
