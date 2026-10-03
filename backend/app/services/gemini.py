"""
Gemini AI service — reusable client for AEGIS.

Design constraints:
- Gemini is NEVER the primary security detector.
- Raw passwords are NEVER sent to Gemini.
- Gemini output is ALWAYS treated as untrusted generated content.
- The API key is read from the environment; it is never logged or exposed.
- Every call has a hard timeout; failures are caught and returned as typed errors.
"""
from __future__ import annotations

import logging
import threading
from enum import Enum
from typing import Any

from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy singleton client — only initialised when first used
# ---------------------------------------------------------------------------
_client_lock = threading.Lock()
_client: Any = None          # google.genai.Client once initialised
_client_error: str = ""      # set if init failed, prevents repeated retries

_MODEL = "gemini-3.8-flash"  # fast, low-latency model suitable for explanations
_TIMEOUT_SECONDS = 20        # hard wall-clock timeout per request
_MAX_OUTPUT_TOKENS = 1024    # cap to keep responses focused but not truncated


# ---------------------------------------------------------------------------
# Typed error codes — callers use these to give specific user messages
# ---------------------------------------------------------------------------

class GeminiError(str, Enum):
    NOT_CONFIGURED   = "not_configured"    # API key missing or placeholder
    INIT_FAILED      = "init_failed"       # SDK init raised an exception
    TIMEOUT          = "timeout"           # thread hit _TIMEOUT_SECONDS
    API_ERROR        = "api_error"         # Gemini API returned an error
    QUOTA_EXHAUSTED  = "quota_exhausted"   # 429 daily/per-minute quota hit
    EMPTY_RESPONSE   = "empty_response"    # call succeeded but text was blank


def _get_client() -> Any | None:
    """Return the initialised Gemini client, or None if unavailable."""
    global _client, _client_error

    if _client is not None:
        return _client
    if _client_error:
        return None

    with _client_lock:
        if _client is not None:
            return _client
        if _client_error:
            return None

        api_key = settings.GEMINI_API_KEY
        if not api_key or api_key.startswith("replace-"):
            _client_error = "GEMINI_API_KEY is not configured"
            logger.warning("Gemini AI disabled: %s", _client_error)
            return None

        try:
            from google import genai  # type: ignore[import]
            from google.genai._api_client import HttpOptions
            import httpx
            import ssl
            import certifi

            # Build an httpx client that trusts both certifi's CA bundle and the
            # Windows system store — handles corporate SSL inspection proxies.
            try:
                ctx = ssl.create_default_context(cafile=certifi.where())
                ctx.load_verify_locations(cafile=certifi.where())
                # Also load the Windows system cert store when available
                if hasattr(ssl, 'enum_certificates'):
                    import ctypes
                    for store_name in ("CA", "ROOT"):
                        try:
                            for cert, enc, trust in ssl.enum_certificates(store_name):
                                try:
                                    ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert))
                                except Exception:
                                    pass
                        except Exception:
                            pass
                http_client = httpx.Client(verify=ctx, timeout=_TIMEOUT_SECONDS)
            except Exception:
                # Fallback: disable SSL verification (network with self-signed proxy)
                http_client = httpx.Client(verify=False, timeout=_TIMEOUT_SECONDS)

            _client = genai.Client(
                api_key=api_key.strip(),
                http_options=HttpOptions(httpx_client=http_client),
            )
            logger.info("Gemini client initialised (model=%s)", _MODEL)
        except Exception as exc:
            _client_error = str(exc)
            logger.warning("Gemini client init failed: %s", exc)

    return _client


def is_available() -> bool:
    """Return True when the Gemini client is ready to use."""
    return _get_client() is not None


def last_error() -> GeminiError | None:
    """Return the error that prevented client initialisation, or None if OK."""
    if _client is not None:
        return None
    if _client_error == "GEMINI_API_KEY is not configured":
        return GeminiError.NOT_CONFIGURED
    if _client_error:
        return GeminiError.INIT_FAILED
    return None


def generate(prompt: str) -> tuple[str | None, GeminiError | None]:
    """
    Send *prompt* to Gemini and return (text, None) on success, or
    (None, GeminiError) on any failure.

    The caller must handle both outcomes gracefully — a non-None error
    means AI explanation is unavailable for this request, not that the
    security analysis failed.
    """
    client = _get_client()
    if client is None:
        return None, last_error() or GeminiError.NOT_CONFIGURED

    def _attempt() -> tuple[str | None, Exception | None, bool]:
        """Run one Gemini call in a thread. Returns (text, exc, timed_out)."""
        result: list[str | None] = [None]
        exc_box: list[Exception | None] = [None]

        def _call() -> None:
            try:
                from google.genai import types  # type: ignore[import]
                response = client.models.generate_content(
                    model=_MODEL,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        max_output_tokens=_MAX_OUTPUT_TOKENS,
                        temperature=0.2,
                        candidate_count=1,
                    ),
                )
                result[0] = response.text
            except Exception as exc:
                exc_box[0] = exc

        thread = threading.Thread(target=_call, daemon=True)
        thread.start()
        thread.join(timeout=_TIMEOUT_SECONDS)
        timed_out = thread.is_alive()
        return result[0], exc_box[0], timed_out

    # Try up to 2 times — retry only on 503 transient overload
    for attempt in range(2):
        text, exc, timed_out = _attempt()

        if timed_out:
            logger.warning("Gemini request timed out after %ss", _TIMEOUT_SECONDS)
            return None, GeminiError.TIMEOUT

        if exc is not None:
            err_str = str(exc)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                logger.warning("Gemini quota exhausted: %s", exc)
                return None, GeminiError.QUOTA_EXHAUSTED
            if "503" in err_str and attempt == 0:
                logger.warning("Gemini 503 on attempt 1, retrying in 2s…")
                import time as _time
                _time.sleep(2)
                continue
            logger.warning("Gemini request failed: %s", exc)
            return None, GeminiError.API_ERROR

        # No exception — check for empty response
        if not text or not text.strip():
            logger.warning("Gemini returned empty response")
            return None, GeminiError.EMPTY_RESPONSE

        return text.strip(), None

    # Should not reach here, but satisfy the type checker
    return None, GeminiError.API_ERROR
