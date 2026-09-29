"""Password analysis API route — POST /api/v1/analysis/password"""

from fastapi import APIRouter, Depends, status

from backend.app.api.deps import get_current_user
from backend.app.models.user import User
from backend.app.schemas.password import PasswordAnalysisRequest, PasswordAnalysisResult
from backend.app.services.password_analyzer import analyse

router = APIRouter(prefix="/v1/analysis", tags=["analysis"])


@router.post(
    "/password",
    response_model=PasswordAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyse password strength",
)
def analyse_password(
    payload: PasswordAnalysisRequest,
    _current_user: User = Depends(get_current_user),
) -> PasswordAnalysisResult:
    """
    Analyse the submitted password deterministically.

    - The password is **never** stored, logged, or sent to any external service.
    - Returns a structured strength result with score, level, weaknesses and
      recommendations.
    - Requires a valid Bearer token.
    """
    result = analyse(payload.password)
    # payload.password goes out of scope here — not persisted anywhere
    return result
