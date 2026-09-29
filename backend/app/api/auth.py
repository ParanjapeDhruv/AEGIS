"""Authentication API routes — register, login, me."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user
from backend.app.core.database import get_db
from backend.app.core.security import create_access_token, hash_password, verify_password
from backend.app.models.user import User
from backend.app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """
    Create a new user.

    - Validates input (Pydantic).
    - Hashes the password with bcrypt — the plaintext is never persisted.
    - Returns a JWT access token immediately so the user is logged in.
    - Raises **409** if the email is already registered.
    """
    user = User(
        name=payload.name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        # role defaults to UserRole.user
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    token = create_access_token(subject=user.id)
    return TokenResponse(access_token=token, user=UserResponse.model_validate(user))


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT",
)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """
    Authenticate a user with email + password.

    - Uses a single generic error message for both wrong email and wrong
      password to avoid user-enumeration attacks.
    - Returns a JWT access token on success.
    """
    user = db.query(User).filter(User.email == payload.email.lower()).first()

    # Deliberate: same error for "not found" and "wrong password"
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    token = create_access_token(subject=user.id)
    return TokenResponse(access_token=token, user=UserResponse.model_validate(user))


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Return the currently authenticated user",
)
def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    """Protected endpoint — requires a valid Bearer token."""
    return UserResponse.model_validate(current_user)
