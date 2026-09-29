"""Pydantic schemas for auth requests and responses."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from backend.app.models.user import UserRole


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_not_trivial(cls, v: str) -> str:
        if v.isdigit() or v.isalpha():
            raise ValueError(
                "Password must contain a mix of letters and numbers or special characters."
            )
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: UserRole
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
