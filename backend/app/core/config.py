"""Application configuration — loaded from environment / .env file."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env relative to the repo root (two levels up from this file:
# backend/app/core/config.py → backend/app/core → backend/app → backend → repo root)
_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_ENV: str = "development"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    DATABASE_URL: str  # required — must be set in .env

    JWT_SECRET_KEY: str  # required — must be set in .env
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    GEMINI_API_KEY: str = ""


settings = Settings()
