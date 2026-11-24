from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    SECRET_KEY: str

    # Optional -- if unset, AI photo triage is skipped gracefully
    # (cases fall back to a flat default risk score and manual review).
    GEMINI_API_KEY: Optional[str] = None

    # "gemini-flash-latest" is Google's moving alias for the newest Flash
    # model, so it keeps working when specific model names are retired.
    GEMINI_MODEL: str = "gemini-flash-latest"
    GEMINI_FALLBACK_MODEL: str = "gemini-flash-latest"
    GEMINI_API_REVISION: str = "2026-05-20"
    GEMINI_TIMEOUT_SECONDS: float = 20.0

    # Comma separated list of allowed browser origins, or "*" for any.
    # Authentication uses Bearer tokens (not cookies), so "*" is safe
    # for local development; set explicit origins in production.
    CORS_ORIGINS: str = "*"

    # Map background tiles are fetched by the SERVER and passed on to the
    # browser (/api/map/tiles/...), so the provider key never reaches the
    # browser. MAP_TILE_URL may contain {z} {x} {y} and {key}.
    MAP_TILE_URL: str = "https://a.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png"
    MAP_API_KEY: Optional[str] = None
    MAP_TILES_PER_MINUTE: int = 1500  # per client IP

    # Login throttling (per email + client IP, in-memory).
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15


settings = Settings()