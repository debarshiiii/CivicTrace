from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str

    # Optional -- if unset, AI photo triage is skipped gracefully
    # (cases just fall back to a flat default risk_score).
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-flash-latest"

    class Config:
        env_file = ".env"

settings = Settings()