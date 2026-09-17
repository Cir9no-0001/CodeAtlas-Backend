# core/config.py

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    session_secret_key: str
    environment: str = "development"

    github_client_id: str
    github_client_secret: str
    google_client_id: str
    google_client_secret: str

    oauth_redirect_base_url: str  # e.g. http://localhost:8000
    extension_oauth_redirect_url: str

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8")


settings = Settings()
