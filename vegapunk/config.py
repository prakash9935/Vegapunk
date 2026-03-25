"""
Central configuration — all settings from environment variables.
Triage uses Haiku (cheap), analyst uses Sonnet (powerful).
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Anthropic ──────────────────────────────────────────────────────────
    anthropic_api_key: str = Field(..., description="Anthropic API key")
    triage_model: str = "claude-haiku-4-5-20251001"        # Fast + cheap
    analyst_model: str = "claude-sonnet-4-6"               # Deep analysis
    triage_confidence_threshold: float = 0.75              # Escalate if below

    # ── Storage ────────────────────────────────────────────────────────────
    chroma_persist_dir: Path = DATA_DIR / "chroma"
    sqlite_path: Path = DATA_DIR / "vegapunk.db"
    chroma_collection: str = "siem_logs"
    embedding_model: str = "all-MiniLM-L6-v2"             # Free, local

    # ── Ingestion ──────────────────────────────────────────────────────────
    chunk_window_minutes: int = 15                          # Time-window size
    max_chunk_events: int = 100                            # Max events/chunk
    ingest_queue_size: int = 1000

    # ── Interfaces ─────────────────────────────────────────────────────────
    slack_bot_token: str | None = None
    slack_signing_secret: str | None = None
    streamlit_port: int = 8501

    # ── Agent memory ───────────────────────────────────────────────────────
    memory_window_k: int = 10                              # Sliding window turns

    # ── Wazuh Cloud ────────────────────────────────────────────────────────
    wazuh_cloud_url: str | None = None          # e.g. https://my-env.wazuh.cloud
    wazuh_username: str = "admin"
    wazuh_password: str | None = None
    wazuh_verify_ssl: bool = False              # Cloud uses self-signed certs
    wazuh_poll_interval: int = 60              # Seconds between polls

    # ── Misc ───────────────────────────────────────────────────────────────
    log_level: LogLevel = LogLevel.INFO
    max_rag_results: int = 8


settings = Settings()  # type: ignore[call-arg]
