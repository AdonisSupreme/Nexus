"""Production-minded configuration for SentinelOps AI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Centralized configuration validated on startup."""

    APP_NAME: str = "SentinelOps AI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=False, env="DEBUG")

    BASE_DIR: Path = Path(__file__).resolve().parents[2]
    KNOWLEDGE_ROOT: Path = BASE_DIR / "knowledge"
    PRIMARY_KNOWLEDGE_DIR: Path = KNOWLEDGE_ROOT / "sops"
    SECONDARY_KNOWLEDGE_DIR: Path = KNOWLEDGE_ROOT / "Under_dev_sop-e-verification-health"
    DATA_DIR: Path = BASE_DIR / "data"
    RAW_SNAPSHOT_DIR: Path = DATA_DIR / "raw"
    NORMALIZED_DIR: Path = DATA_DIR / "normalized"
    INDEX_DIR: Path = DATA_DIR / "index"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    JOBS_DIR: Path = DATA_DIR / "jobs"
    VECTOR_STORE_PATH: Path = DATA_DIR / "vector_store"
    LOGS_DIR: Path = BASE_DIR / "logs"

    API_HOST: str = Field(default="0.0.0.0", env="API_HOST")
    API_PORT: int = Field(default=8010, env="API_PORT")
    API_WORKERS: int = Field(default=1, env="API_WORKERS")
    API_RELOAD: bool = Field(default=False, env="API_RELOAD")

    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(
        default="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
        env="LOG_FORMAT",
    )
    LOG_DATE_FORMAT: str = Field(default="%Y-%m-%d %H:%M:%S", env="LOG_DATE_FORMAT")

    AUDIT_LOG_FILE: str = Field(default="audit.log", env="AUDIT_LOG_FILE")
    AUDIT_LOG_MAX_SIZE: int = Field(default=10485760, env="AUDIT_LOG_MAX_SIZE")
    AUDIT_LOG_BACKUP_COUNT: int = Field(default=5, env="AUDIT_LOG_BACKUP_COUNT")

    EMBEDDING_MODEL: str = Field(default="BAAI/bge-small-en-v1.5", env="EMBEDDING_MODEL")
    EMBEDDING_BACKEND: str = Field(default="auto", env="EMBEDDING_BACKEND")
    EMBEDDING_DEVICE: str = Field(default="cpu", env="EMBEDDING_DEVICE")
    EMBEDDING_DIMENSION: int = Field(default=384, env="EMBEDDING_DIMENSION")
    EMBEDDING_BATCH_SIZE: int = Field(default=32, env="EMBEDDING_BATCH_SIZE")
    RERANK_MODEL: str = Field(default="cross-encoder/ms-marco-MiniLM-L-6-v2", env="RERANK_MODEL")
    ENABLE_RERANKING: bool = Field(default=True, env="ENABLE_RERANKING")
    VECTOR_STORE_TYPE: str = Field(default="local", env="VECTOR_STORE_TYPE")

    MISTRAL_API_KEY: SecretStr | None = Field(default=None, env="MISTRAL_API_KEY")
    MISTRAL_API_BASE_URL: str = Field(default="https://api.mistral.ai", env="MISTRAL_API_BASE_URL")
    MISTRAL_MODEL: str = Field(default="mistral-small-latest", env="MISTRAL_MODEL")
    MISTRAL_CLASSIFICATION_MODEL: str | None = Field(default=None, env="MISTRAL_CLASSIFICATION_MODEL")
    MISTRAL_MODERATION_MODEL: str = Field(default="mistral-moderation-latest", env="MISTRAL_MODERATION_MODEL")
    MISTRAL_TEMPERATURE: float = Field(default=0.1, env="MISTRAL_TEMPERATURE")
    MISTRAL_MAX_TOKENS: int = Field(default=900, env="MISTRAL_MAX_TOKENS")
    MISTRAL_TIMEOUT_SECONDS: float = Field(default=25.0, env="MISTRAL_TIMEOUT_SECONDS")
    MISTRAL_MAX_RETRIES: int = Field(default=2, env="MISTRAL_MAX_RETRIES")
    MISTRAL_CIRCUIT_BREAKER_THRESHOLD: int = Field(default=3, env="MISTRAL_CIRCUIT_BREAKER_THRESHOLD")
    ENABLE_CLASSIFIER_ENDPOINTS: bool = Field(default=True, env="ENABLE_CLASSIFIER_ENDPOINTS")
    ENABLE_MODERATION_GUARDRAILS: bool = Field(default=False, env="ENABLE_MODERATION_GUARDRAILS")

    CORS_ORIGINS: list[str] = Field(default_factory=lambda: ["http://localhost:3000"], env="CORS_ORIGINS")
    ADMIN_API_TOKEN: SecretStr | None = Field(default=None, env="ADMIN_API_TOKEN")

    DATABASE_URL: SecretStr | None = Field(default=None, env="DATABASE_URL")
    POSTGRES_DSN: SecretStr | None = Field(default=None, env="POSTGRES_DSN")
    SECRET_KEY: SecretStr | None = Field(default=None, env="SECRET_KEY")
    ALGORITHM: str = Field(default="HS256", env="ALGORITHM")
    NEXUS_REQUIRE_DATABASE: bool = Field(default=True, env="NEXUS_REQUIRE_DATABASE")
    NEXUS_ALLOW_LOCAL_STATE: bool = Field(default=False, env="NEXUS_ALLOW_LOCAL_STATE")
    NEXUS_WRITE_ROLES: list[str] = Field(default_factory=lambda: ["admin", "manager", "supervisor"], env="NEXUS_WRITE_ROLES")
    NEXUS_ADMIN_ROLES: list[str] = Field(default_factory=lambda: ["admin"], env="NEXUS_ADMIN_ROLES")
    NEXUS_ALLOWED_SECTION_IDS: list[str] = Field(
        default_factory=lambda: ["7bd4144d-68d8-4ac3-897d-245941612daf"],
        env="NEXUS_ALLOWED_SECTION_IDS",
    )
    NEXUS_REQUIRE_AGENT_AUTH: bool = Field(default=True, env="NEXUS_REQUIRE_AGENT_AUTH")
    NEXUS_AGENT_API_TOKEN: SecretStr | None = Field(default=None, env="NEXUS_AGENT_API_TOKEN")
    REDIS_URL: SecretStr | None = Field(default=None, env="REDIS_URL")
    QDRANT_URL: str | None = Field(default=None, env="QDRANT_URL")
    QDRANT_API_KEY: SecretStr | None = Field(default=None, env="QDRANT_API_KEY")

    SOP_VALIDATION_STRICT: bool = Field(default=True, env="SOP_VALIDATION_STRICT")
    SOP_ALLOWED_CLASSES: list[str] = Field(
        default_factory=lambda: ["A", "B", "C", "D", "E", "F"],
        env="SOP_ALLOWED_CLASSES",
    )

    MAX_SOP_RETRIEVAL: int = Field(default=8, env="MAX_SOP_RETRIEVAL")
    MAX_EVIDENCE_CITATIONS: int = Field(default=6, env="MAX_EVIDENCE_CITATIONS")
    REQUEST_TIMEOUT: int = Field(default=30, env="REQUEST_TIMEOUT")
    CACHE_TTL_SECONDS: int = Field(default=300, env="CACHE_TTL_SECONDS")
    LOW_CONFIDENCE_THRESHOLD: float = Field(default=0.45, env="LOW_CONFIDENCE_THRESHOLD")
    HIGH_CONFIDENCE_THRESHOLD: float = Field(default=0.72, env="HIGH_CONFIDENCE_THRESHOLD")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        allowed = {"development", "testing", "staging", "production"}
        if value not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {sorted(allowed)}")
        return value

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return upper

    @field_validator("EMBEDDING_BACKEND")
    @classmethod
    def validate_embedding_backend(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {"auto", "hash", "sentence-transformers"}
        if normalized not in allowed:
            raise ValueError(f"EMBEDDING_BACKEND must be one of {sorted(allowed)}")
        return normalized

    @field_validator("CORS_ORIGINS", "SOP_ALLOWED_CLASSES", "NEXUS_WRITE_ROLES", "NEXUS_ADMIN_ROLES", "NEXUS_ALLOWED_SECTION_IDS", mode="before")
    @classmethod
    def parse_list_values(cls, value: Any) -> Any:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                return json.loads(stripped)
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @field_validator(
        "KNOWLEDGE_ROOT",
        "PRIMARY_KNOWLEDGE_DIR",
        "SECONDARY_KNOWLEDGE_DIR",
        "DATA_DIR",
        "RAW_SNAPSHOT_DIR",
        "NORMALIZED_DIR",
        "INDEX_DIR",
        "REPORTS_DIR",
        "JOBS_DIR",
        "VECTOR_STORE_PATH",
        "LOGS_DIR",
        mode="after",
    )
    @classmethod
    def ensure_directories(cls, value: Path) -> Path:
        value.mkdir(parents=True, exist_ok=True)
        return value

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def nexus_database_dsn(self) -> str | None:
        """Use SentinelOps' DATABASE_URL first, with POSTGRES_DSN as a temporary alias."""
        if self.DATABASE_URL:
            return self.DATABASE_URL.get_secret_value()
        if self.POSTGRES_DSN:
            return self.POSTGRES_DSN.get_secret_value()
        return None

    @property
    def raw_knowledge_dirs(self) -> list[Path]:
        return [self.PRIMARY_KNOWLEDGE_DIR, self.SECONDARY_KNOWLEDGE_DIR]

    @property
    def log_file_path(self) -> Path:
        return self.LOGS_DIR / "app.log"

    @property
    def audit_file_path(self) -> Path:
        return self.LOGS_DIR / self.AUDIT_LOG_FILE

    @property
    def normalized_output_path(self) -> Path:
        return self.NORMALIZED_DIR / "normalized_sops.json"

    @property
    def chunk_output_path(self) -> Path:
        return self.INDEX_DIR / "chunk_graph.json"

    @property
    def alignment_report_path(self) -> Path:
        return self.REPORTS_DIR / "alignment_report.json"

    @property
    def vector_index_path(self) -> Path:
        return self.VECTOR_STORE_PATH / "local_vector_index.json"

    def safe_dict(self) -> dict[str, Any]:
        data = self.model_dump()
        for key in (
            "MISTRAL_API_KEY",
            "DATABASE_URL",
            "POSTGRES_DSN",
            "SECRET_KEY",
            "NEXUS_AGENT_API_TOKEN",
            "REDIS_URL",
            "QDRANT_API_KEY",
            "ADMIN_API_TOKEN",
        ):
            if key in data and data[key] is not None:
                data[key] = "***"
        return data


_BASE_DIR = Path(__file__).resolve().parents[2]
_SENTINEL_ROOT = _BASE_DIR.parent
_ENV_FILES = tuple(
    path
    for path in (
        _SENTINEL_ROOT / "SentinelOps-beta" / ".env",
        _BASE_DIR / ".env",
    )
    if path.exists()
)


settings = Settings(_env_file=_ENV_FILES or None)
