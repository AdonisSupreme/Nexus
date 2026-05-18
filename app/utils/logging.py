"""Application logging helpers."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from app.config.settings import settings


_LOGGING_CONFIGURED = False


def configure_logging() -> None:
    """Configure root logging once for the whole application."""
    global _LOGGING_CONFIGURED

    if _LOGGING_CONFIGURED:
        return

    settings.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    fmt = settings.LOG_FORMAT
    if fmt.strip().lower() == "json":
        # Some environments pass LOG_FORMAT=json as a mode flag instead of a
        # stdlib logging template; fall back to a safe human-readable layout.
        fmt = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s"

    formatter = logging.Formatter(
        fmt=fmt,
        datefmt=settings.LOG_DATE_FORMAT,
    )

    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))
    root.handlers.clear()

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    file_handler = RotatingFileHandler(
        filename=settings.log_file_path,
        maxBytes=settings.AUDIT_LOG_MAX_SIZE,
        backupCount=settings.AUDIT_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    _LOGGING_CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)


def log_with_context(
    logger: logging.Logger,
    level: str,
    message: str,
    context: dict[str, object] | None = None,
) -> None:
    details = ""
    if context:
        parts = [f"{key}={value}" for key, value in sorted(context.items())]
        details = " | " + " ".join(parts)
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(f"{message}{details}")
