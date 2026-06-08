"""Logging configuration for ZorkSec.

Logs to both stderr and a rotating file under ``<home>/logs/zorksec.log``.
Safe to call multiple times (idempotent handler setup).
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from zorksec.config import Settings, ensure_directories, get_settings

_CONFIGURED = False
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def configure_logging(level: int = logging.INFO, settings: Settings | None = None) -> None:
    """Configure root logging handlers once."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    settings = settings or get_settings()
    ensure_directories(settings)

    root = logging.getLogger()
    root.setLevel(level)

    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter(_FORMAT))
    root.addHandler(stream)

    try:
        file_handler = RotatingFileHandler(
            settings.logs_dir / "zorksec.log",
            maxBytes=2_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter(_FORMAT))
        root.addHandler(file_handler)
    except OSError:
        # File logging is best-effort (e.g. read-only paths in tests).
        root.warning("File logging unavailable; continuing with stream logging only.")

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, ensuring logging is configured."""
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
