"""Central logging configuration with UTC timestamps and secret redaction."""

from __future__ import annotations

import logging
import re
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TextIO

from common.constants import (
    APP_LOGGER_NAME,
    DEFAULT_ENCODING,
    DEFAULT_LOG_LEVEL,
    LOG_BACKUP_COUNT,
    MAX_LOG_BYTES,
)

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


class UtcFormatter(logging.Formatter):
    """Logging formatter whose ``asctime`` is always UTC."""

    converter = time.gmtime


class SecretRedactionFilter(logging.Filter):
    """Remove common credential values before records reach handlers."""

    _key_value_pattern = re.compile(
        r"(?i)\b(password|token|api[_-]?key)"
        r"(\s*[=:]\s*)([^\s,;]+)"
    )
    _bearer_pattern = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
    _authorization_pattern = re.compile(
        r"(?i)\bauthorization(\s*[=:]\s*)(?!Bearer\b)([^\s,;]+)"
    )

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        message = self._bearer_pattern.sub("Bearer ***", message)
        message = self._authorization_pattern.sub(r"authorization\1***", message)
        message = self._key_value_pattern.sub(r"\1\2***", message)
        record.msg = message
        record.args = ()
        return True


def parse_log_level(level: str | int) -> int:
    """Validate a logging level name or integer."""
    if isinstance(level, bool):
        raise ValueError("Logging level không hợp lệ.")
    if isinstance(level, int):
        if level < 0:
            raise ValueError("Logging level không được âm.")
        return level
    if not isinstance(level, str):
        raise TypeError("Logging level phải là chuỗi hoặc số nguyên.")

    normalized = level.strip().upper()
    resolved = logging.getLevelName(normalized)
    if not isinstance(resolved, int):
        raise ValueError(f"Logging level không hợp lệ: {level}")
    return resolved


def configure_logging(
    *,
    level: str | int = DEFAULT_LOG_LEVEL,
    log_file: str | Path | None = None,
    console: bool = True,
    stream: TextIO | None = None,
) -> logging.Logger:
    """Configure the toolkit logger without accumulating duplicate handlers."""
    logger = logging.getLogger(APP_LOGGER_NAME)
    logger.setLevel(parse_log_level(level))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = UtcFormatter(LOG_FORMAT)
    redaction_filter = SecretRedactionFilter()

    if console:
        console_handler = logging.StreamHandler(stream or sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(redaction_filter)
        logger.addHandler(console_handler)

    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=MAX_LOG_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding=DEFAULT_ENCODING,
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction_filter)
        logger.addHandler(file_handler)

    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger


def get_logger(component: str | None = None) -> logging.Logger:
    """Return the application logger or one of its named children."""
    if component is None or not component.strip():
        return logging.getLogger(APP_LOGGER_NAME)
    return logging.getLogger(f"{APP_LOGGER_NAME}.{component.strip()}")


def shutdown_logging() -> None:
    """Close handlers owned by the toolkit logger."""
    logger = logging.getLogger(APP_LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
