"""Centralised logging for the baseline defender gateway."""

from __future__ import annotations

import logging
from typing import Final


_DEFAULT_LOG_LEVEL: Final[int] = logging.INFO
_LOGGER_NAME: Final[str] = "defender"


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Return a configured logger for the defender.

    We keep logging minimal but structured so leaderboard failures can be
    debugged. This function is safe to call multiple times.
    """
    logger_name = name or _LOGGER_NAME
    logger = logging.getLogger(logger_name)

    if not logger.handlers:
        # Avoid adding duplicate handlers if basicConfig was already called.
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] defender %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if logger.level == logging.NOTSET:
        logger.setLevel(_DEFAULT_LOG_LEVEL)

    return logger

