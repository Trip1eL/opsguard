from __future__ import annotations

import logging
import sys

_LOGGER_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    global _LOGGER_CONFIGURED
    if _LOGGER_CONFIGURED:
        return
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    _LOGGER_CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
