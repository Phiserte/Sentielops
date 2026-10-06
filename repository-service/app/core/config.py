"""
app/core/config.py

Repository Service configuration.

This module is the single source of truth for all
environment configuration.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------
# Load .env
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent

load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------
# Service
# ---------------------------------------------------------

SERVICE_NAME = os.getenv(
    "SERVICE_NAME",
    "Repository Service",
)

SERVICE_VERSION = os.getenv(
    "SERVICE_VERSION",
    "1.0.0",
)

HOST = os.getenv(
    "HOST",
    "127.0.0.1",
)

PORT = int(
    os.getenv(
        "PORT",
        "8001",
    )
)

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO",
)

# ---------------------------------------------------------
# Repository Storage
# ---------------------------------------------------------

REPOSITORY_STORAGE_PATH = Path(
    os.getenv(
        "REPOSITORY_STORAGE_PATH",
        str(BASE_DIR / "repositories"),
    )
).resolve()

# ---------------------------------------------------------
# Git
# ---------------------------------------------------------

GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN",
)

GIT_CLONE_DEPTH = int(
    os.getenv(
        "GIT_CLONE_DEPTH",
        "1",
    )
)

# ---------------------------------------------------------
# Validation
# ---------------------------------------------------------

REPOSITORY_STORAGE_PATH.mkdir(
    parents=True,
    exist_ok=True,
)

if not REPOSITORY_STORAGE_PATH.exists():
    raise RuntimeError(
        "Repository storage directory does not exist."
    )