import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
# ==========================================================
# Database
# ==========================================================

DATABASE_URL = os.getenv("DATABASE_URL")

# ==========================================================
# GitHub
# ==========================================================

GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

CLI_API_TOKEN = os.getenv("CLI_API_TOKEN")

# ==========================================================
# LLM
# ==========================================================

LLM_PROVIDER = os.getenv(
    "LLM_PROVIDER",
    "openrouter",
)

LLM_MODEL = os.getenv(
    "LLM_MODEL",
    "poolside/laguna-s-2.1:free",
)

LLM_TEMPERATURE = float(
    os.getenv(
        "LLM_TEMPERATURE",
        "0.2",
    )
)

OPENROUTER_API_KEY = os.getenv(
    "OPENROUTER_API_KEY",
)

# ==========================================================
# Repository Service
# ==========================================================

REPOSITORY_SERVICE_URL = os.getenv(
    "REPOSITORY_SERVICE_URL",
)