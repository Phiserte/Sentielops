import logging

from fastapi import FastAPI

from app.api.github_webhook import router as github_webhook_router
from app.api.cli import router as cli_router
from app.api.security_scan import router as security_scan_router
from app.database import Base, engine

import app.database.models.github_event
import app.database.models.analysis

# Import dependencies so they are created on startup
import app.core.dependency


# ==========================================================
# Logging
# ==========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    force=True,
)

logger = logging.getLogger(__name__)

logger.info("=" * 80)
logger.info("Starting SentinelOps AI...")
logger.info("=" * 80)


# ==========================================================
# Database
# ==========================================================

Base.metadata.create_all(bind=engine)

logger.info("Database initialized.")


# ==========================================================
# FastAPI
# ==========================================================

app = FastAPI(
    title="SentinelOps AI",
)

logger.info("FastAPI application created.")


# ==========================================================
# Routes
# ==========================================================

app.include_router(
    github_webhook_router,
    prefix="/api/v1",
)

app.include_router(
    cli_router,
    prefix="/api/v1",
)

app.include_router(
    security_scan_router,
    prefix="/api/v1",
)

logger.info("GitHub webhook router registered.")
logger.info("Security scan router registered.")
logger.info("SentinelOps AI startup complete.")