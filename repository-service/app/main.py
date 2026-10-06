"""
Repository Service

Application entrypoint.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.repositories import router
from app.core.config import (
    SERVICE_NAME,
    SERVICE_VERSION,
)

app = FastAPI(
    title=SERVICE_NAME,
    version=SERVICE_VERSION,
)

app.include_router(router)


@app.get("/")
async def root():

    return {
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "running",
    }


@app.get("/health")
async def health():

    return {
        "status": "healthy",
    }