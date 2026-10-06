"""
HTTP client for Repository Service.
"""

from __future__ import annotations

import logging

from httpx import AsyncClient, HTTPStatusError

from app.models.repository_service_request import (
    RepositoryFilesRequest,
    RepositoryServiceRequest,
)
from app.models.repository_service_response import (
    RepositoryFilesResponse,
    RepositoryServiceResponse,
)


logger = logging.getLogger(__name__)


class RepositoryClient:
    """
    HTTP client responsible for communicating with the
    Repository Service.
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 60,
    ) -> None:

        self._client = AsyncClient(
            base_url=base_url,
            timeout=timeout,
        )

    async def ensure(
        self,
        request: RepositoryServiceRequest,
    ) -> RepositoryServiceResponse:
        """
        Prepare a repository for analysis.
        """

        logger.info(
            "Preparing repository '%s'",
            request.repository_full_name,
        )

        response = await self._client.post(
            "/repositories/ensure",
            json=request.model_dump(),
        )

        response.raise_for_status()

        logger.info(
            "Repository prepared successfully."
        )

        return RepositoryServiceResponse.model_validate(
            response.json(),
        )

    async def get_files(
        self,
        request: RepositoryFilesRequest,
    ) -> RepositoryFilesResponse:
        """
        Retrieve repository file contents for a specific commit.
        """

        logger.info(
            "Fetching repository files for '%s' at commit '%s'",
            request.repository_full_name,
            request.commit[:8],
        )

        response = await self._client.post(
            "/repositories/files",
            json=request.model_dump(exclude_none=True),
        )

        response.raise_for_status()

        logger.info(
            "Repository files retrieved successfully."
        )

        return RepositoryFilesResponse.model_validate(
            response.json(),
        )

    async def status(
        self,
        request: RepositoryServiceRequest,
    ) -> dict:
        """
        Retrieve repository status.
        """

        response = await self._client.post(
            "/repositories/status",
            json=request.model_dump(),
        )

        response.raise_for_status()

        return response.json()

    async def health(
        self,
    ) -> bool:
        """
        Check Repository Service health.
        """

        try:

            response = await self._client.get(
                "/health",
            )

            response.raise_for_status()

            return True

        except HTTPStatusError:

            return False

        except Exception:

            logger.exception(
                "Repository Service health check failed."
            )

            return False

    async def close(
        self,
    ) -> None:
        """
        Close the HTTP client.
        """

        await self._client.aclose()

        logger.info(
            "Repository client closed."
        )