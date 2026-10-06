"""
app/api/repositories.py

Repository API endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.models.repository_request import RepositoryFilesRequest
from app.models.repository_request import RepositoryRequest
from app.models.repository_response import RepositoryFilesResponse
from app.models.repository_response import RepositoryResponse
from app.services.repository_service import (
    RepositoryNotFoundError,
    RepositoryPreparationError,
    RepositoryService,
)

router = APIRouter(
    prefix="/repositories",
    tags=["Repositories"],
)

repository_service = RepositoryService()


@router.post(
    "/ensure",
    response_model=RepositoryResponse,
    status_code=status.HTTP_200_OK,
)
async def ensure_repository(
    request: RepositoryRequest,
) -> RepositoryResponse:
    """
    Ensure that a repository is cloned,
    fetched and checked out to the
    requested commit.
    """

    try:

        return repository_service.prepare(
            request,
        )

    except RepositoryPreparationError as exc:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post(
    "/files",
    response_model=RepositoryFilesResponse,
    status_code=status.HTTP_200_OK,
)
async def get_repository_files(
    request: RepositoryFilesRequest,
) -> RepositoryFilesResponse:
    """
    Retrieve repository file contents for security scanning.

    Allows SecurityAgent to retrieve filtered file contents
    without direct filesystem or Git access.
    """

    try:

        return repository_service.get_repository_files(request)

    except RepositoryNotFoundError as exc:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post(
    "/status",
    status_code=status.HTTP_200_OK,
)
async def repository_status(
    request: RepositoryRequest,
):

    try:

        return repository_service.status(
            request,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc