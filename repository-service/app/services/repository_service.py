"""
app/services/repository_service.py

Business logic for repository preparation.

This service coordinates Git operations but never
executes Git commands directly.
"""

from __future__ import annotations

from pathlib import Path

from app.models.repository_request import RepositoryRequest
from app.models.repository_request import RepositoryFilesRequest
from app.models.repository_response import RepositoryResponse
from app.models.repository_response import RepositoryFilesResponse
from app.models.repository_response import ChangedFileResponse
from app.models.repository_response import RepositoryFileResponse
from app.services.git_service import GitService
from app.utils.path_utils import repository_path


class RepositoryService:
    """
    Coordinates repository preparation.

    Workflow

        RepositoryRequest
                │
                ▼
        Clone (if needed)
                │
                ▼
        Fetch latest
                │
                ▼
        Checkout commit
                │
                ▼
        Collect metadata
                │
                ▼
        RepositoryResponse
    """

    def __init__(self) -> None:
        self.git = GitService()

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    def ensure_repository(
        self,
        request: RepositoryRequest,
    ) -> RepositoryResponse:
        """
        Ensure that a repository exists locally and is
        checked out to the requested commit.
        """

        repo_path = repository_path(
            request.repository_full_name,
        )

        cloned = False
        fetched = False
        checked_out = False

        # ---------------------------------------------
        # Clone
        # ---------------------------------------------

        if not self.git.is_git_repository(repo_path):

            self.git.clone(
                clone_url=request.clone_url,
                repository_path=repo_path,
            )

            cloned = True

        # ---------------------------------------------
        # Fetch latest commits
        # ---------------------------------------------

        self.git.fetch(
            repository_path=repo_path,
        )

        fetched = True

        # ---------------------------------------------
        # Checkout requested commit
        # ---------------------------------------------

        self.git.checkout(
            repository_path=repo_path,
            commit=request.after_commit,
        )

        checked_out = True

        # ---------------------------------------------
        # Continue building response
        # ---------------------------------------------

        return self._build_response(
            request=request,
            repository_path=repo_path,
            cloned=cloned,
            fetched=fetched,
            checked_out=checked_out,
        )
        # ---------------------------------------------------------
    # Response Builder
    # ---------------------------------------------------------

    def _build_response(
        self,
        request: RepositoryRequest,
        repository_path: Path,
        cloned: bool,
        fetched: bool,
        checked_out: bool,
    ) -> RepositoryResponse:
        """
        Build the RepositoryResponse returned to SentinelOps.
        """

        current_commit = self.git.current_commit(
            repository_path=repository_path,
        )

        changed_files = self.git.changed_files(
            repository_path=repository_path,
            previous_commit=request.before_commit,
            current_commit=request.after_commit,
        )

        return RepositoryResponse(
            repository_name=request.repository_name,
            repository_full_name=request.repository_full_name,
            repository_path=str(repository_path),
            branch=request.branch,
            current_commit=current_commit,
            previous_commit=request.before_commit,
            changed_files=changed_files,
            cloned=cloned,
            fetched=fetched,
            checked_out=checked_out,
        )

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def repository_exists(
        self,
        request: RepositoryRequest,
    ) -> bool:
        """
        Returns True if the repository already exists locally.
        """

        repo_path = repository_path(
            request.repository_full_name,
        )

        return self.git.is_git_repository(
            repo_path,
        )

    def repository_location(
        self,
        request: RepositoryRequest,
    ) -> Path:
        """
        Returns the local repository path.
        """

        return repository_path(
            request.repository_full_name,
        )

    def current_commit(
        self,
        request: RepositoryRequest,
    ) -> str:
        """
        Returns the current checked-out commit.
        """

        repo_path = repository_path(
            request.repository_full_name,
        )

        return self.git.current_commit(
            repo_path,
        )

    def changed_files(
        self,
        request: RepositoryRequest,
    ) -> list[ChangedFileResponse]:
        """
        Returns files changed in this push.
        """

        repo_path = repository_path(
            request.repository_full_name,
        )

        return self.git.changed_files(
            repository_path=repo_path,
            previous_commit=request.before_commit,
            current_commit=request.after_commit,
        )

    def repository_files(
        self,
        request: RepositoryRequest,
        commit: str | None = None,
        paths: list[str] | None = None,
        extensions: list[str] | None = None,
        max_file_size: int | None = None,
    ) -> tuple[list[RepositoryFileResponse], list[str], bool]:
        """
        Returns repository files at a specific commit with filtering.

        Used by SecurityAgent for repository security scanning.
        """

        repo_path = repository_path(
            request.repository_full_name,
        )

        target_commit = commit or request.after_commit

        return self.git.get_repository_files(
            repository_path=repo_path,
            commit=target_commit,
            paths=paths,
            extensions=extensions,
            max_file_size=max_file_size,
        )

    def get_repository_files(
        self,
        request: RepositoryFilesRequest,
    ) -> RepositoryFilesResponse:
        """
        Get repository files for security scanning.

        Public API method that takes RepositoryFilesRequest and returns
        RepositoryFilesResponse with filtering applied.
        """

        repo_path = repository_path(
            request.repository_full_name,
        )

        # Ensure repository exists
        if not self.git.is_git_repository(repo_path):
            raise RepositoryNotFoundError(request.repository_full_name)

        # Ensure the commit is checked out (fetch if needed)
        try:
            self.git.checkout(repository_path=repo_path, commit=request.commit or "HEAD")
        except RuntimeError:
            # If checkout fails, try fetching first then checkout
            self.git.fetch(repository_path=repo_path)
            self.git.checkout(repository_path=repo_path, commit=request.commit or "HEAD")

        files, skipped_files, truncated = self.git.get_repository_files(
            repository_path=repo_path,
            commit=request.commit or "HEAD",
            paths=request.paths,
            extensions=request.extensions,
            max_file_size=request.max_file_size,
        )

        total_size = sum(f.size for f in files)

        return RepositoryFilesResponse(
            repository_full_name=request.repository_full_name,
            commit=request.commit or self.git.current_commit(repo_path),
            files=files,
            total_files=len(files),
            total_size=total_size,
            truncated=truncated,
            skipped_files=skipped_files,
        )
    # ---------------------------------------------------------
# Safe Wrapper
# ---------------------------------------------------------

    def prepare(
        self,
        request: RepositoryRequest,
    ) -> RepositoryResponse:
        """
        Public entrypoint used by FastAPI.

        Wraps internal exceptions into service exceptions.
        """

        logger.info(
            "Preparing repository %s",
            request.repository_full_name,
        )

        try:

            return self.ensure_repository(
                request,
            )

        except Exception as exc:

            logger.exception(
                "Repository preparation failed."
            )

            raise RepositoryPreparationError(
                f"Failed preparing repository "
                f"{request.repository_full_name}"
            ) from exc


# ---------------------------------------------------------
# Status
# ---------------------------------------------------------

    def status(
        self,
        request: RepositoryRequest,
    ) -> dict:

        repo_path = repository_path(
            request.repository_full_name,
        )

        if not self.git.is_git_repository(
            repo_path,
        ):

            raise RepositoryNotFoundError(
                request.repository_full_name,
            )

        return {
            "repository": request.repository_full_name,
            "path": str(repo_path),
            "current_commit": self.git.current_commit(
                repo_path,
            ),
            "git_status": self.git.repository_status(
                repo_path,
            ),
            "remote": self.git.remote_url(
                repo_path,
            ),
            "default_branch": self.git.default_branch(
                repo_path,
            ),
        }
    """
Part 3

Production helpers, validation and error handling.
"""


import logging

logger = logging.getLogger(__name__)


class RepositoryServiceError(Exception):
    """
    Base exception raised by RepositoryService.
    """

    pass


class RepositoryPreparationError(RepositoryServiceError):
    """
    Raised when repository preparation fails.
    """

    pass


class RepositoryNotFoundError(RepositoryServiceError):
    """
    Raised when a repository does not exist locally.
    """

    pass


