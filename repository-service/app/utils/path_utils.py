"""
app/utils/path_utils.py

Utility functions for working with repository paths.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import REPOSITORY_STORAGE_PATH


_INVALID_FILENAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_repository_name(
    repository_full_name: str,
) -> str:
    """
    Convert a GitHub repository name into a filesystem-safe name.

    Example
    -------
    tejasbhat/SentinelOps

    becomes

    tejasbhat__SentinelOps
    """

    repository_name = repository_full_name.replace("/", "__")

    repository_name = _INVALID_FILENAME_PATTERN.sub(
        "_",
        repository_name,
    )

    return repository_name


def repository_path(
    repository_full_name: str,
) -> Path:
    """
    Returns the absolute local repository path.

    Example
    -------
    Input:
        tejasbhat/SentinelOps

    Output:
        /repositories/tejasbhat__SentinelOps
    """

    return (
        REPOSITORY_STORAGE_PATH
        / sanitize_repository_name(repository_full_name)
    )


def repository_exists(
    repository_full_name: str,
) -> bool:
    """
    Returns True if the repository already exists locally.
    """

    return repository_path(
        repository_full_name,
    ).exists()


def ensure_storage_directory() -> None:
    """
    Ensures the repository storage directory exists.
    """

    REPOSITORY_STORAGE_PATH.mkdir(
        parents=True,
        exist_ok=True,
    )