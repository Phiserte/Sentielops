"""
Response returned from Repository Service.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ChangedFileResponse(BaseModel):
    """
    Represents a changed file in the repository.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    path: str = Field(
        ...,
        description="Repository-relative file path.",
    )

    status: str = Field(
        ...,
        description="Git status (added, modified, deleted, renamed).",
    )

    old_content: str | None = Field(
        default=None,
        description="File contents before the change.",
    )

    new_content: str | None = Field(
        default=None,
        description="File contents after the change.",
    )

    diff: str | None = Field(
        default=None,
        description="Unified git diff for the file.",
    )


class RepositoryFileResponse(BaseModel):
    """
    Represents a file in the repository.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    path: str = Field(
        ...,
        description="Repository-relative file path.",
    )

    content: str = Field(
        ...,
        description="File contents.",
    )

    size: int = Field(
        ...,
        description="File size in bytes.",
    )

    language: str | None = Field(
        default=None,
        description="Detected programming language.",
    )


class RepositoryFilesResponse(BaseModel):
    """
    Response returned by the Repository Service files endpoint.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    repository_full_name: str = Field(
        ...,
        description="Repository full name (owner/repo).",
    )

    commit: str = Field(
        ...,
        description="Commit SHA that was retrieved.",
    )

    files: list[RepositoryFileResponse] = Field(
        default_factory=list,
        description="Repository files.",
    )

    total_files: int = Field(
        ...,
        description="Total number of files returned.",
    )

    total_size: int = Field(
        ...,
        description="Total size of all files in bytes.",
    )

    truncated: bool = Field(
        default=False,
        description="Whether the file list was truncated due to limits.",
    )

    skipped_files: list[str] = Field(
        default_factory=list,
        description="Files that were skipped (e.g., too large, binary).",
    )


class RepositoryServiceResponse(BaseModel):
    """
    Response returned by the Repository Service.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    repository_name: str = Field(
        ...,
        description="Repository name.",
    )

    repository_full_name: str = Field(
        ...,
        description="Repository full name (owner/repo).",
    )

    repository_path: str = Field(
        ...,
        description="Local repository path.",
    )

    branch: str = Field(
        ...,
        description="Checked out branch.",
    )

    current_commit: str = Field(
        ...,
        description="Current commit SHA.",
    )

    previous_commit: str = Field(
        ...,
        description="Previous commit SHA.",
    )

    changed_files: list[ChangedFileResponse] = Field(
        default_factory=list,
        description="Files changed between the two commits.",
    )

    cloned: bool = Field(
        ...,
        description="Whether the repository was cloned.",
    )

    fetched: bool = Field(
        ...,
        description="Whether the latest changes were fetched.",
    )

    checked_out: bool = Field(
        ...,
        description="Whether the target branch was successfully checked out.",
    )