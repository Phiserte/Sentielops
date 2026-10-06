"""
app/models/repository_response.py

Response models for the Repository Service.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RepositoryFileResponse(BaseModel):
    """
    Represents a file in the repository with its content.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    path: str = Field(
        ...,
        description="Repository-relative path.",
        examples=["app/api/login.py"],
    )

    content: str = Field(
        ...,
        description="File content at the requested commit.",
    )

    size: int = Field(
        ...,
        description="File size in bytes.",
    )


class ChangedFileResponse(BaseModel):
    """
    Represents a changed file between two commits.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    path: str = Field(
        ...,
        description="Repository-relative path.",
        examples=["app/api/login.py"],
    )

    status: str = Field(
        ...,
        description="Git change type.",
        examples=["modified"],
    )

    old_content: str = Field(
        default="",
        description="Contents of the file in the previous commit.",
    )

    new_content: str = Field(
        default="",
        description="Contents of the file in the current commit.",
    )

    diff: str = Field(
        default="",
        description="Git diff for this file.",
    )


class RepositoryFilesResponse(BaseModel):
    """
    Response containing repository file contents for security scanning.

    Provides filtered file access without exposing local filesystem paths.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    repository_full_name: str = Field(
        ...,
        description="Repository full name.",
        examples=["tejasbhat/SentinelOps"],
    )

    commit: str = Field(
        ...,
        description="Commit SHA the files were retrieved from.",
    )

    files: list[RepositoryFileResponse] = Field(
        default_factory=list,
        description="Repository files with content.",
    )

    total_files: int = Field(
        ...,
        description="Total number of files returned.",
        ge=0,
    )

    total_size: int = Field(
        ...,
        description="Total size of all returned files in bytes.",
        ge=0,
    )

    truncated: bool = Field(
        ...,
        description="True if files were filtered out due to size or limits.",
    )

    skipped_files: list[str] = Field(
        default_factory=list,
        description="Paths of files skipped due to size or filter limits.",
    )


class RepositoryResponse(BaseModel):
    """
    Response returned after preparing a repository.

    This object represents the repository state that
    SentinelOps needs before AI analysis begins.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    repository_name: str = Field(
        ...,
        description="Repository name.",
        examples=["SentinelOps"],
    )

    repository_full_name: str = Field(
        ...,
        description="Repository full name.",
        examples=["tejasbhat/SentinelOps"],
    )

    repository_path: str = Field(
        ...,
        description="Absolute path to the local repository.",
        examples=[
            "/home/tejas/repository-service/repositories/tejasbhat__SentinelOps"
        ],
    )

    branch: str = Field(
        ...,
        description="Currently checked out branch.",
        examples=["main"],
    )

    current_commit: str = Field(
        ...,
        description="Current checked out commit.",
    )

    previous_commit: str = Field(
        ...,
        description="Previous commit before checkout.",
    )

    changed_files: list[ChangedFileResponse] = Field(
        default_factory=list,
        description="Detailed information about files changed between the previous and current commit.",
    )

    cloned: bool = Field(
        ...,
        description="True if the repository was cloned during this request.",
    )

    fetched: bool = Field(
        ...,
        description="True if new changes were fetched from the remote.",
    )

    checked_out: bool = Field(
        ...,
        description="True if the requested commit was checked out successfully.",
    )