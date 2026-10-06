"""
app/models/repository_request.py

Request models for the Repository Service.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RepositoryFilesRequest(BaseModel):
    """
    Request to retrieve repository files for security scanning.

    Allows SecurityAgent to select specific files or
    retrieve all files at a given commit.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    repository_full_name: str = Field(
        ...,
        description="GitHub repository in owner/repository format.",
        examples=["tejasbhat/SentinelOps"],
    )

    commit: str | None = Field(
        default=None,
        description="Commit SHA to retrieve files from. Defaults to after_commit from prepare.",
        min_length=7,
    )

    paths: list[str] | None = Field(
        default=None,
        description="Optional list of specific file paths to retrieve. If omitted, all files are returned.",
        examples=[["app/api/login.py", "app/models/user.py"]],
    )

    max_file_size: int | None = Field(
        default=None,
        description="Maximum file size in bytes to include. Larger files are skipped.",
        ge=1,
    )

    extensions: list[str] | None = Field(
        default=None,
        description="Optional list of file extensions to filter by (e.g., ['.py', '.js']).",
        examples=[[".py", ".js", ".ts"]],
    )


class RepositoryRequest(BaseModel):
    """
    Request sent by SentinelOps to prepare a repository
    for analysis.
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
        description="GitHub repository in owner/repository format.",
        examples=["tejasbhat/SentinelOps"],
    )

    clone_url: str = Field(
        ...,
        description="Git clone URL.",
        examples=[
            "https://github.com/tejasbhat/SentinelOps.git",
        ],
    )

    default_branch: str = Field(
        ...,
        description="Repository default branch.",
        examples=["main"],
    )

    branch: str = Field(
        ...,
        description="Branch to checkout.",
        examples=["main"],
    )

    before_commit: str = Field(
        ...,
        description="Commit SHA before the push.",
        min_length=7,
    )

    after_commit: str = Field(
        ...,
        description="Commit SHA after the push.",
        min_length=7,
    )