from __future__ import annotations

from pydantic import BaseModel, Field


class ChangedFile(BaseModel):
    """
    Represents a single changed file in a GitHub push.
    """

    path: str = Field(
        ...,
        description="Path of the changed file relative to the repository root.",
    )

    status: str = Field(
        ...,
        description="Git status (added, modified, deleted, renamed).",
    )

    old_content: str = Field(
        default="",
        description="Content of the file before the push.",
    )

    new_content: str = Field(
        default="",
        description="Content of the file after the push.",
    )

    diff: str = Field(
        default="",
        description="Git diff for this file.",
    )


class RepositoryContext(BaseModel):
    """
    Repository context used by PushAgent to generate
    an LLM prompt.

    This object contains everything required for
    understanding a GitHub push.
    """

    repository_name: str = Field(
        ...,
        description="Repository name.",
    )

    repository_full_name: str = Field(
        ...,
        description="Full repository name (owner/repository).",
    )

    repository_path: str = Field(
        ...,
        description="Local repository path.",
    )

    branch: str = Field(
        ...,
        description="Branch that was analyzed.",
    )

    before_commit: str = Field(
        ...,
        description="Commit before the push.",
    )

    after_commit: str = Field(
        ...,
        description="Commit after the push.",
    )

    changed_files: list[ChangedFile] = Field(
        default_factory=list,
        description="All changed files with their status, old content, new content and git diff.",
    )

    class Config:
        frozen = True