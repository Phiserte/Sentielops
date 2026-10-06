"""
Request sent to Repository Service.
"""

from pydantic import BaseModel, ConfigDict, Field


class RepositoryServiceRequest(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    repository_name: str
    repository_full_name: str

    clone_url: str

    default_branch: str
    branch: str

    before_commit: str
    after_commit: str

    extensions: list[str] | None = Field(
        default=None,
        description="File extensions to include (e.g., ['.py', '.js']).",
    )

    max_file_size: int | None = Field(
        default=None,
        description="Maximum file size in bytes.",
    )


class RepositoryFilesRequest(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    repository_full_name: str = Field(..., description="Repository full name (owner/repo).")

    commit: str = Field(..., description="Commit SHA to retrieve files for.")

    extensions: list[str] | None = Field(
        default=None,
        description="File extensions to include (e.g., ['.py', '.js']).",
    )

    max_file_size: int | None = Field(
        default=None,
        description="Maximum file size in bytes. Files larger than this will be excluded.",
    )