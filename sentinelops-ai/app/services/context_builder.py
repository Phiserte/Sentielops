"""
app/builders/context_builder.py

Builds the RepositoryContext used by PushAgent.

This builder transforms the Repository Service response into
the context consumed by PromptBuilder.
"""

from __future__ import annotations

from app.models.repository_context import (
    ChangedFile,
    RepositoryContext,
)
from app.models.repository_service_response import (
    RepositoryServiceResponse,
)


class ContextBuilder:
    """
    Builds RepositoryContext from RepositoryServiceResponse.

    This class contains no Git logic.

    It simply maps Repository Service data into the
    internal AI context model.
    """

    async def build(
        self,
        repository: RepositoryServiceResponse,
    ) -> RepositoryContext:

        changed_files: list[ChangedFile] = []

        for file in repository.changed_files:

            changed_files.append(
                ChangedFile(
                    path=file.path,
                    status=file.status,
                    old_content=file.old_content,
                    new_content=file.new_content,
                    diff=file.diff,
                )
            )

        return RepositoryContext(
            repository_name=repository.repository_name,
            repository_full_name=repository.repository_full_name,
            repository_path=repository.repository_path,
            branch=repository.branch,
            before_commit=repository.previous_commit,
            after_commit=repository.current_commit,
            changed_files=changed_files,
        )