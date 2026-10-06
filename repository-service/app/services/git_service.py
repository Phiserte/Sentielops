"""
Low-level Git operations.

This service is responsible ONLY for interacting with Git.

Business logic belongs in RepositoryService.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from app.core.config import GITHUB_TOKEN
from app.models.repository_response import ChangedFileResponse, RepositoryFileResponse


class GitService:
    """
    Provides low-level Git operations.

    This class never knows anything about FastAPI,
    PushAgent, AI analysis or HTTP.

    It only knows how to work with Git repositories.
    """

    def __init__(self) -> None:
        self.github_token = GITHUB_TOKEN

    # ---------------------------------------------------------
    # Internal Helpers
    # ---------------------------------------------------------

    def _run_git(
        self,
        *args: str,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Execute a Git command with non-interactive GitHub authentication.
        """

        command = [
            "git",
            *args,
        ]

        environment = os.environ.copy()

        environment["GIT_TERMINAL_PROMPT"] = "0"

        askpass_file: Path | None = None

        try:
            if self.github_token:
                fd, path = tempfile.mkstemp(
                    prefix="sentinelops-git-",
                    suffix=".sh",
                )

                os.close(fd)

                askpass_file = Path(path)

                askpass_file.write_text(
                    "#!/bin/sh\n"
                    'if echo "$1" | grep -qi username; then\n'
                    '    printf "%s\\n" "x-access-token"\n'
                    "else\n"
                    '    printf "%s\\n" "$GITHUB_TOKEN"\n'
                    "fi\n",
                    encoding="utf-8",
                )

                askpass_file.chmod(0o700)

                environment["GIT_ASKPASS"] = str(
                    askpass_file
                )

                environment["GITHUB_TOKEN"] = (
                    self.github_token
                )

            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                env=environment,
            )

        finally:
            if askpass_file is not None:
                try:
                    askpass_file.unlink()
                except FileNotFoundError:
                    pass

        if result.returncode != 0:
            raise RuntimeError(
                "\n".join(
                    [
                        "Git command failed.",
                        f"Command: {' '.join(command)}",
                        f"Exit Code: {result.returncode}",
                        f"STDOUT:\n{result.stdout}",
                        f"STDERR:\n{result.stderr}",
                    ]
                )
            )

        return result

    # ---------------------------------------------------------
    # Repository Helpers
    # ---------------------------------------------------------

    @staticmethod
    def repository_exists(
        repository_path: Path,
    ) -> bool:
        return repository_path.exists()

    @staticmethod
    def is_git_repository(
        repository_path: Path,
    ) -> bool:
        return (
            repository_path.exists()
            and (repository_path / ".git").exists()
        )

    @staticmethod
    def ensure_parent_directory(
        repository_path: Path,
    ) -> None:
        repository_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    # ---------------------------------------------------------
    # Git Operations
    # ---------------------------------------------------------

    def clone(
        self,
        clone_url: str,
        repository_path: Path,
    ) -> None:
        """
        Clone a repository if it does not already exist.
        """

        if self.is_git_repository(repository_path):
            return

        self.ensure_parent_directory(repository_path)

        self._run_git(
            "clone",
            clone_url,
            str(repository_path),
        )

    def fetch(
        self,
        repository_path: Path,
    ) -> None:
        """
        Fetch latest changes from origin.
        """

        self._run_git(
            "fetch",
            "--all",
            "--prune",
            cwd=repository_path,
        )

    def checkout(
        self,
        repository_path: Path,
        commit: str,
    ) -> None:
        self._run_git(
            "checkout",
            "--force",
            commit,
            cwd=repository_path,
        )

    def current_commit(
        self,
        repository_path: Path,
    ) -> str:
        result = self._run_git(
            "rev-parse",
            "HEAD",
            cwd=repository_path,
        )

        return result.stdout.strip()

    def changed_files(
        self,
        repository_path: Path,
        previous_commit: str,
        current_commit: str,
    ) -> list[ChangedFileResponse]:

        result = self._run_git(
            "diff",
            "--name-status",
            previous_commit,
            current_commit,
            cwd=repository_path,
        )

        changed_files: list[ChangedFileResponse] = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            parts = line.split(
                maxsplit=1,
            )

            if len(parts) != 2:
                continue

            git_status, file_path = parts

            status_map = {
                "A": "added",
                "M": "modified",
                "D": "deleted",
                "R": "renamed",
            }

            status = status_map.get(
                git_status[0],
                "modified",
            )

            old_content = self.file_content(
                repository_path,
                previous_commit,
                file_path,
            )

            new_content = self.current_file_content(
                repository_path,
                file_path,
            )

            diff = self.file_diff(
                repository_path,
                previous_commit,
                current_commit,
                file_path,
            )

            changed_files.append(
                ChangedFileResponse(
                    path=file_path,
                    status=status,
                    old_content=old_content,
                    new_content=new_content,
                    diff=diff,
                )
            )

        return changed_files

    def branch_exists(
        self,
        repository_path: Path,
        branch: str,
    ) -> bool:

        result = subprocess.run(
            [
                "git",
                "show-ref",
                "--verify",
                f"refs/heads/{branch}",
            ],
            cwd=repository_path,
            capture_output=True,
            text=True,
        )

        return result.returncode == 0

    def checkout_branch(
        self,
        repository_path: Path,
        branch: str,
    ) -> None:

        self._run_git(
            "checkout",
            branch,
            cwd=repository_path,
        )

    def pull(
        self,
        repository_path: Path,
    ) -> None:

        self._run_git(
            "pull",
            "--ff-only",
            cwd=repository_path,
        )

    def repository_status(
        self,
        repository_path: Path,
    ) -> str:

        result = self._run_git(
            "status",
            "--short",
            cwd=repository_path,
        )

        return result.stdout.strip()

    def remote_url(
        self,
        repository_path: Path,
    ) -> str:

        result = self._run_git(
            "remote",
            "get-url",
            "origin",
            cwd=repository_path,
        )

        return result.stdout.strip()

    def default_branch(
        self,
        repository_path: Path,
    ) -> str:

        result = self._run_git(
            "rev-parse",
            "--abbrev-ref",
            "origin/HEAD",
            cwd=repository_path,
        )

        return (
            result.stdout
            .strip()
            .replace("origin/", "")
        )

    def file_content(
        self,
        repository_path: Path,
        commit: str,
        file_path: str,
    ) -> str:

        try:
            result = self._run_git(
                "show",
                f"{commit}:{file_path}",
                cwd=repository_path,
            )

            return result.stdout

        except RuntimeError:
            return ""

    def current_file_content(
        self,
        repository_path: Path,
        file_path: str,
    ) -> str:

        path = repository_path / file_path

        if not path.exists():
            return ""

        try:
            return path.read_text(
                encoding="utf-8",
            )

        except Exception:
            return ""

    def file_diff(
        self,
        repository_path: Path,
        previous_commit: str,
        current_commit: str,
        file_path: str,
    ) -> str:

        try:
            result = self._run_git(
                "diff",
                previous_commit,
                current_commit,
                "--",
                file_path,
                cwd=repository_path,
            )

            return result.stdout

        except RuntimeError:
            return ""

    def get_repository_files(
        self,
        repository_path: Path,
        commit: str = "HEAD",
        paths: list[str] | None = None,
        extensions: list[str] | None = None,
        max_file_size: int | None = None,
        max_total_size: int = 10_000_000,
    ) -> tuple[list[RepositoryFileResponse], list[str], bool]:
        """
        List files in the repository at a specific commit with filtering.

        Args:
            repository_path: Path to the local repository.
            commit: Commit SHA or ref to retrieve files from.
            paths: Optional list of specific file paths to retrieve.
            extensions: Optional list of file extensions to filter by (e.g., ['.py', '.js']).
            max_file_size: Maximum file size in bytes to include.
            max_total_size: Maximum total response size in bytes.

        Returns:
            Tuple of (files, skipped_files, truncated)
        """
        files: list[RepositoryFileResponse] = []
        skipped_files: list[str] = []
        total_size = 0
        truncated = False

        # If specific paths requested, fetch only those
        if paths:
            for file_path in paths:
                content = self.file_content(repository_path, commit, file_path)
                size = len(content.encode("utf-8"))

                if max_file_size is not None and size > max_file_size:
                    skipped_files.append(file_path)
                    truncated = True
                    continue

                if total_size + size > max_total_size:
                    skipped_files.append(file_path)
                    truncated = True
                    continue

                files.append(
                    RepositoryFileResponse(
                        path=file_path,
                        content=content,
                        size=size,
                    )
                )
                total_size += size
            return files, skipped_files, truncated

        # Otherwise, list all files and apply filters
        result = self._run_git(
            "ls-tree",
            "-r",
            "--name-only",
            commit,
            cwd=repository_path,
        )

        file_paths = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        # Filter by extensions if provided
        if extensions:
            ext_set = set(ext.lower() for ext in extensions)
            file_paths = [
                p for p in file_paths
                if any(p.lower().endswith(ext) for ext in ext_set)
            ]

        for file_path in file_paths:
            content = self.file_content(repository_path, commit, file_path)
            size = len(content.encode("utf-8"))

            if max_file_size is not None and size > max_file_size:
                skipped_files.append(file_path)
                truncated = True
                continue

            if total_size + size > max_total_size:
                skipped_files.append(file_path)
                truncated = True
                continue

            files.append(
                RepositoryFileResponse(
                    path=file_path,
                    content=content,
                    size=size,
                )
            )
            total_size += size

        return files, skipped_files, truncated

    def get_file_content(
        self,
        repository_path: Path,
        commit: str,
        file_path: str,
    ) -> RepositoryFileResponse:
        """
        Get content of a specific file at a commit.
        """
        content = self.file_content(
            repository_path,
            commit,
            file_path,
        )

        size = len(content.encode("utf-8"))

        return RepositoryFileResponse(
            path=file_path,
            content=content,
            size=size,
        )