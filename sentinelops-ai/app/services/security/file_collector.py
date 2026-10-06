from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(slots=True)
class CollectedFile:
    """
    Represents a collected source/config file.
    """

    path: Path
    content: str
    language: str


class FileCollector:
    """
    Recursively collects source and configuration files from a repository.
    """

    IGNORED_DIRS = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "build",
        "dist",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".coverage",
        "htmlcov",
        ".eggs",
        "*.egg-info",
        ".idea",
        ".vscode",
        ".vs",
    }

    IGNORED_EXTENSIONS = {
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".dat",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".flac",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
    }

    SOURCE_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".kt",
        ".scala",
        ".go",
        ".rs",
        ".cpp",
        ".cc",
        ".cxx",
        ".c",
        ".h",
        ".hpp",
        ".cs",
        ".php",
        ".rb",
        ".pl",
        ".pm",
        ".swift",
        ".m",
        ".mm",
        ".r",
        ".R",
        ".lua",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".sql",
        ".graphql",
        ".gql",
    }

    CONFIG_EXTENSIONS = {
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".config",
        ".properties",
        ".env",
        ".env.example",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.test",
        ".tf",
        ".tfvars",
        ".hcl",
        ".dockerfile",
        ".dockerignore",
        ".gitignore",
        ".gitattributes",
        ".editorconfig",
        ".eslintrc",
        ".prettierrc",
        ".babelrc",
        ".stylelintrc",
    }

    CONFIG_FILENAMES = {
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "Makefile",
        "makefile",
        "CMakeLists.txt",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.properties",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "Pipfile",
        "Pipfile.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "poetry.lock",
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "composer.json",
        "composer.lock",
        "Gemfile",
        "Gemfile.lock",
        "Rakefile",
        ".python-version",
        ".node-version",
        ".ruby-version",
        ".go-version",
        ".rust-version",
    }

    MAX_FILE_SIZE = 1024 * 1024

    def __init__(self, max_file_size: int = MAX_FILE_SIZE) -> None:
        self._max_file_size = max_file_size

    def collect(self, repo_path: Path) -> list[CollectedFile]:
        """
        Collect all relevant source and config files from the repository.
        """
        files: list[CollectedFile] = []
        for file_path in self._walk_files(repo_path):
            collected = self._read_file(file_path)
            if collected:
                files.append(collected)
        return files

    def _walk_files(self, repo_path: Path) -> Iterator[Path]:
        """
        Walk the repository and yield file paths, skipping ignored directories.
        """
        for root, dirs, filenames in os.walk(repo_path):
            root_path = Path(root)

            dirs[:] = [d for d in dirs if not self._is_ignored_dir(d)]

            for filename in filenames:
                file_path = root_path / filename
                if self._should_collect(file_path):
                    yield file_path

    def _is_ignored_dir(self, dirname: str) -> bool:
        """
        Check if a directory should be ignored.
        """
        if dirname in self.IGNORED_DIRS:
            return True
        if dirname.startswith(".") and dirname not in {".github", ".gitlab", ".circleci", ".husky"}:
            return True
        return False

    def _should_collect(self, file_path: Path) -> bool:
        """
        Determine if a file should be collected.
        """
        if file_path.suffix.lower() in self.IGNORED_EXTENSIONS:
            return False

        if file_path.suffix.lower() in self.SOURCE_EXTENSIONS:
            return True

        if file_path.suffix.lower() in self.CONFIG_EXTENSIONS:
            return True

        if file_path.name in self.CONFIG_FILENAMES:
            return True

        return False

    def _read_file(self, file_path: Path) -> CollectedFile | None:
        """
        Read a file and return a CollectedFile if valid.
        """
        try:
            stat = file_path.stat()
            if stat.st_size > self._max_file_size:
                return None

            if self._is_binary(file_path):
                return None

            content = file_path.read_text(encoding="utf-8", errors="replace")

            language = self._detect_language(file_path)

            return CollectedFile(
                path=file_path,
                content=content,
                language=language,
            )
        except (OSError, UnicodeDecodeError):
            return None

    def _is_binary(self, file_path: Path) -> bool:
        """
        Check if a file is binary by reading the first chunk.
        """
        try:
            with file_path.open("rb") as f:
                chunk = f.read(8192)
                if b"\x00" in chunk:
                    return True
                text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x7F)))
                if chunk and not all(c in text_chars for c in chunk):
                    return True
        except OSError:
            return True
        return False

    def _detect_language(self, file_path: Path) -> str:
        """
        Detect the programming language from file extension.
        """
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".kt": "kotlin",
            ".scala": "scala",
            ".go": "go",
            ".rs": "rust",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".cs": "csharp",
            ".php": "php",
            ".rb": "ruby",
            ".pl": "perl",
            ".pm": "perl",
            ".swift": "swift",
            ".m": "objective-c",
            ".mm": "objective-cpp",
            ".r": "r",
            ".lua": "lua",
            ".sh": "shell",
            ".bash": "shell",
            ".zsh": "shell",
            ".fish": "shell",
            ".ps1": "powershell",
            ".bat": "batch",
            ".cmd": "batch",
            ".sql": "sql",
            ".graphql": "graphql",
            ".gql": "graphql",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".toml": "toml",
            ".ini": "ini",
            ".cfg": "ini",
            ".conf": "config",
            ".config": "config",
            ".properties": "properties",
            ".tf": "terraform",
            ".tfvars": "terraform",
            ".hcl": "hcl",
        }

        if suffix in language_map:
            return language_map[suffix]

        if name in {"dockerfile", "makefile", "cmakelists.txt"}:
            return name.replace(".", "").replace("-", "")

        return "text"