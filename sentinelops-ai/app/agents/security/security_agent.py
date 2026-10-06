from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

from app.models.repository_service_request import (
    RepositoryFilesRequest,
    RepositoryServiceRequest,
)
from app.models.repository_service_response import (
    RepositoryFilesResponse,
    RepositoryServiceResponse,
)
from app.services.repository_client import RepositoryClient
from app.services.security.context_selector import ContextSelector, FindingContext
from app.services.security.file_collector import CollectedFile, FileCollector
from app.services.security.heuristic_scanner import HeuristicScanner, SecurityFinding, Severity
from app.services.security.llm_analyzer import LLMAnalysisResult, SecurityLLMAnalyzer
from app.services.security.sast_scanner import SASTResult, SASTScanner


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SecurityScanResult:
    """
    Result of a security scan.
    """

    repository_path: str
    files_scanned: int
    findings: list[SecurityFinding]
    scan_duration_ms: float
    sast_result: Optional[SASTResult] = None
    heuristic_duration_ms: float = 0.0
    sast_duration_ms: float = 0.0
    context_selection_duration_ms: float = 0.0
    llm_analysis: Optional[LLMAnalysisResult] = None
    llm_analysis_duration_ms: float = 0.0
    finding_contexts: list[FindingContext] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def heuristic_findings(self) -> list[SecurityFinding]:
        if not self.sast_result:
            return self.findings
        sast_rule_ids = {f.rule_id for f in self.sast_result.findings}
        return [f for f in self.findings if f.rule_id not in sast_rule_ids]

    @property
    def sast_findings(self) -> list[SecurityFinding]:
        if not self.sast_result:
            return []
        return self.sast_result.findings

    @property
    def llm_findings(self) -> list:
        if not self.llm_analysis:
            return []
        return self.llm_analysis.findings

    @property
    def validated_findings(self) -> list:
        if not self.llm_analysis:
            return []
        return [f for f in self.llm_analysis.findings if f.is_valid and not f.is_false_positive]

    @property
    def false_positives(self) -> list:
        if not self.llm_analysis:
            return []
        return [f for f in self.llm_analysis.findings if f.is_false_positive]

    @property
    def risk_level(self) -> str:
        if self.critical_count > 0:
            return "CRITICAL"
        if self.high_count > 0:
            return "HIGH"
        if self.medium_count > 0:
            return "MEDIUM"
        if self.low_count > 0:
            return "LOW"
        return "NONE"

    @property
    def llm_risk_level(self) -> str:
        if not self.llm_analysis:
            return self.risk_level
        return self.llm_analysis.risk_level


class SecurityAgent:
    """
    Orchestrates security analysis of a repository.

    Pipeline:
    1. Collect relevant source/config files
    2. Run heuristic scanner for obvious patterns
    3. Run SAST scanner (Bandit for Python)
    4. Select relevant code context for findings
    5. Run LLM security analysis (optional)
    6. Return structured security findings
    """

    def __init__(
        self,
        file_collector: Optional[FileCollector] = None,
        heuristic_scanner: Optional[HeuristicScanner] = None,
        sast_scanner: Optional[SASTScanner] = None,
        context_selector: Optional[ContextSelector] = None,
        llm_analyzer: Optional[SecurityLLMAnalyzer] = None,
        repository_client: Optional[RepositoryClient] = None,
        enable_llm_analysis: bool = False,
    ) -> None:
        self._file_collector = file_collector or FileCollector()
        self._heuristic_scanner = heuristic_scanner or HeuristicScanner()
        self._sast_scanner = sast_scanner or SASTScanner()
        self._context_selector = context_selector or ContextSelector()
        self._llm_analyzer = llm_analyzer
        self._repository_client = repository_client
        self._enable_llm_analysis = enable_llm_analysis

    def scan(self, repository_path: Path) -> SecurityScanResult:
        """
        Execute the security scan pipeline on a repository.

        Args:
            repository_path: Path to the repository root

        Returns:
            SecurityScanResult with all findings
        """
        import time

        overall_start = time.perf_counter()

        collected_files = self._file_collector.collect(repository_path)

        heuristic_start = time.perf_counter()
        heuristic_findings = self._heuristic_scanner.scan(collected_files)
        heuristic_duration_ms = (time.perf_counter() - heuristic_start) * 1000

        sast_start = time.perf_counter()
        sast_result = self._sast_scanner.scan(repository_path, collected_files)
        sast_duration_ms = (time.perf_counter() - sast_start) * 1000

        all_findings = heuristic_findings + sast_result.findings

        context_start = time.perf_counter()
        finding_contexts = self._context_selector.select_contexts(all_findings, collected_files)
        context_selection_duration_ms = (time.perf_counter() - context_start) * 1000

        llm_analysis = None
        llm_analysis_duration_ms = 0.0

        if self._enable_llm_analysis and finding_contexts:
            if self._llm_analyzer is None:
                self._llm_analyzer = SecurityLLMAnalyzer()

            llm_start = time.perf_counter()
            llm_analysis = self._llm_analyzer.analyze(finding_contexts)
            llm_analysis_duration_ms = (time.perf_counter() - llm_start) * 1000

        scan_duration_ms = (time.perf_counter() - overall_start) * 1000

        return SecurityScanResult(
            repository_path=str(repository_path),
            files_scanned=len(collected_files),
            findings=all_findings,
            scan_duration_ms=scan_duration_ms,
            sast_result=sast_result,
            heuristic_duration_ms=heuristic_duration_ms,
            sast_duration_ms=sast_duration_ms,
            context_selection_duration_ms=context_selection_duration_ms,
            llm_analysis=llm_analysis,
            llm_analysis_duration_ms=llm_analysis_duration_ms,
            finding_contexts=finding_contexts,
        )

    async def scan_async(self, repository_path: Path) -> SecurityScanResult:
        """
        Execute the security scan pipeline asynchronously.

        Args:
            repository_path: Path to the repository root

        Returns:
            SecurityScanResult with all findings
        """
        import time

        overall_start = time.perf_counter()

        collected_files = self._file_collector.collect(repository_path)

        heuristic_start = time.perf_counter()
        heuristic_findings = self._heuristic_scanner.scan(collected_files)
        heuristic_duration_ms = (time.perf_counter() - heuristic_start) * 1000

        sast_start = time.perf_counter()
        sast_result = self._sast_scanner.scan(repository_path, collected_files)
        sast_duration_ms = (time.perf_counter() - sast_start) * 1000

        all_findings = heuristic_findings + sast_result.findings

        context_start = time.perf_counter()
        finding_contexts = self._context_selector.select_contexts(all_findings, collected_files)
        context_selection_duration_ms = (time.perf_counter() - context_start) * 1000

        llm_analysis = None
        llm_analysis_duration_ms = 0.0

        if self._enable_llm_analysis and finding_contexts:
            if self._llm_analyzer is None:
                self._llm_analyzer = SecurityLLMAnalyzer()

            llm_start = time.perf_counter()
            llm_analysis = await self._llm_analyzer.analyze(finding_contexts)
            llm_analysis_duration_ms = (time.perf_counter() - llm_start) * 1000

        scan_duration_ms = (time.perf_counter() - overall_start) * 1000

        return SecurityScanResult(
            repository_path=str(repository_path),
            files_scanned=len(collected_files),
            findings=all_findings,
            scan_duration_ms=scan_duration_ms,
            sast_result=sast_result,
            heuristic_duration_ms=heuristic_duration_ms,
            sast_duration_ms=sast_duration_ms,
            context_selection_duration_ms=context_selection_duration_ms,
            llm_analysis=llm_analysis,
            llm_analysis_duration_ms=llm_analysis_duration_ms,
            finding_contexts=finding_contexts,
        )

    async def scan_repository(
        self,
        repository_name: str,
        repository_full_name: str,
        clone_url: str,
        default_branch: str,
        branch: str,
        before_commit: str,
        after_commit: str,
    ) -> SecurityScanResult:
        """
        Execute the security scan pipeline on a repository via Repository Service.

        Args:
            repository_name: Repository name (e.g., "test_automation")
            repository_full_name: Full repository name (e.g., "Phiserte/test_automation")
            clone_url: Git clone URL
            default_branch: Default branch name
            branch: Branch to scan
            before_commit: Base commit SHA
            after_commit: Head commit SHA

        Returns:
            SecurityScanResult with all findings

        Raises:
            RuntimeError: If Repository Service is not configured or request fails
        """
        if self._repository_client is None:
            raise RuntimeError(
                "RepositoryClient not configured. Pass repository_client to SecurityAgent "
                "or set REPOSITORY_SERVICE_URL in environment."
            )

        request = RepositoryServiceRequest(
            repository_name=repository_name,
            repository_full_name=repository_full_name,
            clone_url=clone_url,
            default_branch=default_branch,
            branch=branch,
            before_commit=before_commit,
            after_commit=after_commit,
        )

        repo_response = await self._repository_client.ensure(request)

        return await self.scan_async(Path(repo_response.repository_path))

    def scan_repository_sync(
        self,
        repository_name: str,
        repository_full_name: str,
        clone_url: str,
        default_branch: str,
        branch: str,
        before_commit: str,
        after_commit: str,
    ) -> SecurityScanResult:
        """
        Synchronous version of scan_repository.

        Args:
            repository_name: Repository name (e.g., "test_automation")
            repository_full_name: Full repository name (e.g., "Phiserte/test_automation")
            clone_url: Git clone URL
            default_branch: Default branch name
            branch: Branch to scan
            before_commit: Base commit SHA
            after_commit: Head commit SHA

        Returns:
            SecurityScanResult with all findings

        Raises:
            RuntimeError: If Repository Client is not configured or request fails
        """
        import asyncio

        return asyncio.run(self.scan_repository(
            repository_name=repository_name,
            repository_full_name=repository_full_name,
            clone_url=clone_url,
            default_branch=default_branch,
            branch=branch,
            before_commit=before_commit,
            after_commit=after_commit,
        ))

    def enable_llm_analysis(self, enabled: bool = True) -> None:
        """
        Enable or disable LLM analysis.
        """
        self._enable_llm_analysis = enabled

    def set_llm_analyzer(self, analyzer: SecurityLLMAnalyzer) -> None:
        """
        Set a custom LLM analyzer.
        """
        self._llm_analyzer = analyzer
        self._enable_llm_analysis = True

    def _files_response_to_collected(
        self,
        files_response: RepositoryFilesResponse,
    ) -> list[CollectedFile]:
        """
        Convert RepositoryFilesResponse to list of CollectedFile.

        Validates paths to prevent path traversal.
        """
        collected: list[CollectedFile] = []

        for file_resp in files_response.files:
            rel_path = Path(file_resp.path)

            if rel_path.is_absolute() or ".." in rel_path.parts:
                logger.warning(
                    "Skipping file with unsafe path: %s",
                    file_resp.path,
                )
                continue

            try:
                content = file_resp.content
                language = file_resp.language or self._detect_language(rel_path)

                collected.append(
                    CollectedFile(
                        path=rel_path,
                        content=content,
                        language=language,
                    )
                )
            except Exception as e:
                logger.warning(
                    "Failed to process file %s: %s",
                    file_resp.path,
                    e,
                )
                continue

        return collected

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

    async def scan_repository_files(
        self,
        repository_name: str,
        repository_full_name: str,
        clone_url: str,
        default_branch: str,
        branch: str,
        commit: str,
        max_file_size: int | None = None,
        extensions: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> SecurityScanResult:
        """
        Execute the security scan pipeline by fetching repository files via Repository Service.

        Args:
            repository_name: Repository name (e.g., "test_automation")
            repository_full_name: Full repository name (e.g., "Phiserte/test_automation")
            clone_url: Git clone URL
            default_branch: Default branch name
            branch: Branch to scan
            commit: Commit SHA to scan
            max_file_size: Maximum file size in bytes (optional)
            extensions: File extensions to include (optional)
            exclude_patterns: Glob patterns to exclude (optional)

        Returns:
            SecurityScanResult with all findings

        Raises:
            RuntimeError: If RepositoryClient is not configured or request fails
        """
        if self._repository_client is None:
            raise RuntimeError(
                "RepositoryClient not configured. Pass repository_client to SecurityAgent "
                "or set REPOSITORY_SERVICE_URL in environment."
            )

        request = RepositoryFilesRequest(
            repository_full_name=repository_full_name,
            commit=commit,
            max_file_size=max_file_size,
            extensions=extensions,
        )

        files_response = await self._repository_client.get_files(request)

        collected_files = self._files_response_to_collected(files_response)

        return await self._scan_collected_files(
            collected_files=collected_files,
            repository_identifier=f"{repository_full_name}@{commit[:8]}",
        )

    async def _scan_collected_files(
        self,
        collected_files: list[CollectedFile],
        repository_identifier: str,
    ) -> SecurityScanResult:
        """
        Execute the security scan pipeline on pre-collected files.

        Creates a temporary directory with the files and runs the existing pipeline.
        """
        import time

        overall_start = time.perf_counter()

        with TemporaryDirectory(prefix="sentinelops-scan-") as tmp_dir:
            tmp_path = Path(tmp_dir)

            for collected in collected_files:
                file_path = tmp_path / collected.path
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(collected.content, encoding="utf-8")

            heuristic_start = time.perf_counter()
            heuristic_findings = self._heuristic_scanner.scan(collected_files)
            heuristic_duration_ms = (time.perf_counter() - heuristic_start) * 1000

            sast_start = time.perf_counter()
            sast_result = self._sast_scanner.scan(tmp_path, collected_files)
            sast_duration_ms = (time.perf_counter() - sast_start) * 1000

            all_findings = heuristic_findings + sast_result.findings

            context_start = time.perf_counter()
            finding_contexts = self._context_selector.select_contexts(all_findings, collected_files)
            context_selection_duration_ms = (time.perf_counter() - context_start) * 1000

            llm_analysis = None
            llm_analysis_duration_ms = 0.0

            if self._enable_llm_analysis and finding_contexts:
                if self._llm_analyzer is None:
                    self._llm_analyzer = SecurityLLMAnalyzer()

                llm_start = time.perf_counter()
                llm_analysis = await self._llm_analyzer.analyze(finding_contexts)
                llm_analysis_duration_ms = (time.perf_counter() - llm_start) * 1000

            scan_duration_ms = (time.perf_counter() - overall_start) * 1000

            return SecurityScanResult(
                repository_path=repository_identifier,
                files_scanned=len(collected_files),
                findings=all_findings,
                scan_duration_ms=scan_duration_ms,
                sast_result=sast_result,
                heuristic_duration_ms=heuristic_duration_ms,
                sast_duration_ms=sast_duration_ms,
                context_selection_duration_ms=context_selection_duration_ms,
                llm_analysis=llm_analysis,
                llm_analysis_duration_ms=llm_analysis_duration_ms,
                finding_contexts=finding_contexts,
            )