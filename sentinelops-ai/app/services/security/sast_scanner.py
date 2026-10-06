from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.services.security.file_collector import CollectedFile
from app.services.security.heuristic_scanner import SecurityFinding, Severity

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SASTResult:
    """
    Result of a SAST scan.
    """

    tool: str
    findings: list[SecurityFinding]
    errors: list[str]
    scan_duration_ms: float


class SASTScanner:
    """
    Runs SAST tools and parses results into unified finding format.
    """

    def __init__(self, timeout: int = 120) -> None:
        self._timeout = timeout

    def scan(self, repo_path: Path, files: list[CollectedFile]) -> SASTResult:
        """
        Run SAST scans appropriate for the repository.

        Currently supports:
        - Bandit for Python code
        """
        import time

        start_time = time.perf_counter()
        all_findings: list[SecurityFinding] = []
        all_errors: list[str] = []

        if self._has_python_files(files):
            bandit_result = self._run_bandit(repo_path)
            all_findings.extend(bandit_result.findings)
            all_errors.extend(bandit_result.errors)

        scan_duration_ms = (time.perf_counter() - start_time) * 1000

        return SASTResult(
            tool="bandit" if self._has_python_files(files) else "none",
            findings=all_findings,
            errors=all_errors,
            scan_duration_ms=scan_duration_ms,
        )

    def _has_python_files(self, files: list[CollectedFile]) -> bool:
        """
        Check if the repository contains Python files.
        """
        return any(f.language == "python" for f in files)

    def _run_bandit(self, repo_path: Path) -> SASTResult:
        """
        Run Bandit SAST scanner on Python code.
        """
        import time

        start_time = time.perf_counter()
        findings: list[SecurityFinding] = []
        errors: list[str] = []

        bandit_path = shutil.which("bandit")
        if not bandit_path:
            errors.append("Bandit not installed. Install with: pip install bandit")
            return SASTResult(
                tool="bandit",
                findings=[],
                errors=errors,
                scan_duration_ms=(time.perf_counter() - start_time) * 1000,
            )

        try:
            result = subprocess.run(
                [
                    bandit_path,
                    "-r",
                    str(repo_path),
                    "-f",
                    "json",
                    "-q",
                ],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            if result.returncode not in (0, 1):
                errors.append(f"Bandit exited with code {result.returncode}: {result.stderr[:500]}")
                return SASTResult(
                    tool="bandit",
                    findings=findings,
                    errors=errors,
                    scan_duration_ms=(time.perf_counter() - start_time) * 1000,
                )

            if result.stdout:
                findings.extend(self._parse_bandit_output(result.stdout))

        except subprocess.TimeoutExpired:
            errors.append(f"Bandit timed out after {self._timeout} seconds")
        except subprocess.SubprocessError as e:
            errors.append(f"Bandit execution failed: {e}")
        except json.JSONDecodeError as e:
            errors.append(f"Failed to parse Bandit JSON output: {e}")

        return SASTResult(
            tool="bandit",
            findings=findings,
            errors=errors,
            scan_duration_ms=(time.perf_counter() - start_time) * 1000,
        )

    def _parse_bandit_output(self, output: str) -> list[SecurityFinding]:
        """
        Parse Bandit JSON output into SecurityFinding objects.
        """
        findings: list[SecurityFinding] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])

        for issue in results:
            try:
                finding = self._convert_bandit_issue(issue)
                if finding:
                    findings.append(finding)
            except (KeyError, ValueError) as e:
                logger.warning(f"Failed to parse Bandit issue: {e}")
                continue

        return findings

    def _convert_bandit_issue(self, issue: dict) -> Optional[SecurityFinding]:
        """
        Convert a single Bandit issue to SecurityFinding.
        """
        severity_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }

        severity_str = issue.get("issue_severity", "LOW").upper()
        severity = severity_map.get(severity_str, Severity.LOW)

        test_id = issue.get("test_id", "UNKNOWN")
        rule_id = f"BANDIT-{test_id}"

        filename = issue.get("filename", "")
        line_number = issue.get("line_number", 0)
        issue_text = issue.get("issue_text", "")
        code = issue.get("code", "")

        evidence = code[:200] if code else issue_text[:200]

        return SecurityFinding(
            rule_id=rule_id,
            severity=severity,
            file=filename,
            line=line_number,
            message=issue_text,
            evidence=evidence,
        )


def create_sast_scanner(timeout: int = 120) -> SASTScanner:
    """
    Factory function to create a SASTScanner.
    """
    return SASTScanner(timeout=timeout)