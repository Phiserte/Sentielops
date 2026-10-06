from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.services.security.file_collector import CollectedFile
from app.services.security.heuristic_scanner import SecurityFinding, Severity


@dataclass(slots=True)
class CodeContext:
    """
    Represents a code snippet with surrounding context.
    """

    file_path: str
    language: str
    start_line: int
    end_line: int
    content: str
    finding_line: Optional[int] = None


@dataclass(slots=True)
class FindingContext:
    """
    A finding paired with its relevant code context.
    """

    finding: SecurityFinding
    context: CodeContext


class ContextSelector:
    """
    Selects relevant code context for security findings and identifies
    high-risk files for targeted LLM review.
    """

    CONTEXT_LINES_BEFORE = 10
    CONTEXT_LINES_AFTER = 10
    MAX_CONTEXT_CHARS = 8000
    MAX_TOTAL_CONTEXT_CHARS = 50000

    SEVERITY_PRIORITY = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }

    HIGH_RISK_PATTERNS = {
        "auth": [
            "login", "logout", "authenticate", "authorization", "permission",
            "session", "token", "jwt", "oauth", "saml", "ldap", "password",
            "credential", "secret", "api_key", "access_token", "refresh_token"
        ],
        "database": [
            "execute", "query", "select", "insert", "update", "delete",
            "cursor", "connection", "transaction", "commit", "rollback",
            "orm", "sqlalchemy", "django.db", "psycopg", "sqlite3", "mysql",
            "pymongo", "redis", "firestore"
        ],
        "filesystem": [
            "open(", "read(", "write(", "file(", "path", "os.path",
            "pathlib", "shutil", "tempfile", "upload", "download",
            "send_file", "static_file", "send_from_directory"
        ],
        "subprocess": [
            "subprocess", "os.system", "os.popen", "commands.",
            "child_process", "exec(", "spawn", "fork", "popen",
            "Runtime.getRuntime", "ProcessBuilder", "syscall.Exec"
        ],
        "network": [
            "requests", "httpx", "urllib", "aiohttp", "fetch",
            "axios", "http.client", "socket", "websocket", "grpc",
            "urllib3", "curl", "wget"
        ],
        "crypto": [
            "hashlib", "hmac", "secrets", "cryptography", "bcrypt",
            "argon2", "scrypt", "pbkdf2", "fernet", "aes", "rsa",
            "ecdsa", "ed25519", "jwt", "jws", "jwe", "sign", "verify",
            "encrypt", "decrypt", "cipher", "digest"
        ],
        "api": [
            "fastapi", "flask", "django", "starlette", "express",
            "koa", "gin", "echo", "chi", "router", "endpoint",
            "route", "handler", "controller", "middleware",
            "decorator", "blueprint", "app.route", "@app."
        ],
    }

    def __init__(
        self,
        context_lines_before: int = CONTEXT_LINES_BEFORE,
        context_lines_after: int = CONTEXT_LINES_AFTER,
        max_context_chars: int = MAX_CONTEXT_CHARS,
        max_total_context_chars: int = MAX_TOTAL_CONTEXT_CHARS,
    ) -> None:
        self._context_lines_before = context_lines_before
        self._context_lines_after = context_lines_after
        self._max_context_chars = max_context_chars
        self._max_total_context_chars = max_total_context_chars

    def select_contexts(
        self,
        findings: list[SecurityFinding],
        collected_files: list[CollectedFile],
    ) -> list[FindingContext]:
        """
        Build code context for each finding and identify high-risk files.
        Prioritizes CRITICAL/HIGH findings, deduplicates overlapping findings,
        and ensures high-risk code reaches LLM even without scanner findings.
        """
        file_map = {str(f.path): f for f in collected_files}

        finding_contexts = self._build_finding_contexts(findings, file_map)
        finding_contexts = self._deduplicate_finding_contexts(finding_contexts)

        high_risk_contexts = self._identify_high_risk_files(collected_files, finding_contexts)
        finding_contexts.extend(high_risk_contexts)

        finding_contexts = self._prioritize_and_trim(finding_contexts)

        return finding_contexts

    def _build_finding_contexts(
        self,
        findings: list[SecurityFinding],
        file_map: dict[str, CollectedFile],
    ) -> list[FindingContext]:
        """
        Extract code context for each finding.
        """
        finding_contexts: list[FindingContext] = []

        for finding in findings:
            file_obj = file_map.get(finding.file)
            if not file_obj:
                continue

            context = self._extract_context(file_obj, finding.line)
            if context:
                finding_contexts.append(FindingContext(finding=finding, context=context))

        return finding_contexts

    def _extract_context(
        self,
        file_obj: CollectedFile,
        finding_line: int,
    ) -> Optional[CodeContext]:
        """
        Extract code context around a finding line.
        """
        lines = file_obj.content.splitlines()
        if not lines:
            return None

        total_lines = len(lines)
        start = max(0, finding_line - 1 - self._context_lines_before)
        end = min(total_lines, finding_line + self._context_lines_after)

        context_lines = lines[start:end]
        content = "\n".join(context_lines)

        if len(content) > self._max_context_chars:
            content = content[: self._max_context_chars] + "\n... [truncated]"

        return CodeContext(
            file_path=str(file_obj.path),
            language=file_obj.language,
            start_line=start + 1,
            end_line=end,
            content=content,
            finding_line=finding_line,
        )

    def _deduplicate_finding_contexts(
        self,
        contexts: list[FindingContext],
    ) -> list[FindingContext]:
        """
        Deduplicate findings that represent the same vulnerability.
        Groups by file and overlapping line ranges, keeping highest severity.
        Does NOT merge different vulnerability types that happen to be near each other.
        """
        if not contexts:
            return []

        contexts.sort(
            key=lambda fc: (
                fc.context.file_path,
                fc.context.start_line,
                self.SEVERITY_PRIORITY.get(fc.finding.severity, 5),
            )
        )

        deduplicated: list[FindingContext] = []

        for fc in contexts:
            if not deduplicated:
                deduplicated.append(fc)
                continue

            last = deduplicated[-1]

            if fc.context.file_path != last.context.file_path:
                deduplicated.append(fc)
                continue

            overlap = self._contexts_overlap(fc.context, last.context)

            if not overlap:
                deduplicated.append(fc)
                continue

            if self._is_same_vulnerability(fc.finding, last.finding):
                if self.SEVERITY_PRIORITY.get(fc.finding.severity, 5) < self.SEVERITY_PRIORITY.get(last.finding.severity, 5):
                    deduplicated[-1] = fc
            else:
                deduplicated.append(fc)

        return deduplicated

    def _contexts_overlap(self, ctx1: CodeContext, ctx2: CodeContext) -> bool:
        """Check if two code contexts overlap in line range."""
        return not (ctx1.end_line < ctx2.start_line or ctx2.end_line < ctx1.start_line)

    def _is_same_vulnerability(self, f1: SecurityFinding, f2: SecurityFinding) -> bool:
        """
        Determine if two findings likely represent the same vulnerability.
        """
        if f1.rule_id == f2.rule_id:
            return True

        heuristic_rules = {"SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008", "SEC009",
                          "SEC010", "SEC011", "SEC012", "SEC013", "SEC014", "SEC015", "SEC016", "SEC017", "SEC018",
                          "SEC019", "SEC020", "SEC021", "SEC022", "SEC023", "SEC024"}

        sast_rules = {r for r in [f1.rule_id, f2.rule_id] if r.startswith("BANDIT-")}

        if f1.rule_id in heuristic_rules and f2.rule_id in heuristic_rules:
            same_category = (f1.rule_id[:5] == f2.rule_id[:5])
            return same_category

        if f1.rule_id in sast_rules and f2.rule_id in sast_rules:
            return True

        if f1.rule_id in heuristic_rules and f2.rule_id in sast_rules:
            return self._heuristic_matches_sast(f1.rule_id, f2.rule_id)

        if f2.rule_id in heuristic_rules and f1.rule_id in sast_rules:
            return self._heuristic_matches_sast(f2.rule_id, f1.rule_id)

        return False

    def _heuristic_matches_sast(self, heuristic_id: str, sast_id: str) -> bool:
        """Map heuristic rules to corresponding Bandit rules."""
        mapping = {
            "SEC001": ["BANDIT-B105", "BANDIT-B106"],
            "SEC004": ["BANDIT-B307", "BANDIT-B301"],
            "SEC006": ["BANDIT-B605", "BANDIT-B603", "BANDIT-B404"],
            "SEC010": ["BANDIT-B608"],
            "SEC016": ["BANDIT-B607"],
        }
        return sast_id in mapping.get(heuristic_id, [])

    def _identify_high_risk_files(
        self,
        collected_files: list[CollectedFile],
        existing_contexts: list[FindingContext],
    ) -> list[FindingContext]:
        """
        Identify high-risk files/functions even without scanner findings.
        """
        existing_ranges: dict[str, list[tuple[int, int]]] = {}
        for fc in existing_contexts:
            existing_ranges.setdefault(fc.context.file_path, []).append(
                (fc.context.start_line, fc.context.end_line)
            )

        high_risk_contexts: list[FindingContext] = []

        for file_obj in collected_files:
            file_path = str(file_obj.path)

            risk_category = self._assess_file_risk(file_obj)
            if not risk_category:
                continue

            context = self._extract_high_risk_context(file_obj, risk_category)
            if not context:
                continue

            if self._range_covered(context, existing_ranges.get(file_path, [])):
                continue

            pseudo_finding = SecurityFinding(
                rule_id=f"CONTEXT-{risk_category.upper()}",
                severity=Severity.INFO,
                file=file_path,
                line=context.finding_line or 1,
                message=f"High-risk {risk_category} code identified for review",
                evidence=context.content[:200],
            )
            high_risk_contexts.append(FindingContext(finding=pseudo_finding, context=context))

        return high_risk_contexts

    def _range_covered(self, context: CodeContext, existing_ranges: list[tuple[int, int]]) -> bool:
        """Check if context range is already covered by existing contexts."""
        for start, end in existing_ranges:
            if not (context.end_line < start or context.start_line > end):
                return True
        return False

    def _assess_file_risk(self, file_obj: CollectedFile) -> Optional[str]:
        """
        Assess if a file contains high-risk patterns.
        """
        content_lower = file_obj.content.lower()
        scores = {}

        for category, patterns in self.HIGH_RISK_PATTERNS.items():
            score = sum(content_lower.count(p.lower()) for p in patterns)
            if score > 0:
                scores[category] = score

        if not scores:
            return None

        return max(scores, key=scores.get)

    def _extract_high_risk_context(
        self,
        file_obj: CollectedFile,
        risk_category: str,
    ) -> Optional[CodeContext]:
        """
        Extract context from a high-risk file around the most relevant section.
        """
        lines = file_obj.content.splitlines()
        if not lines:
            return None

        patterns = self.HIGH_RISK_PATTERNS.get(risk_category, [])
        best_line = 1
        best_score = 0

        for i, line in enumerate(lines):
            line_lower = line.lower()
            score = sum(line_lower.count(p.lower()) for p in patterns)
            if score > best_score:
                best_score = score
                best_line = i + 1

        return self._extract_context(file_obj, best_line)

    def _prioritize_and_trim(
        self,
        contexts: list[FindingContext],
    ) -> list[FindingContext]:
        """
        Prioritize contexts by severity and trim to total character limit.
        """
        if not contexts:
            return []

        contexts.sort(
            key=lambda fc: (
                self.SEVERITY_PRIORITY.get(fc.finding.severity, 5),
                fc.context.file_path,
                fc.context.start_line,
            )
        )

        trimmed: list[FindingContext] = []
        current_chars = 0

        for fc in contexts:
            context_len = len(fc.context.content)

            if current_chars + context_len <= self._max_total_context_chars:
                trimmed.append(fc)
                current_chars += context_len
            else:
                remaining = self._max_total_context_chars - current_chars
                if remaining > 500:
                    fc.context.content = fc.context.content[:remaining] + "\n... [truncated]"
                    trimmed.append(fc)
                break

        return trimmed