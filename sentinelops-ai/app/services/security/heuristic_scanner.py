from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern

from app.services.security.file_collector import CollectedFile


class Severity(Enum):
    """
    Severity levels for security findings.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(slots=True)
class SecurityFinding:
    """
    Represents a security finding from heuristic scanning.
    """

    rule_id: str
    severity: Severity
    file: str
    line: int
    message: str
    evidence: str


class HeuristicScanner:
    """
    Scans source code for obvious security anti-patterns.
    """

    def __init__(self) -> None:
        self._rules: list[HeuristicRule] = self._build_rules()

    def scan(self, files: list[CollectedFile]) -> list[SecurityFinding]:
        """
        Scan all collected files for security issues.
        """
        findings: list[SecurityFinding] = []
        for file in files:
            findings.extend(self._scan_file(file))
        return findings

    def _scan_file(self, file: CollectedFile) -> list[SecurityFinding]:
        """
        Scan a single file against all rules.
        """
        findings: list[SecurityFinding] = []
        lines = file.content.splitlines()

        for rule in self._rules:
            if not rule.applies_to(file.language):
                continue

            for line_num, line in enumerate(lines, start=1):
                for match in rule.pattern.finditer(line):
                    findings.append(
                        SecurityFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            file=str(file.path),
                            line=line_num,
                            message=rule.message,
                            evidence=match.group(0)[:200],
                        )
                    )

        return findings

    def _build_rules(self) -> list[HeuristicRule]:
        """
        Build the list of heuristic detection rules.
        """
        return [
            # Hardcoded secrets / API keys / passwords
            HeuristicRule(
                rule_id="SEC001",
                severity=Severity.CRITICAL,
                pattern=re.compile(
                    r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
                    re.IGNORECASE,
                ),
                message="Hardcoded secret or API key detected",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "shell", "powershell", "yaml", "json", "toml", "ini", "config", "properties"},
            ),
            HeuristicRule(
                rule_id="SEC002",
                severity=Severity.CRITICAL,
                pattern=re.compile(
                    r'(?i)(aws_access_key_id|aws_secret_access_key|aws_session_token|google_api_key|github_token|gitlab_token|slack_token|discord_token|stripe_key|sendgrid_key|mailgun_key|twilio_key|firebase_key|heroku_key|netlify_key|vercel_key)\s*[=:]\s*["\'][^"\']+["\']',
                    re.IGNORECASE,
                ),
                message="Hardcoded cloud/service credential detected",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "shell", "powershell", "yaml", "json", "toml", "ini", "config", "properties"},
            ),
            # Private keys
            HeuristicRule(
                rule_id="SEC003",
                severity=Severity.CRITICAL,
                pattern=re.compile(
                    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                ),
                message="Private key detected in source code",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "shell", "yaml", "json", "toml", "ini", "config", "properties", "text"},
            ),
            # eval/exec
            HeuristicRule(
                rule_id="SEC004",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"\b(eval|exec)\s*\(",
                ),
                message="Use of dangerous eval/exec function",
                languages={"python", "javascript", "typescript", "php", "ruby", "perl", "shell", "powershell"},
            ),
            HeuristicRule(
                rule_id="SEC005",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"\b(Function|setTimeout|setInterval)\s*\(\s*[\"'][^\"']*[\"']",
                ),
                message="Dynamic code execution via Function constructor or timer",
                languages={"javascript", "typescript"},
            ),
            # Dangerous subprocess/shell execution
            HeuristicRule(
                rule_id="SEC006",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"\b(subprocess\.(run|Popen|call|check_output|getstatusoutput|getoutput)|os\.(system|popen|popen2|popen3|popen4)|commands\.(getstatusoutput|getoutput))\s*\(",
                ),
                message="Dangerous shell command execution",
                languages={"python"},
            ),
            HeuristicRule(
                rule_id="SEC007",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"\b(child_process\.(exec|execFile|spawn|fork)|require\([\"']child_process[\"']\))\b",
                ),
                message="Dangerous child process execution",
                languages={"javascript", "typescript"},
            ),
            HeuristicRule(
                rule_id="SEC008",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(",
                ),
                message="Dangerous process execution",
                languages={"java"},
            ),
            HeuristicRule(
                rule_id="SEC009",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"\b(os\.exec|exec\.Command|syscall\.Exec)\b",
                ),
                message="Dangerous command execution",
                languages={"go"},
            ),
            # SQL string concatenation/interpolation
            HeuristicRule(
                rule_id="SEC010",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(cursor\.execute|conn\.execute|connection\.execute|db\.execute|database\.execute)\s*\(\s*[fF]?[\"'].*[\+\%]",
                ),
                message="Potential SQL injection via string concatenation/interpolation",
                languages={"python"},
            ),
            HeuristicRule(
                rule_id="SEC011",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(query|execute|prepare)\s*\(\s*[\"'].*\$\{.*\}",
                ),
                message="Potential SQL injection via template interpolation",
                languages={"javascript", "typescript", "go", "rust", "java", "csharp", "php"},
            ),
            HeuristicRule(
                rule_id="SEC012",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(Statement|PreparedStatement)\.execute.*[\+\|].*",
                ),
                message="Potential SQL injection via string concatenation",
                languages={"java"},
            ),
            # Path traversal
            HeuristicRule(
                rule_id="SEC013",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(open|read|write|file|path)\s*[\(\[]\s*.*\.\./",
                ),
                message="Potential path traversal vulnerability",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby"},
            ),
            HeuristicRule(
                rule_id="SEC014",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(os\.path\.join|path\.join|filepath\.Join)\s*\(\s*.*\.\./",
                ),
                message="Potential path traversal via path joining",
                languages={"python", "go"},
            ),
            # Weak crypto: MD5
            HeuristicRule(
                rule_id="SEC015",
                severity=Severity.MEDIUM,
                pattern=re.compile(
                    r"\b(hashlib\.md5|MessageDigest\.getInstance\([\"']MD5[\"']|md5\.(create|sum)|crypto\.createHash\([\"']md5[\"']|Digest::MD5|System\.Security\.Cryptography\.MD5)\b",
                ),
                message="Use of weak cryptographic hash MD5",
                languages={"python", "java", "javascript", "typescript", "go", "ruby", "csharp"},
            ),
            # Weak crypto: SHA1
            HeuristicRule(
                rule_id="SEC016",
                severity=Severity.MEDIUM,
                pattern=re.compile(
                    r"\b(hashlib\.sha1|MessageDigest\.getInstance\([\"']SHA-?1[\"']|sha1\.(create|sum)|crypto\.createHash\([\"']sha1[\"']|Digest::SHA1|System\.Security\.Cryptography\.SHA1)\b",
                ),
                message="Use of weak cryptographic hash SHA1",
                languages={"python", "java", "javascript", "typescript", "go", "ruby", "csharp"},
            ),
            # Weak crypto: DES/3DES
            HeuristicRule(
                rule_id="SEC017",
                severity=Severity.MEDIUM,
                pattern=re.compile(
                    r"\b(DES|3DES|TripleDES|DESede)\b",
                ),
                message="Use of weak encryption algorithm DES/3DES",
                languages={"python", "java", "javascript", "typescript", "go", "rust", "csharp", "php", "ruby"},
            ),
            # Hardcoded JWT secret
            HeuristicRule(
                rule_id="SEC018",
                severity=Severity.CRITICAL,
                pattern=re.compile(
                    r"(?i)(jwt[_-]?secret|jwt[_-]?key|jsonwebtoken[_-]?secret)\s*[=:]\s*[\"'][^\"']{16,}[\"]",
                ),
                message="Hardcoded JWT secret detected",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "yaml", "json", "toml", "ini", "config", "properties"},
            ),
            # Insecure random
            HeuristicRule(
                rule_id="SEC019",
                severity=Severity.MEDIUM,
                pattern=re.compile(
                    r"\b(random\.random|Math\.random\(\)|rand\(\)|Random\(\))\b",
                ),
                message="Use of cryptographically insecure random number generator",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby"},
            ),
            # Debug/development flags in production
            HeuristicRule(
                rule_id="SEC020",
                severity=Severity.LOW,
                pattern=re.compile(
                    r"(?i)(debug\s*=\s*true|DEBUG\s*=\s*True|development\s*=\s*true|DEVELOPMENT\s*=\s*True)",
                ),
                message="Debug/development mode enabled",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "yaml", "json", "toml", "ini", "config", "properties"},
            ),
            # TODO/FIXME security comments
            HeuristicRule(
                rule_id="SEC021",
                severity=Severity.INFO,
                pattern=re.compile(
                    r"(?i)(TODO|FIXME|XXX|HACK).*?(security|auth|password|secret|token|encrypt|decrypt|vuln|exploit|inject)",
                ),
                message="Security-related TODO/FIXME comment",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "c", "cpp", "shell"},
            ),
            # Insecure SSL/TLS verification disabled
            HeuristicRule(
                rule_id="SEC022",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(verify\s*=\s*False|verify_ssl\s*=\s*False|check_hostname\s*=\s*False|InsecureRequestWarning|setDefaultHostnameVerifier|TrustManager|X509TrustManager|checkServerTrusted)",
                ),
                message="SSL/TLS certificate verification disabled",
                languages={"python", "java", "javascript", "typescript", "go", "csharp"},
            ),
            # Hardcoded IP addresses (potential internal exposure)
            HeuristicRule(
                rule_id="SEC023",
                severity=Severity.LOW,
                pattern=re.compile(
                    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)\b",
                ),
                message="Hardcoded internal IP address or localhost",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "yaml", "json", "toml", "ini", "config", "properties", "shell"},
            ),
            # Exposed secrets in URLs
            HeuristicRule(
                rule_id="SEC024",
                severity=Severity.HIGH,
                pattern=re.compile(
                    r"(?i)(https?://)[^:\s]+:[^@\s]+@",
                ),
                message="Credentials embedded in URL",
                languages={"python", "javascript", "typescript", "java", "go", "rust", "csharp", "php", "ruby", "yaml", "json", "toml", "ini", "config", "properties", "shell"},
            ),
        ]


@dataclass(slots=True)
class HeuristicRule:
    """
    Represents a single heuristic detection rule.
    """

    rule_id: str
    severity: Severity
    pattern: Pattern[str]
    message: str
    languages: set[str]

    def applies_to(self, language: str) -> bool:
        """
        Check if this rule applies to the given language.
        """
        return language in self.languages or "text" in self.languages