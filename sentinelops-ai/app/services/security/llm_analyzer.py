from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field, ValidationError

from app.services.openrouter_client import OpenRouterClient
from app.services.security.context_selector import FindingContext

logger = logging.getLogger(__name__)


class LLMFinding(BaseModel):
    """
    A single finding from LLM analysis.
    """
    rule_id: str
    severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    file: str
    line: int
    message: str
    evidence: str
    is_valid: bool
    is_false_positive: bool
    explanation: str
    attack_scenario: str
    remediation: str
    additional_issues: list[str] = Field(default_factory=list)


class LLMAnalysisResponse(BaseModel):
    """
    Structured response from the security LLM analyzer.
    """
    summary: str
    findings: list[LLMFinding]
    recommendations: list[str]
    risk_level: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")


@dataclass(slots=True)
class LLMAnalysisResult:
    """
    Result of LLM security analysis.
    """
    findings: list[LLMFinding]
    summary: str
    recommendations: list[str]
    risk_level: str
    errors: list[str]
    raw_response: Optional[str] = None


class SecurityLLMAnalyzer:
    """
    Analyzes security findings using an LLM.
    """

    MAX_BATCH_SIZE = 3

    def __init__(
        self,
        llm_client: Optional[OpenRouterClient] = None,
        model: Optional[str] = None,
        batch_size: int = MAX_BATCH_SIZE,
    ) -> None:
        self._llm_client = llm_client
        self._model = model
        self._batch_size = max(1, min(batch_size, self.MAX_BATCH_SIZE))

    async def analyze(
        self,
        finding_contexts: list[FindingContext],
    ) -> LLMAnalysisResult:
        """
        Send finding contexts to LLM for security analysis in batches.
        """
        if not finding_contexts:
            return LLMAnalysisResult(
                findings=[],
                summary="No findings to analyze.",
                recommendations=[],
                risk_level="LOW",
                errors=[],
            )

        if self._llm_client is None:
            try:
                self._llm_client = OpenRouterClient()
            except RuntimeError as e:
                return LLMAnalysisResult(
                    findings=[],
                    summary="LLM analysis unavailable.",
                    recommendations=[],
                    risk_level="LOW",
                    errors=[f"Failed to initialize LLM client: {e}"],
                )

        batches = self._create_batches(finding_contexts)
        all_findings: list[LLMFinding] = []
        all_recommendations: list[str] = []
        all_errors: list[str] = []
        summaries: list[str] = []
        risk_levels: list[str] = []
        raw_responses: list[str] = []

        for batch in batches:
            prompt = self._build_prompt(batch)
            try:
                raw_response = await self._llm_client.generate(prompt)
                raw_responses.append(raw_response)
                batch_result = self._parse_response(raw_response, batch)
                all_findings.extend(batch_result.findings)
                all_recommendations.extend(batch_result.recommendations)
                all_errors.extend(batch_result.errors)
                if batch_result.summary:
                    summaries.append(batch_result.summary)
                if batch_result.risk_level:
                    risk_levels.append(batch_result.risk_level)
            except Exception as e:
                logger.exception("LLM analysis batch failed")
                all_errors.append(f"Batch analysis error: {str(e)}")

        merged_risk = self._merge_risk_levels(risk_levels)
        merged_summary = self._merge_summaries(summaries)
        merged_recommendations = self._deduplicate(all_recommendations)

        return LLMAnalysisResult(
            findings=all_findings,
            summary=merged_summary,
            recommendations=merged_recommendations,
            risk_level=merged_risk,
            errors=all_errors,
            raw_response="\n---\n".join(raw_responses) if raw_responses else None,
        )

    def _create_batches(self, finding_contexts: list[FindingContext]) -> list[list[FindingContext]]:
        """
        Split finding contexts into batches of size <= batch_size.
        Prioritizes by severity (CRITICAL/HIGH first).
        """
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        sorted_contexts = sorted(
            finding_contexts,
            key=lambda fc: severity_order.get(fc.finding.severity.value, 5),
        )
        return [
            sorted_contexts[i : i + self._batch_size]
            for i in range(0, len(sorted_contexts), self._batch_size)
        ]

    def _merge_risk_levels(self, risk_levels: list[str]) -> str:
        """Merge risk levels, returning the highest."""
        if not risk_levels:
            return "LOW"
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return max(risk_levels, key=lambda r: order.get(r, 0))

    def _merge_summaries(self, summaries: list[str]) -> str:
        """Combine summaries into a single summary."""
        if not summaries:
            return "No findings analyzed."
        if len(summaries) == 1:
            return summaries[0]
        return " ".join(summaries)

    def _deduplicate(self, items: list[str]) -> list[str]:
        """Remove duplicates while preserving order."""
        seen = set()
        result = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    def _build_prompt(self, finding_contexts: list[FindingContext]) -> str:
        """
        Build the prompt for LLM security analysis.
        """
        context_sections = []
        for i, fc in enumerate(finding_contexts, 1):
            ctx = fc.context
            finding = fc.finding

            section = f"""
=== FINDING #{i} ===
Rule ID: {finding.rule_id}
Scanner Severity: {finding.severity.value}
File: {finding.file}
Line: {finding.line}
Scanner Message: {finding.message}
Scanner Evidence: {finding.evidence}

=== CODE CONTEXT (lines {ctx.start_line}-{ctx.end_line}) ===
```{ctx.language}
{ctx.content}
```
"""
            context_sections.append(section)

        contexts_text = "\n".join(context_sections)

        return f"""
You are a senior security engineer performing a targeted code review.

Below are {len(finding_contexts)} security findings from automated scanners (heuristic/SAST), each with relevant code context.

Your task for EACH finding:
1. VALIDATE: Is this a real vulnerability or a false positive?
2. SEVERITY: Determine the actual severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
3. EXPLAIN: Explain the vulnerability in clear terms
4. ATTACK SCENARIO: Describe a realistic attack scenario
5. REMEDIATION: Provide specific fix recommendations
6. ADDITIONAL ISSUES: Identify any OTHER security issues visible in the supplied code context

Return ONLY valid JSON matching this schema:
{{
  "summary": "string - overall security assessment",
  "findings": [
    {{
      "rule_id": "string - original rule_id from scanner",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "file": "string",
      "line": "integer",
      "message": "string - concise finding description",
      "evidence": "string - code snippet",
      "is_valid": "boolean - true if real vulnerability",
      "is_false_positive": "boolean - true if false positive",
      "explanation": "string - detailed explanation",
      "attack_scenario": "string - realistic attack scenario",
      "remediation": "string - specific fix",
      "additional_issues": ["string"] - other issues in context
    }}
  ],
  "recommendations": ["string"] - overall recommendations,
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL"
}}

IMPORTANT:
- Be precise and technical
- Only mark as false positive if you are confident
- "is_valid" and "is_false_positive" are mutually exclusive
- If additional_issues found, include them
- Never claim "no findings" means secure - scanners have blind spots

FINDINGS TO ANALYZE:
{contexts_text}
""".strip()

    def _parse_response(
        self,
        raw_response: str,
        finding_contexts: list[FindingContext],
    ) -> LLMAnalysisResult:
        """
        Parse and validate LLM response.
        """
        errors: list[str] = []

        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError as e:
            logger.error(f"LLM returned invalid JSON: {e}")
            errors.append(f"Invalid JSON: {e}")
            return LLMAnalysisResult(
                findings=[],
                summary="LLM returned invalid JSON.",
                recommendations=[],
                risk_level="LOW",
                errors=errors,
                raw_response=raw_response,
            )

        try:
            validated = LLMAnalysisResponse.model_validate(data)
        except ValidationError as e:
            logger.error(f"LLM response validation failed: {e}")
            errors.append(f"Validation error: {e}")
            return LLMAnalysisResult(
                findings=[],
                summary="LLM response validation failed.",
                recommendations=[],
                risk_level="LOW",
                errors=errors,
                raw_response=raw_response,
            )

        llm_findings = []
        for llm_finding in validated.findings:
            if llm_finding.rule_id.startswith("CONTEXT-"):
                continue

            llm_findings.append(llm_finding)

        return LLMAnalysisResult(
            findings=llm_findings,
            summary=validated.summary,
            recommendations=validated.recommendations,
            risk_level=validated.risk_level,
            errors=errors,
            raw_response=raw_response,
        )


def create_security_llm_analyzer(
    llm_client: Optional[OpenRouterClient] = None,
    model: Optional[str] = None,
) -> SecurityLLMAnalyzer:
    """
    Factory function to create a SecurityLLMAnalyzer.
    """
    return SecurityLLMAnalyzer(llm_client=llm_client, model=model)