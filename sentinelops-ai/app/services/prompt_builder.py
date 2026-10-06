"""
app/builders/prompt_builder.py

Builds the prompt sent to the LLM.
"""

from __future__ import annotations

from app.models.repository_context import RepositoryContext


class PromptBuilder:
    """
    Builds the PushAgent prompt.

    The prompt explains the GitHub push and asks the
    LLM to identify what changed, relevant findings,
    recommendations, and overall security risk.

    This builder contains no LLM logic.
    """

    def build(
        self,
        context: RepositoryContext,
    ) -> str:

        sections: list[str] = []

        sections.append(
            """
You are SentinelOps PushAgent.

Your responsibility is to analyze a GitHub Push
from a software engineering and security perspective.

Analyze the changes and determine:

1. What changed.
2. Important findings from the changes.
3. Recommended actions, if any.
4. Overall security and engineering risk.

Do not invent issues that are not supported by the
provided repository changes.

A trivial test-data or text-file modification should
normally receive LOW risk unless the provided context
indicates otherwise.

Return ONLY valid JSON.

Do NOT return markdown.

Do NOT explain anything outside the JSON.

The response MUST contain exactly these fields:

- summary
- findings
- recommendations
- risk_level

risk_level MUST be exactly one of:

LOW
MEDIUM
HIGH
CRITICAL
""".strip()
        )

        sections.append(
            f"""
Repository:
{context.repository_full_name}

Branch:
{context.branch}

Previous Commit:
{context.before_commit}

Current Commit:
{context.after_commit}
""".strip()
        )

        for changed_file in context.changed_files:

            sections.append(
                f"""
===============================================================================

FILE

Path:
{changed_file.path}

Status:
{changed_file.status}

OLD FILE

{changed_file.old_content}

NEW FILE

{changed_file.new_content}

DIFF

{changed_file.diff}
""".strip()
            )

        sections.append(
            """
===============================================================================

Return ONLY JSON using exactly this schema:

{
    "summary": "Brief description of what changed.",
    "findings": [
        "Important finding about the change."
    ],
    "recommendations": [
        "Recommended action, if any."
    ],
    "risk_level": "LOW"
}

Rules:

- "summary" must be a string.
- "findings" must be an array of strings.
- "recommendations" must be an array of strings.
- "risk_level" must be one of:
  "LOW", "MEDIUM", "HIGH", "CRITICAL".
- Do not return any additional fields.
- Do not return developer_intent.
- Do not return change_categories.
- Do not return files.
- Do not return overall_impact.
- Do not return potential_risks.
- Do not return breaking_changes.
- Do not return confidence.
""".strip()
        )

        return "\n\n".join(sections)