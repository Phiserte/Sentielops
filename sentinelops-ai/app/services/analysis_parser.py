"""
app/services/analysis_parser.py

Converts raw LLM JSON into SentinelOps'
internal AnalysisResult model.
"""

from __future__ import annotations

import json
import logging

from app.models.analysis_result import AnalysisResult


logger = logging.getLogger(__name__)


class AnalysisParser:
    """
    Parses and validates LLM responses.
    """

    VALID_RISK_LEVELS = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    REQUIRED_FIELDS = (
        "summary",
        "findings",
        "recommendations",
        "risk_level",
    )

    @classmethod
    def parse(
        cls,
        response: str,
        *,
        model: str | None = None,
    ) -> AnalysisResult:
        """
        Parse the raw JSON response returned by the LLM.

        Parameters
        ----------
        response:
            Raw JSON string.

        model:
            Model name.

        Returns
        -------
        AnalysisResult
        """

        try:

            data = json.loads(response)

        except json.JSONDecodeError as exc:

            logger.exception(
                "Invalid JSON returned by LLM."
            )

            raise RuntimeError(
                "LLM returned invalid JSON."
            ) from exc

        cls._validate_required_fields(data)

        cls._validate_types(data)

        cls._validate_risk_level(
            data["risk_level"],
        )

        logger.info(
            "Successfully parsed analysis result."
        )

        return AnalysisResult(
            summary=data["summary"].strip(),
            findings=data["findings"],
            recommendations=data["recommendations"],
            risk_level=data["risk_level"],
            model=model,
        )

    @classmethod
    def _validate_required_fields(
        cls,
        data: dict,
    ) -> None:

        missing = [
            field
            for field in cls.REQUIRED_FIELDS
            if field not in data
        ]

        if missing:

            raise RuntimeError(
                "Missing required fields: "
                + ", ".join(missing)
            )

    @classmethod
    def _validate_types(
        cls,
        data: dict,
    ) -> None:

        if not isinstance(
            data["summary"],
            str,
        ):
            raise RuntimeError(
                "'summary' must be a string."
            )

        if not isinstance(
            data["findings"],
            list,
        ):
            raise RuntimeError(
                "'findings' must be a list."
            )

        if not isinstance(
            data["recommendations"],
            list,
        ):
            raise RuntimeError(
                "'recommendations' must be a list."
            )

        if not isinstance(
            data["risk_level"],
            str,
        ):
            raise RuntimeError(
                "'risk_level' must be a string."
            )

    @classmethod
    def _validate_risk_level(
        cls,
        risk_level: str,
    ) -> None:

        if risk_level not in cls.VALID_RISK_LEVELS:

            raise RuntimeError(
                "Invalid risk level "
                f"'{risk_level}'."
            )