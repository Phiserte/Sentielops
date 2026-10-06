from dataclasses import dataclass, field


@dataclass(slots=True)
class AnalysisResult:
    """
    Structured AI analysis.
    """

    summary: str

    findings: list[str] = field(default_factory=list)

    recommendations: list[str] = field(default_factory=list)

    risk_level: str = "LOW"

    model: str | None = None