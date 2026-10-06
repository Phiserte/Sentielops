from dataclasses import dataclass, field
from datetime import datetime

from app.models.push_event import PushEvent


@dataclass(slots=True)
class AnalysisJob:
    """
    Represents one repository analysis request.
    """

    event: PushEvent

    status: str = "pending"

    retries: int = 0

    created_at: datetime = field(
        default_factory=datetime.utcnow
    )

    started_at: datetime | None = None

    completed_at: datetime | None = None

    error: str | None = None