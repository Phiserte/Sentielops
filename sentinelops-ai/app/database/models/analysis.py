from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.database.models.github_event import GitHubEvent


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)

    github_event_id: Mapped[int] = mapped_column(
        ForeignKey("github_events.id"),
        nullable=False,
        index=True,
    )

    summary: Mapped[str] = mapped_column(
        nullable=False,
    )

    findings: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
    )

    recommendations: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    model: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    github_event: Mapped[GitHubEvent] = relationship(
        back_populates="analyses",
    )