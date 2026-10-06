from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.database.models.analysis import Analysis


class GitHubEvent(Base):
    __tablename__ = "github_events"

    id: Mapped[int] = mapped_column(primary_key=True)

    delivery_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    payload: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    processed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    analyses: Mapped[list["Analysis"]] = relationship(
        "Analysis",
        back_populates="github_event",
        cascade="all, delete-orphan",
    )