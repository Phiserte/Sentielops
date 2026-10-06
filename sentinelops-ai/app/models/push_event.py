"""
Internal representation of a GitHub Push Event.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True, frozen=True)
class PushEvent:
    """
    Internal representation of a GitHub Push Event.

    This model is independent of GitHub's webhook payload.
    It contains only the information required by SentinelOps.
    """

    # ==========================================================
    # Event Metadata
    # ==========================================================

    delivery_id: str
    event_type: str

    received_at: datetime

    # ==========================================================
    # Repository
    # ==========================================================

    repository_name: str
    repository_full_name: str

    clone_url: str

    default_branch: str
    branch: str

    # ==========================================================
    # Commit Range
    # ==========================================================

    before_commit: str
    after_commit: str

    # ==========================================================
    # Actor
    # ==========================================================

    sender: str

    installation_id: int | None = None