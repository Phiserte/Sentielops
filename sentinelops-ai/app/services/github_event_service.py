from app.database import SessionLocal
from app.database.models.analysis import Analysis
from app.database.models.github_event import GitHubEvent


def save_event(
    delivery_id: str,
    event_type: str,
    payload: dict,
) -> GitHubEvent:

    db = SessionLocal()

    try:
        event = GitHubEvent(
            delivery_id=delivery_id,
            event_type=event_type,
            payload=payload,
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def save_analysis(
    github_event_id: int,
    summary: str,
    findings: list[str],
    recommendations: list[str],
    risk_level: str,
    model: str | None,
) -> Analysis:

    db = SessionLocal()

    try:
        analysis = Analysis(
            github_event_id=github_event_id,
            summary=summary,
            findings=findings,
            recommendations=recommendations,
            risk_level=risk_level,
            model=model,
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        return analysis

    finally:
        db.close()


def mark_event_processed(
    github_event_id: int,
) -> None:

    db = SessionLocal()

    try:
        event = db.get(GitHubEvent, github_event_id)

        if event is None:
            raise ValueError(
                f"GitHub event not found: {github_event_id}"
            )

        event.processed = True

        db.commit()

    finally:
        db.close()