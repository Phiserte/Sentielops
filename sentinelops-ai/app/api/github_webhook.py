import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from app.core.dependency import push_agent
from app.models.push_event import PushEvent
from app.services.github_event_service import (
    mark_event_processed,
    save_analysis,
    save_event,
)
from app.services.github_signature import verify_signature

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/webhooks/github")
async def github_webhook(request: Request):

    logger.info("=" * 80)
    logger.info("GitHub webhook received.")

    payload = await request.body()

    signature = request.headers.get("X-Hub-Signature-256")

    logger.info("Verifying GitHub webhook signature...")

    if not verify_signature(payload, signature):
        logger.error("GitHub webhook signature verification failed.")

        raise HTTPException(
            status_code=401,
            detail="Invalid GitHub signature",
        )

    logger.info("Signature verified successfully.")

    payload_json = json.loads(payload)

    delivery_id = request.headers.get(
        "X-GitHub-Delivery",
        "",
    )

    event_type = request.headers.get(
        "X-GitHub-Event",
        "",
    )

    logger.info("Delivery ID: %s", delivery_id)
    logger.info("Event Type : %s", event_type)

    logger.info("Saving webhook event to database...")

    github_event = save_event(
        delivery_id=delivery_id,
        event_type=event_type,
        payload=payload_json,
    )

    logger.info(
        "Webhook event saved successfully. Database ID: %s",
        github_event.id,
    )

    # SentinelOps currently analyzes only push events.
    if event_type != "push":
        logger.info(
            "Ignoring unsupported event type '%s'.",
            event_type,
        )

        return {
            "status": "ignored",
            "event_type": event_type,
        }

    logger.info("Creating PushEvent object...")

    event = PushEvent(
        delivery_id=delivery_id,
        event_type=event_type,
        repository_name=payload_json["repository"]["name"],
        repository_full_name=payload_json["repository"]["full_name"],
        clone_url=payload_json["repository"]["clone_url"],
        default_branch=payload_json["repository"]["default_branch"],
        branch=payload_json["ref"].replace(
            "refs/heads/",
            "",
        ),
        before_commit=payload_json["before"],
        after_commit=payload_json["after"],
        sender=payload_json["sender"]["login"],
        installation_id=(
            payload_json["installation"]["id"]
            if payload_json.get("installation")
            else None
        ),
        received_at=datetime.now(timezone.utc),
    )

    logger.info(
        "PushEvent created for repository '%s'.",
        event.repository_full_name,
    )

    logger.info("Starting PushAgent execution...")

    analysis = await push_agent.execute(event)

    logger.info(
        "PushAgent execution completed successfully."
    )

    logger.info("Saving analysis result to database...")

    save_analysis(
        github_event_id=github_event.id,
        summary=analysis.summary,
        findings=analysis.findings,
        recommendations=analysis.recommendations,
        risk_level=analysis.risk_level,
        model=analysis.model,
    )

    logger.info(
        "Analysis result saved successfully."
    )

    logger.info("Marking GitHub event as processed...")

    mark_event_processed(
        github_event_id=github_event.id,
    )

    logger.info(
        "GitHub event marked as processed."
    )

    response = {
        "status": "success",
        "analysis": asdict(analysis),
    }

    logger.info("Returning analysis to caller.")
    logger.info("=" * 80)
    logger.info(type(analysis))
    logger.info("Response: %s", response)

    return response