import hmac
import json
import logging
import secrets
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException

from app.core.config import CLI_API_TOKEN
from app.core.dependency import push_agent
from app.models.cli_push_request import CLIPushRequest
from app.models.push_event import PushEvent
from app.services.github_event_service import mark_event_processed, save_analysis, save_event

logger = logging.getLogger(__name__)
router = APIRouter()


def authenticate_cli(authorization: str | None = Header(default=None)) -> None:
    if not CLI_API_TOKEN:
        raise HTTPException(status_code=503, detail="CLI authentication is not configured")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, CLI_API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid CLI API token")


@router.post("/cli/push-analysis", dependencies=[Depends(authenticate_cli)])
async def cli_push_analysis(request: CLIPushRequest):
    delivery_id = f"cli-{uuid4()}"
    received_at = datetime.now(timezone.utc)
    payload = request.model_dump(mode="json")
    event_record = save_event(delivery_id, "cli_push", payload)
    event = PushEvent(
        delivery_id=delivery_id,
        event_type="push",
        repository_name=request.repository_name,
        repository_full_name=request.repository_full_name,
        clone_url=str(request.clone_url),
        default_branch=request.default_branch,
        branch=request.branch,
        before_commit=request.before_commit,
        after_commit=request.after_commit,
        sender=request.sender,
        installation_id=None,
        received_at=received_at,
    )
    try:
        analysis = await push_agent.execute(event)
        save_analysis(
            github_event_id=event_record.id,
            summary=analysis.summary,
            findings=analysis.findings,
            recommendations=analysis.recommendations,
            risk_level=analysis.risk_level,
            model=analysis.model,
        )
        mark_event_processed(github_event_id=event_record.id)
    except Exception as exc:
        logger.exception("CLI push analysis failed")
        raise HTTPException(status_code=500, detail="Push analysis failed") from exc

    return {"status": "success", "analysis": asdict(analysis)}
