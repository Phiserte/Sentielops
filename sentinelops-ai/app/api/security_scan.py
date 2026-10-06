import logging
from dataclasses import asdict

from fastapi import APIRouter, HTTPException

from app.core.dependency import security_agent
from app.models.repository_service_request import RepositoryServiceRequest

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/security/scan")
async def security_scan(request: RepositoryServiceRequest):
    """
    Trigger a security scan on a repository.

    Uses the Repository Service to fetch repository files for the after_commit,
    then runs the complete SecurityAgent pipeline: heuristic scan, SAST, and optional LLM analysis.
    """

    logger.info("=" * 80)
    logger.info("Security scan requested.")
    logger.info("Repository: %s", request.repository_full_name)
    logger.info("Branch: %s", request.branch)
    logger.info("Commit: %s", request.after_commit[:8])

    if security_agent._repository_client is None:
        logger.error("RepositoryClient not configured on SecurityAgent.")
        raise HTTPException(
            status_code=503,
            detail="Repository Service not configured. Set REPOSITORY_SERVICE_URL.",
        )

    try:
        result = await security_agent.scan_repository_files(
            repository_name=request.repository_name,
            repository_full_name=request.repository_full_name,
            clone_url=request.clone_url,
            default_branch=request.default_branch,
            branch=request.branch,
            commit=request.after_commit,
            extensions=request.extensions,
            max_file_size=request.max_file_size,
        )

    except Exception as e:
        logger.exception("Security scan failed.")
        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {str(e)}",
        )

    logger.info(
        "Security scan completed. Files: %d, Findings: %d, Risk: %s",
        result.files_scanned,
        len(result.findings),
        result.risk_level,
    )

    response = {
        "status": "success",
        "repository": request.repository_full_name,
        "branch": request.branch,
        "commit": request.after_commit,
        "files_scanned": result.files_scanned,
        "findings_count": len(result.findings),
        "risk_level": result.risk_level,
        "llm_risk_level": result.llm_risk_level,
        "heuristic_findings": result.heuristic_duration_ms,
        "sast_findings": result.sast_duration_ms,
        "context_selection_ms": result.context_selection_duration_ms,
        "llm_analysis_ms": result.llm_analysis_duration_ms,
        "total_duration_ms": result.scan_duration_ms,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
        "sast_errors": result.sast_result.errors if result.sast_result else [],
        "llm_analysis": (
            {
                "summary": result.llm_analysis.summary,
                "risk_level": result.llm_analysis.risk_level,
                "recommendations": result.llm_analysis.recommendations,
                "validated_findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "file": f.file,
                        "line": f.line,
                        "message": f.message,
                        "evidence": f.evidence,
                        "is_valid": f.is_valid,
                        "is_false_positive": f.is_false_positive,
                        "explanation": f.explanation,
                        "attack_scenario": f.attack_scenario,
                        "remediation": f.remediation,
                        "additional_issues": f.additional_issues,
                    }
                    for f in result.llm_analysis.findings
                ],
            }
            if result.llm_analysis
            else None
        ),
    }

    logger.info("=" * 80)

    return response


@router.get("/security/health")
async def security_health():
    """
    Health check for security scanning service.
    """
    return {
        "status": "ok",
        "llm_enabled": security_agent._enable_llm_analysis,
        "repository_client_configured": security_agent._repository_client is not None,
    }