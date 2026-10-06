"""
Application shared dependencies.

This module creates long-lived service instances that are shared
across the application.
"""

from app.core.config import REPOSITORY_SERVICE_URL

from app.agents.github.push_agent import PushAgent
from app.agents.security.security_agent import SecurityAgent

from app.services.repository_client import RepositoryClient
from app.services.openrouter_client import OpenRouterClient
from app.services.context_builder import ContextBuilder
from app.services.prompt_builder import PromptBuilder
from app.services.analysis_parser import AnalysisParser


# ==========================================================
# Services
# ==========================================================

repository_client = RepositoryClient(
    base_url=REPOSITORY_SERVICE_URL,
)

context_builder = ContextBuilder()

prompt_builder = PromptBuilder()

llm_client = OpenRouterClient()

analysis_parser = AnalysisParser()


# ==========================================================
# Agents
# ==========================================================

push_agent = PushAgent(
    repository_client=repository_client,
    context_builder=context_builder,
    prompt_builder=prompt_builder,
    llm_client=llm_client,
    analysis_parser=analysis_parser,
)

security_agent = SecurityAgent(
    repository_client=repository_client,
    enable_llm_analysis=False,
)