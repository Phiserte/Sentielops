from __future__ import annotations

from app.models.analysis_result import AnalysisResult
from app.models.push_event import PushEvent
from app.models.repository_context import RepositoryContext
from app.models.repository_service_request import RepositoryServiceRequest
from app.models.repository_service_response import RepositoryServiceResponse

from app.services.analysis_parser import AnalysisParser
from app.services.context_builder import ContextBuilder
from app.services.llm_client import LLMClient
from app.services.prompt_builder import PromptBuilder
from app.services.repository_client import RepositoryClient


class PushAgent:
    """
    Orchestrates the complete GitHub Push analysis workflow.

            PushEvent
               │
               ▼
    Repository Service
               │
               ▼
      RepositoryContext
               │
               ▼
       Prompt Builder
               │
               ▼
         LLM Provider
               │
               ▼
      Analysis Parser
               │
               ▼
       AnalysisResult
    """

    def __init__(
        self,
        repository_client: RepositoryClient,
        context_builder: ContextBuilder,
        prompt_builder: PromptBuilder,
        llm_client: LLMClient,
        analysis_parser: AnalysisParser,
    ) -> None:

        self._repository_client = repository_client
        self._context_builder = context_builder
        self._prompt_builder = prompt_builder
        self._llm_client = llm_client
        self._analysis_parser = analysis_parser

    async def execute(
        self,
        event: PushEvent,
    ) -> AnalysisResult:
        """
        Execute the complete Push analysis pipeline.
        """

        repository = await self._prepare_repository(event)

        context = await self._build_context(repository)

        prompt = self._build_prompt(context)

        response = await self._generate_analysis(prompt)

        return self._parse_analysis(response)

    async def _prepare_repository(
        self,
        event: PushEvent,
    ) -> RepositoryServiceResponse:
        """
        Prepare the repository using the Repository Service.
        """

        request = RepositoryServiceRequest(
            repository_name=event.repository_name,
            repository_full_name=event.repository_full_name,
            clone_url=event.clone_url,
            default_branch=event.default_branch,
            branch=event.branch,
            before_commit=event.before_commit,
            after_commit=event.after_commit,
        )

        return await self._repository_client.ensure(request)

    async def _build_context(
        self,
        repository: RepositoryServiceResponse,
    ) -> RepositoryContext:
        """
        Build the RepositoryContext consumed by the PromptBuilder.
        """

        return await self._context_builder.build(repository)

    def _build_prompt(
        self,
        context: RepositoryContext,
    ) -> str:
        """
        Build the prompt sent to the LLM.
        """

        return self._prompt_builder.build(context)

    async def _generate_analysis(
        self,
        prompt: str,
    ) -> str:
        """
        Generate the AI analysis.
        """

        return await self._llm_client.generate(prompt)

    def _parse_analysis(
        self,
        response: str,
    ) -> AnalysisResult:
        """
        Parse the LLM response into an AnalysisResult.
        """

        return self._analysis_parser.parse(response)