from abc import ABC, abstractmethod

from app.models.analysis_result import AnalysisResult


class LLMClient(ABC):
    """
    Base interface for all LLM providers.
    """

    @abstractmethod
    async def generate(
        self,
        prompt: str,
    ) -> AnalysisResult:
        """
        Generate an AI analysis from the supplied prompt.
        """
        raise NotImplementedError