"""
app/services/openrouter_client.py

Production-grade OpenRouter client.

Responsibilities
----------------
- Communicate with OpenRouter.
- Send prompts.
- Request JSON through prompt instructions.
- Retry transient failures.
- Return raw JSON.

This class DOES NOT parse responses.
Parsing is handled by AnalysisParser.
"""

from __future__ import annotations

import asyncio
import logging

from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncOpenAI,
    RateLimitError,
)

from app.core.config import (
    LLM_MODEL,
    LLM_TEMPERATURE,
    OPENROUTER_API_KEY,
)
from app.services.llm_client import LLMClient


logger = logging.getLogger(__name__)


class OpenRouterClient(LLMClient):
    """
    OpenRouter implementation of the LLMClient interface.
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 2
    REQUEST_TIMEOUT = 120

    def __init__(self) -> None:

        if not OPENROUTER_API_KEY:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not configured."
            )

        self._provider = "openrouter"
        self._model = LLM_MODEL
        self._temperature = LLM_TEMPERATURE

        self.client = AsyncOpenAI(
            api_key=OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
            timeout=self.REQUEST_TIMEOUT,
        )

        logger.info(
            "Initialized OpenRouter client "
            "with model '%s'",
            self._model,
        )

        logger.info(
            "OpenRouter temperature: %s",
            self._temperature,
        )

        logger.info(
            "OpenRouter timeout: %s seconds",
            self.REQUEST_TIMEOUT,
        )

    @property
    def provider_name(self) -> str:
        return self._provider

    @property
    def model_name(self) -> str:
        return self._model

    @staticmethod
    def _system_prompt() -> str:
        """
        Returns the fixed SentinelOps system prompt.
        """

        return """
You are SentinelOps AI.

You are an expert:

- Senior Software Engineer
- Security Engineer
- DevSecOps Engineer
- Cloud Engineer
- Code Reviewer

You MUST always return valid JSON.

Do NOT return markdown.

Do NOT explain anything.

Do NOT wrap JSON inside ```.

Return ONLY JSON.

Expected JSON schema:

{
    "summary": "string",
    "findings": [
        "string"
    ],
    "recommendations": [
        "string"
    ],
    "risk_level": "LOW | MEDIUM | HIGH | CRITICAL"
}
""".strip()

    @staticmethod
    def _response_schema() -> dict:
        """
        Structured Output JSON Schema.

        Kept for models/providers that support structured
        outputs. The current free Nemotron model is not
        using this parameter.
        """

        return {
            "type": "json_schema",
            "json_schema": {
                "name": "analysis_result",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "summary": {
                            "type": "string"
                        },
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "recommendations": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "risk_level": {
                            "type": "string",
                            "enum": [
                                "LOW",
                                "MEDIUM",
                                "HIGH",
                                "CRITICAL",
                            ],
                        },
                    },
                    "required": [
                        "summary",
                        "findings",
                        "recommendations",
                        "risk_level",
                    ],
                    "additionalProperties": False,
                },
            },
        }

    async def _retry_sleep(
        self,
        attempt: int,
    ) -> None:
        """
        Exponential backoff.
        """

        delay = self.RETRY_DELAY * attempt

        logger.info(
            "Waiting %s seconds before retry...",
            delay,
        )

        await asyncio.sleep(delay)

    async def generate(
        self,
        prompt: str,
    ) -> str:
        """
        Sends a prompt to OpenRouter and returns the raw JSON response.

        Raises
        ------
        RuntimeError
            If all retry attempts fail.
        """

        last_exception: Exception | None = None

        for attempt in range(1, self.MAX_RETRIES + 1):

            try:

                logger.info("=" * 70)

                logger.info(
                    "Sending request to OpenRouter "
                    "(Attempt %s/%s)",
                    attempt,
                    self.MAX_RETRIES,
                )

                logger.info(
                    "Provider: %s",
                    self._provider,
                )

                logger.info(
                    "Model: %s",
                    self._model,
                )

                logger.info(
                    "Temperature: %s",
                    self._temperature,
                )

                logger.info(
                    "Prompt length: %s characters",
                    len(prompt),
                )

                logger.info(
                    "Requesting JSON through system prompt."
                )

                # The current free Nemotron endpoint is called
                # without response_format because the provider
                # returned a 404 when response_format was supplied.

                response = await self.client.chat.completions.create(
                    model=self._model,
                    temperature=self._temperature,
                    messages=[
                        {
                            "role": "system",
                            "content": self._system_prompt(),
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ],
                )

                # ==================================================
                # Response diagnostics
                # ==================================================

                logger.info(
                    "OpenRouter request completed."
                )

                logger.info(
                    "Response type: %s",
                    type(response),
                )

                logger.info(
                    "Response ID: %s",
                    getattr(response, "id", None),
                )

                logger.info(
                    "Response model: %s",
                    getattr(response, "model", None),
                )

                logger.info(
                    "Response provider: %s",
                    getattr(response, "provider", None),
                )

                logger.info(
                    "Response usage: %s",
                    getattr(response, "usage", None),
                )

                choices = getattr(
                    response,
                    "choices",
                    None,
                )

                logger.info(
                    "Response choices present: %s",
                    choices is not None,
                )

                if choices is None:

                    logger.error(
                        "OpenRouter returned choices=None."
                    )

                    logger.error(
                        "Full response object: %r",
                        response,
                    )

                    raise RuntimeError(
                        "OpenRouter returned no choices."
                    )

                if not choices:

                    logger.error(
                        "OpenRouter returned an empty choices list."
                    )

                    logger.error(
                        "Full response object: %r",
                        response,
                    )

                    raise RuntimeError(
                        "OpenRouter returned an empty choices list."
                    )

                # ==================================================
                # First choice
                # ==================================================

                first_choice = choices[0]

                logger.info(
                    "First choice finish reason: %s",
                    getattr(
                        first_choice,
                        "finish_reason",
                        None,
                    ),
                )

                logger.info(
                    "First choice native finish reason: %s",
                    getattr(
                        first_choice,
                        "native_finish_reason",
                        None,
                    ),
                )

                message = getattr(
                    first_choice,
                    "message",
                    None,
                )

                if message is None:

                    logger.error(
                        "OpenRouter returned no message "
                        "inside the first choice."
                    )

                    logger.error(
                        "First choice: %r",
                        first_choice,
                    )

                    raise RuntimeError(
                        "OpenRouter returned a choice "
                        "without a message."
                    )

                # ==================================================
                # Message diagnostics
                # ==================================================

                logger.info(
                    "Message role: %s",
                    getattr(
                        message,
                        "role",
                        None,
                    ),
                )

                logger.info(
                    "Message refusal: %s",
                    getattr(
                        message,
                        "refusal",
                        None,
                    ),
                )

                content = getattr(
                    message,
                    "content",
                    None,
                )

                logger.info(
                    "Response content present: %s",
                    content is not None,
                )

                logger.info(
                    "Response content length: %s",
                    len(content) if content else 0,
                )

                # TEMPORARY DEBUG:
                # Show exactly what the model returned so we can
                # diagnose the AnalysisParser validation failure.
                if content:

                    logger.info(
                        "OpenRouter raw content: %s",
                        content,
                    )

                if not content:

                    logger.error(
                        "OpenRouter returned empty message content."
                    )

                    logger.error(
                        "Message object: %r",
                        message,
                    )

                    raise RuntimeError(
                        "OpenRouter returned an empty response."
                    )

                logger.info(
                    "OpenRouter response received successfully."
                )

                logger.info(
                    "Returning raw response to AnalysisParser."
                )

                logger.info("=" * 70)

                return content

            except (
                RateLimitError,
                APIConnectionError,
                APITimeoutError,
            ) as exc:

                last_exception = exc

                logger.warning(
                    "Transient OpenRouter error "
                    "(Attempt %s/%s): %s",
                    attempt,
                    self.MAX_RETRIES,
                    exc,
                )

                if attempt < self.MAX_RETRIES:

                    await self._retry_sleep(attempt)

            except Exception as exc:

                logger.exception(
                    "Unexpected OpenRouter error."
                )

                raise RuntimeError(
                    "OpenRouter request failed."
                ) from exc

        raise RuntimeError(
            "OpenRouter failed after "
            f"{self.MAX_RETRIES} attempts."
        ) from last_exception

    async def health_check(
        self,
    ) -> bool:
        """
        Performs a lightweight health check.
        """

        logger.info(
            "Running OpenRouter health check..."
        )

        try:

            response = await self.client.chat.completions.create(
                model=self._model,
                messages=[
                    {
                        "role": "user",
                        "content": "ping",
                    }
                ],
                max_tokens=1,
            )

            logger.info(
                "OpenRouter health check succeeded."
            )

            logger.info(
                "Health check model: %s",
                getattr(
                    response,
                    "model",
                    None,
                ),
            )

            logger.info(
                "Health check provider: %s",
                getattr(
                    response,
                    "provider",
                    None,
                ),
            )

            return True

        except Exception:

            logger.exception(
                "OpenRouter health check failed."
            )

            return False

    async def close(
        self,
    ) -> None:
        """
        Cleanup resources.
        """

        logger.info(
            "Closing OpenRouter client..."
        )

        try:

            await self.client.close()

            logger.info(
                "OpenRouter client closed."
            )

        except Exception:

            logger.exception(
                "Failed to close OpenRouter client."
            )