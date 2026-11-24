"""Local Ollama LLM provider implementation with async HTTP, circuit breaker, and strict telemetry."""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
import httpx

from disstroy.llm.base import BaseLLMProvider
from disstroy.models.asset import Asset
from disstroy.models.enums import FailureCategory, HypothesisCategory, HypothesisStatus
from disstroy.models.failure import FailureLesson
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.observation import Observation

logger = logging.getLogger(__name__)


class OllamaProvider(BaseLLMProvider):
    """Integrates local Ollama models (e.g. Llama 3, Mistral, Qwen) with fast circuit-breaker and fallback."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "llama3.2:latest",
        timeout: float = 10.0,
        fallback: Optional[BaseLLMProvider] = None,
        circuit_breaker_ttl: float = 10.0,
    ):
        # Normalize localhost to 127.0.0.1 to avoid Windows IPv6 resolution latency
        normalized_url = base_url.rstrip("/")
        if "://localhost" in normalized_url:
            normalized_url = normalized_url.replace("://localhost", "://127.0.0.1")

        self.base_url = normalized_url
        self.model = model
        self.timeout = timeout
        self.fallback = fallback
        self.circuit_breaker_ttl = circuit_breaker_ttl

        # Circuit breaker state
        self._cached_available: Optional[bool] = None
        self._last_health_check: float = 0.0
        self._last_error: Optional[str] = None

        # Telemetry
        self.total_calls: int = 0
        self.successful_calls: int = 0
        self.total_fallbacks: int = 0

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self.model

    async def is_available(self, force_check: bool = False) -> bool:
        """Ping local Ollama daemon with circuit-breaker caching."""
        now = time.time()
        if not force_check and self._cached_available is not None and (now - self._last_health_check) < self.circuit_breaker_ttl:
            return self._cached_available

        try:
            # Fast ping with 0.35s timeout
            async with httpx.AsyncClient(timeout=0.35) as client:
                res = await client.get(f"{self.base_url}/api/tags")
                self._cached_available = (res.status_code == 200)
                self._last_error = None if self._cached_available else f"HTTP {res.status_code}"
        except Exception as e:
            self._cached_available = False
            self._last_error = f"{type(e).__name__}: {e}"

        self._last_health_check = now
        return self._cached_available

    async def generate_text(self, prompt: str, system: Optional[str] = None) -> str:
        """Invoke Ollama /api/generate endpoint with strict fallback tracking."""
        self.total_calls += 1

        if not await self.is_available():
            if self.fallback:
                self.total_fallbacks += 1
                return await self.fallback.generate_text(prompt, system)
            raise ConnectionError(f"Ollama daemon unreachable at {self.base_url}: {self._last_error}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                }
                if system:
                    payload["system"] = system

                res = await client.post(f"{self.base_url}/api/generate", json=payload)
                if res.status_code == 200:
                    self.successful_calls += 1
                    return res.json().get("response", "")
                raise RuntimeError(f"Ollama returned HTTP {res.status_code}: {res.text}")
        except Exception as e:
            self._cached_available = False
            self._last_error = str(e)
            if self.fallback:
                self.total_fallbacks += 1
                logger.warning(f"Ollama call failed ({e}); invoking fallback provider.")
                return await self.fallback.generate_text(prompt, system)
            raise

    async def generate_hypotheses(
        self,
        asset: Asset,
        observations: List[Observation],
        active_lessons: List[FailureLesson],
    ) -> List[Hypothesis]:
        """Synthesize competing hypotheses with test plans and transparent provider metadata."""
        self.total_calls += 1

        # Check circuit breaker
        if not await self.is_available():
            if self.fallback:
                self.total_fallbacks += 1
                hyps = await self.fallback.generate_hypotheses(asset, observations, active_lessons)
                for h in hyps:
                    h.is_fallback = True
                    h.fallback_reason = f"Ollama daemon unreachable ({self.base_url}): {self._last_error}"
                return hyps
            return []

        prompt = (
            f"You are an autonomous security reasoning system analyzing asset '{asset.name}' ({asset.asset_type.value}).\n"
            f"Observations:\n"
            + "\n".join([f"- {o.kind.value}: {o.title}" for o in observations])
            + "\nActive Failure Lessons to respect:\n"
            + "\n".join([f"- {l.rule_description} (penalty {l.penalty_factor})" for l in active_lessons])
            + "\nFormulate 1 to 3 distinct security investigation hypotheses. Output JSON array with fields: "
            "title, category, description, prior_probability, test_plan (list of action_type, parameters, expected_indicators, refuting_indicators)."
        )

        try:
            raw_response = await self.generate_text(prompt)
            parsed_items = self._parse_json_hypotheses(raw_response)
            if parsed_items:
                hypotheses = []
                for item in parsed_items:
                    plan = [ProbeStep(**s) for s in item.get("test_plan", [])]
                    hyp = Hypothesis(
                        target_asset_id=asset.id,
                        category=HypothesisCategory(item.get("category", "CONFIGURATION_DEFECT")),
                        title=item.get("title", "Hypothesis from Ollama"),
                        description=item.get("description", ""),
                        prior_probability=float(item.get("prior_probability", 0.5)),
                        confidence=float(item.get("prior_probability", 0.5)),
                        test_plan=plan,
                        supporting_observation_ids=[o.id for o in observations],
                        generated_by_provider="ollama",
                        generated_by_model=self.model,
                        is_fallback=False,
                    )
                    hypotheses.append(hyp)
                self.successful_calls += 1
                return hypotheses
            else:
                raise ValueError("Ollama response did not contain a valid JSON array of hypotheses.")
        except Exception as e:
            logger.warning(f"Ollama hypothesis synthesis failed ({e}), switching to fallback.")
            if self.fallback:
                self.total_fallbacks += 1
                hyps = await self.fallback.generate_hypotheses(asset, observations, active_lessons)
                for h in hyps:
                    h.is_fallback = True
                    h.fallback_reason = f"Ollama output validation error: {e}"
                return hyps
        return []

    def _parse_json_hypotheses(self, text: str) -> Optional[List[Dict[str, Any]]]:
        """Robust parser supporting raw JSON, markdown-fenced codeblocks, and JSON extraction."""
        text = text.strip()
        # Check markdown code fence
        match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                if isinstance(data, list):
                    return data
            except Exception:
                pass

        # Check raw bracket slice
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                if isinstance(data, list):
                    return data
            except Exception:
                pass

        return None

    async def diagnose_failure(
        self,
        hypothesis: Hypothesis,
        probe_output: Dict[str, Any],
    ) -> tuple[FailureCategory, str, float]:
        """Diagnose a failed probe using Ollama or fallback."""
        self.total_calls += 1

        if not await self.is_available():
            if self.fallback:
                self.total_fallbacks += 1
                return await self.fallback.diagnose_failure(hypothesis, probe_output)
            return FailureCategory.INVALID_PREMISE, "Fallback unavailable; default premise refuted.", 0.5

        prompt = (
            f"Hypothesis failed: '{hypothesis.title}' on asset {hypothesis.target_asset_id}.\n"
            f"Probe output: {json.dumps(probe_output)}\n"
            f"Diagnose failure category (ACCESS_DENIED_HARD, COUNTERMEASURE_DETECTED, INVALID_PREMISE, PROBE_TIMEOUT), "
            f"explanation, and penalty score between 0.1 and 0.8."
        )
        try:
            text = await self.generate_text(prompt)
            self.successful_calls += 1
            if "countermeasure" in text.lower() or "rate" in text.lower():
                return FailureCategory.COUNTERMEASURE_DETECTED, text[:120], 0.3
            if "denied" in text.lower() or "signature" in text.lower() or "forbidden" in text.lower():
                return FailureCategory.ACCESS_DENIED_HARD, text[:120], 0.25
            return FailureCategory.INVALID_PREMISE, text[:120], 0.5
        except Exception:
            if self.fallback:
                self.total_fallbacks += 1
                return await self.fallback.diagnose_failure(hypothesis, probe_output)
        return FailureCategory.INVALID_PREMISE, "Hypothesis refuted by negative probe evidence.", 0.5

    def get_telemetry(self) -> Dict[str, Any]:
        return {
            "configured_provider": "ollama",
            "configured_model": self.model,
            "endpoint": self.base_url,
            "is_live_available": bool(self._cached_available),
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "fallback_calls": self.total_fallbacks,
            "active_backend_used": "ollama" if (self._cached_available and self.successful_calls > 0) else "mock_fallback",
            "last_error": self._last_error,
        }
