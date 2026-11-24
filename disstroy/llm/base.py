"""Abstract base interface for replaceable LLM providers."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from disstroy.models.asset import Asset
from disstroy.models.enums import FailureCategory
from disstroy.models.failure import FailureLesson
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.observation import Observation


class BaseLLMProvider(ABC):
    """Base interface for autonomous reasoning and hypothesis synthesis providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider backend."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the model in use."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if provider backend is reachable and healthy."""
        pass

    @abstractmethod
    async def generate_text(self, prompt: str, system: Optional[str] = None) -> str:
        """Raw completion or generation call."""
        pass

    @abstractmethod
    async def generate_hypotheses(
        self,
        asset: Asset,
        observations: List[Observation],
        active_lessons: List[FailureLesson],
    ) -> List[Hypothesis]:
        """Synthesize competing hypotheses with test plans given observations and active failure lessons."""
        pass

    @abstractmethod
    async def diagnose_failure(
        self,
        hypothesis: Hypothesis,
        probe_output: Dict[str, Any],
    ) -> tuple[FailureCategory, str, float]:
        """Diagnose a failed probe attempt and recommend penalty multiplier."""
        pass

    @abstractmethod
    def get_telemetry(self) -> Dict[str, Any]:
        """Export provider call counts, fallback counts, and health status."""
        pass
