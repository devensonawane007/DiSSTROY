"""Hypothesis Engine generating, deduplicating, and managing competing security hypotheses."""

import logging
from typing import List, Optional
from disstroy.hypothesis.prioritizer import DynamicHypothesisPrioritizer
from disstroy.llm.base import BaseLLMProvider
from disstroy.models.enums import HypothesisStatus
from disstroy.models.hypothesis import Hypothesis
from disstroy.state.shared_state import SharedState

logger = logging.getLogger(__name__)


class HypothesisEngine:
    """Orchestrates generation of competing hypotheses and their dynamic reprioritization."""

    def __init__(
        self,
        shared_state: SharedState,
        llm_provider: BaseLLMProvider,
        prioritizer: DynamicHypothesisPrioritizer,
    ):
        self.state = shared_state
        self.llm = llm_provider
        self.prioritizer = prioritizer

    async def generate_hypotheses_for_asset(self, asset_id: str) -> List[Hypothesis]:
        """Synthesize competing hypotheses for a specific asset using observations and failure lessons."""
        asset = await self.state.get_asset(asset_id)
        if not asset:
            logger.warning(f"Cannot generate hypotheses: asset {asset_id} not found.")
            return []

        observations = await self.state.list_observations(asset_id)
        active_lessons = await self.state.list_lessons(active_only=True)

        generated = await self.llm.generate_hypotheses(asset, observations, active_lessons)

        # Prioritize and save
        stored_hypotheses: List[Hypothesis] = []
        for hyp in generated:
            hyp.priority_score = await self.prioritizer.calculate_priority(hyp, asset)
            await self.state.add_hypothesis(hyp)
            stored_hypotheses.append(hyp)

        return stored_hypotheses

    async def reprioritize_all_open_hypotheses(self) -> List[Hypothesis]:
        """Recalculate dynamic priority scores for all open hypotheses based on new evidence or lessons."""
        proposed = await self.state.list_hypotheses(status=HypothesisStatus.PROPOSED)
        queued = await self.state.list_hypotheses(status=HypothesisStatus.QUEUED)
        open_hypotheses = proposed + queued

        if not open_hypotheses:
            return []

        reprioritized = await self.prioritizer.reprioritize_list(open_hypotheses)
        for hyp in reprioritized:
            await self.state.update_hypothesis(hyp)

        return reprioritized
