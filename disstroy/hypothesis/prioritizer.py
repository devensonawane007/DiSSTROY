"""Dynamic hypothesis prioritizer incorporating asset criticality, observation density, and failure penalties."""

from typing import List
from disstroy.config import DiSSTROYConfig
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.asset import Asset
from disstroy.models.hypothesis import Hypothesis
from disstroy.state.shared_state import SharedState


class DynamicHypothesisPrioritizer:
    """Calculates adaptive priority scores for hypothesis scheduling."""

    def __init__(
        self,
        shared_state: SharedState,
        failure_intelligence: FailureIntelligenceEngine,
        config: DiSSTROYConfig,
    ):
        self.state = shared_state
        self.failure_intel = failure_intelligence
        self.w_crit = config.criticality_weight
        self.w_conf = config.confidence_weight
        self.w_density = config.observation_density_weight

    async def calculate_priority(self, hypothesis: Hypothesis, asset: Asset) -> float:
        """Compute holistic priority combining asset importance, confidence, observation density, and failure penalties."""
        # 1. Base Score
        crit = asset.criticality
        conf = hypothesis.confidence
        density = min(1.0, len(hypothesis.supporting_observation_ids) / 3.0)

        base_score = (self.w_crit * crit) + (self.w_conf * conf) + (self.w_density * density)

        # 2. Penalty Multiplier from Failure Intelligence
        penalty_multiplier = await self.failure_intel.compute_penalty_multiplier(hypothesis)

        final_priority = base_score * penalty_multiplier
        return round(max(0.01, min(1.0, final_priority)), 4)

    async def reprioritize_list(self, hypotheses: List[Hypothesis]) -> List[Hypothesis]:
        """Recalculate priorities across a set of hypotheses and return sorted descending."""
        assets = {a.id: a for a in await self.state.list_assets()}

        for hyp in hypotheses:
            asset = assets.get(hyp.target_asset_id)
            if asset:
                hyp.priority_score = await self.calculate_priority(hyp, asset)

        hypotheses.sort(key=lambda h: h.priority_score, reverse=True)
        return hypotheses
