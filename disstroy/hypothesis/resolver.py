"""HypothesisDependencyResolver: Unified prerequisite tracking, cycle detection, and unlocking."""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from disstroy.models.enums import HypothesisStatus, PathStatus
from disstroy.models.hypothesis import Hypothesis
from disstroy.state.shared_state import SharedState
from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.graph.path_evaluator import AttackPathEvaluator
from disstroy.hypothesis.prioritizer import DynamicHypothesisPrioritizer

logger = logging.getLogger(__name__)


class DependencyResolutionResult(BaseModel):
    """Structured evaluation of hypothesis prerequisite status and eligibility."""

    hypothesis_id: str
    is_eligible: bool = Field(description="True if all prerequisites are VALIDATED and ready for testing")
    is_blocked: bool = Field(description="True if prerequisites are unresolved, refuted, missing, or circular")
    is_permanently_blocked: bool = Field(default=False, description="True if any prerequisite is permanently REFUTED")
    missing_prerequisites: List[str] = Field(default_factory=list)
    unresolved_prerequisites: List[str] = Field(default_factory=list)
    refuted_prerequisites: List[str] = Field(default_factory=list)
    validated_prerequisites: List[str] = Field(default_factory=list)
    is_cycle_detected: bool = Field(default=False)
    blocking_reason: Optional[str] = Field(default=None)


class HypothesisDependencyResolver:
    """Manages prerequisite dependency evaluation, eligibility gates, and automatic unlocking."""

    def __init__(
        self,
        shared_state: SharedState,
        knowledge_graph: Optional[KnowledgeGraph] = None,
        prioritizer: Optional[DynamicHypothesisPrioritizer] = None,
        path_evaluator: Optional[AttackPathEvaluator] = None,
    ):
        self.state = shared_state
        self.graph = knowledge_graph
        self.prioritizer = prioritizer
        self.path_evaluator = path_evaluator

    def detect_cycle(
        self,
        hypothesis_id: str,
        prerequisite_map: Dict[str, List[str]],
        visited: Optional[Set[str]] = None,
        rec_stack: Optional[Set[str]] = None,
    ) -> bool:
        """Detect circular dependencies via depth-first search on prerequisite mapping."""
        if visited is None:
            visited = set()
        if rec_stack is None:
            rec_stack = set()

        visited.add(hypothesis_id)
        rec_stack.add(hypothesis_id)

        for prereq_id in prerequisite_map.get(hypothesis_id, []):
            if prereq_id not in visited:
                if self.detect_cycle(prereq_id, prerequisite_map, visited, rec_stack):
                    return True
            elif prereq_id in rec_stack:
                return True

        rec_stack.remove(hypothesis_id)
        return False

    async def resolve_dependencies(self, hypothesis: Hypothesis) -> DependencyResolutionResult:
        """
        Evaluate prerequisite state for a hypothesis.
        Distinguishes between prerequisite existence and actual validation.
        """
        prereqs = list(hypothesis.prerequisite_hypothesis_ids or [])

        # 1. No prerequisites: immediately eligible
        if not prereqs:
            return DependencyResolutionResult(
                hypothesis_id=hypothesis.id,
                is_eligible=True,
                is_blocked=False,
                is_permanently_blocked=False,
            )

        # 2. Check for circular dependencies
        all_hyps = await self.state.list_hypotheses()
        prereq_map = {h.id: list(h.prerequisite_hypothesis_ids or []) for h in all_hyps}
        prereq_map[hypothesis.id] = prereqs

        if self.detect_cycle(hypothesis.id, prereq_map):
            return DependencyResolutionResult(
                hypothesis_id=hypothesis.id,
                is_eligible=False,
                is_blocked=True,
                is_permanently_blocked=False,
                is_cycle_detected=True,
                blocking_reason=f"Blocked by circular prerequisite dependency involving hypothesis {hypothesis.id}",
            )

        # 3. Check individual prerequisite statuses in shared state
        missing: List[str] = []
        unresolved: List[str] = []
        refuted: List[str] = []
        validated: List[str] = []

        for pid in prereqs:
            prereq_h = await self.state.get_hypothesis(pid)
            if prereq_h is None:
                missing.append(pid)
            elif prereq_h.status == HypothesisStatus.VALIDATED:
                validated.append(pid)
            elif prereq_h.status in (HypothesisStatus.REFUTED, HypothesisStatus.ABANDONED):
                refuted.append(pid)
            else:
                # Still in PROPOSED, QUEUED, TESTING, PENDING
                unresolved.append(pid)

        is_permanently_blocked = len(refuted) > 0
        is_blocked = bool(missing or unresolved or refuted)
        is_eligible = not is_blocked

        blocking_reason: Optional[str] = None
        if refuted:
            blocking_reason = f"Permanently blocked by refuted prerequisite(s): {', '.join(refuted)}"
        elif missing:
            blocking_reason = f"Blocked by missing prerequisite(s): {', '.join(missing)}"
        elif unresolved:
            blocking_reason = f"Blocked by unresolved prerequisite(s): {', '.join(unresolved)}"

        return DependencyResolutionResult(
            hypothesis_id=hypothesis.id,
            is_eligible=is_eligible,
            is_blocked=is_blocked,
            is_permanently_blocked=is_permanently_blocked,
            missing_prerequisites=missing,
            unresolved_prerequisites=unresolved,
            refuted_prerequisites=refuted,
            validated_prerequisites=validated,
            is_cycle_detected=False,
            blocking_reason=blocking_reason,
        )

    async def update_hypothesis_dependency_state(self, hypothesis: Hypothesis) -> DependencyResolutionResult:
        """
        Evaluate dependencies, update hypothesis lifecycle status, and record diagnosis in state metadata.
        Guarantees that blocked hypotheses do not disappear and their blocking reason is transparently recorded.
        """
        result = await self.resolve_dependencies(hypothesis)
        hypothesis.metadata["dependency_resolution"] = result.model_dump()

        if result.is_blocked:
            hypothesis.metadata["is_blocked"] = True
            hypothesis.metadata["blocking_reason"] = result.blocking_reason
            if result.is_permanently_blocked:
                # Cannot proceed because foundation is refuted
                hypothesis.status = HypothesisStatus.ABANDONED
            else:
                # Waiting on prerequisites to resolve
                hypothesis.status = HypothesisStatus.PENDING
        else:
            hypothesis.metadata["is_blocked"] = False
            hypothesis.metadata.pop("blocking_reason", None)
            if hypothesis.status == HypothesisStatus.PENDING:
                # Promoted to eligible
                hypothesis.status = HypothesisStatus.PROPOSED

        await self.state.update_hypothesis(hypothesis)
        return result

    async def is_eligible_for_dispatch(self, hypothesis: Hypothesis) -> bool:
        """Determine whether a hypothesis is currently eligible to be dispatched to a worker."""
        if hypothesis.status == HypothesisStatus.PENDING:
            return False
        if hypothesis.metadata.get("is_blocked"):
            return False
        resolution = await self.resolve_dependencies(hypothesis)
        return resolution.is_eligible

    async def evaluate_and_unlock_dependent_hypotheses(self, validated_hyp_id: str) -> List[Hypothesis]:
        """
        Called when a prerequisite hypothesis validates.
        Identifies dependent hypotheses, promotes eligible ones to PROPOSED, recalculates priorities,
        and triggers AttackPath reevaluation.
        """
        all_hyps = await self.state.list_hypotheses()
        unlocked: List[Hypothesis] = []

        for h in all_hyps:
            prereqs = h.prerequisite_hypothesis_ids or []
            if validated_hyp_id in prereqs:
                previous_status = h.status
                res = await self.update_hypothesis_dependency_state(h)
                if res.is_eligible and previous_status == HypothesisStatus.PENDING:
                    # Recalculate priority if prioritizer is configured
                    if self.prioritizer:
                        asset = await self.state.get_asset(h.target_asset_id)
                        if asset:
                            new_priority = await self.prioritizer.calculate_priority(h, asset)
                            # Boost priority for newly unlocked actionable hypothesis
                            h.priority_score = round(min(1.0, max(new_priority, 0.75)), 4)
                            await self.state.update_hypothesis(h)
                    unlocked.append(h)
                    logger.info("Hypothesis %s unlocked by validated prerequisite %s.", h.id, validated_hyp_id)

        # Trigger reevaluation of all attack paths
        if self.path_evaluator:
            await self.path_evaluator.recalculate_all_paths()

        return unlocked

    async def evaluate_and_block_dependent_hypotheses(self, refuted_hyp_id: str) -> List[Hypothesis]:
        """
        Called when a prerequisite hypothesis is permanently refuted.
        Blocks and penalizes all downstream hypotheses and updates attack paths.
        """
        all_hyps = await self.state.list_hypotheses()
        blocked: List[Hypothesis] = []

        for h in all_hyps:
            prereqs = h.prerequisite_hypothesis_ids or []
            if refuted_hyp_id in prereqs:
                res = await self.update_hypothesis_dependency_state(h)
                blocked.append(h)
                logger.info("Hypothesis %s blocked by refuted prerequisite %s.", h.id, refuted_hyp_id)

        # Re-evaluate all attack paths
        if self.path_evaluator:
            await self.path_evaluator.recalculate_all_paths()

        return blocked
