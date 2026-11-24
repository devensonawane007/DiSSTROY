"""AttackPathEvaluator module for multi-stage graph reasoning and path evaluation.

Distinguishes theoretical graph connectivity from feasible and verified attack trajectories.
Calculates path confidence, uncertainty, required access levels, and dependency satisfaction.
"""

import math
from typing import Any, Dict, List, Optional, Set, Tuple

from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.models.enums import AccessLevel, HypothesisStatus, PathRisk, PathStatus
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.path import AttackPath
from disstroy.models.asset import Asset
from disstroy.state.shared_state import SharedState


ACCESS_LEVEL_RANKS: Dict[AccessLevel, int] = {
    AccessLevel.NONE: 0,
    AccessLevel.PUBLIC: 1,
    AccessLevel.INTERNAL_NETWORK: 2,
    AccessLevel.AUTHENTICATED_USER: 3,
    AccessLevel.ADMIN_PRIVILEGE: 4,
    AccessLevel.DATABASE_ROOT: 5,
}


def get_access_rank(level: Any) -> int:
    """Return numeric privilege tier for an AccessLevel."""
    if isinstance(level, AccessLevel):
        return ACCESS_LEVEL_RANKS.get(level, 0)
    try:
        return ACCESS_LEVEL_RANKS.get(AccessLevel(level), 0)
    except Exception:
        return 0


class AttackPathEvaluator:
    """Evaluates multi-stage attack paths against real graph state and evidence."""

    def __init__(self, graph: KnowledgeGraph, state: SharedState):
        self.graph = graph
        self.state = state

    async def evaluate_path(self, path: AttackPath) -> AttackPath:
        """Evaluate a candidate path's feasibility, confidence, uncertainty, and status."""
        # 1. Cycle Detection
        has_asset_dupes = len(path.asset_sequence) > len(set(path.asset_sequence))
        graph_cycles = self.graph.detect_cycles()
        hyp_set = set(path.hypothesis_sequence)
        in_graph_cycle = any(hyp_set.issubset(set(c)) for c in graph_cycles) if graph_cycles else False
        is_cycle = has_asset_dupes or in_graph_cycle
        path.is_cycle_detected = is_cycle

        # 2. Fetch Assets along the path
        source_asset = await self.state.get_asset(path.source_asset_id)
        target_asset = await self.state.get_asset(path.target_asset_id)

        if target_asset and target_asset.is_canary_objective:
            path.canary_target = target_asset.canary_description or f"CANARY_{target_asset.id}"

        # Calculate initial simulated access level on source asset
        current_access_rank = get_access_rank(source_asset.current_access_level if source_asset else AccessLevel.PUBLIC)

        # 3. Fetch Hypotheses in sequence
        hypotheses: List[Hypothesis] = []
        for hid in path.hypothesis_sequence:
            h = await self.state.get_hypothesis(hid)
            if h:
                hypotheses.append(h)

        if not hypotheses:
            path.path_status = PathStatus.THEORETICAL
            path.path_confidence = 0.1
            path.path_uncertainty = 1.0
            return path

        total_steps = len(hypotheses)
        validated_steps = 0
        blocked_step_id: Optional[str] = None
        unresolved_prereqs_count = 0
        step_confidences: List[float] = []
        next_step_is_feasible = False
        reached_first_unvalidated = False

        invalidated_branches = self.graph.get_invalidated_branches()

        for idx, h in enumerate(hypotheses):
            step_confidences.append(h.confidence)

            # Check if hypothesis itself is refuted or in an invalidated branch
            if h.id in invalidated_branches or h.status in (HypothesisStatus.REFUTED, HypothesisStatus.ABANDONED):
                if blocked_step_id is None:
                    blocked_step_id = h.id

            # Check prerequisites
            prereq_ids = h.prerequisite_hypothesis_ids or self.graph.get_prerequisite_hypotheses(h.id)
            step_prereqs_validated = True

            for pid in prereq_ids:
                prereq_h = await self.state.get_hypothesis(pid)
                if prereq_h:
                    if prereq_h.status in (HypothesisStatus.REFUTED, HypothesisStatus.ABANDONED):
                        if blocked_step_id is None:
                            blocked_step_id = h.id
                        step_prereqs_validated = False
                    elif prereq_h.status != HypothesisStatus.VALIDATED:
                        unresolved_prereqs_count += 1
                        step_prereqs_validated = False
                else:
                    unresolved_prereqs_count += 1
                    step_prereqs_validated = False

            # Check required access level
            req_rank = get_access_rank(h.required_access_level)
            access_satisfied = current_access_rank >= req_rank

            if h.status == HypothesisStatus.VALIDATED:
                validated_steps += 1
                if h.enables_access_level:
                    enabled_rank = get_access_rank(h.enables_access_level)
                    current_access_rank = max(current_access_rank, enabled_rank)
            else:
                if not reached_first_unvalidated:
                    reached_first_unvalidated = True
                    # If this first unvalidated step has all prerequisites met and access level met, it is feasible!
                    if step_prereqs_validated and access_satisfied and blocked_step_id is None:
                        next_step_is_feasible = True

        path.blocked_step_id = blocked_step_id

        # 4. Status determination
        if blocked_step_id is not None or is_cycle:
            path.path_status = PathStatus.BLOCKED
            path.path_confidence = 0.0
            path.path_uncertainty = 1.0
        elif validated_steps == total_steps and total_steps > 0:
            # Complete chain is proven with evidence
            path.path_status = PathStatus.VERIFIED
            # High aggregate confidence for verified path
            base_conf = 1.0
            for sc in step_confidences:
                base_conf *= max(0.9, sc)
            path.path_confidence = round(min(1.0, base_conf), 3)
            path.path_uncertainty = 0.0
        elif next_step_is_feasible:
            # Actionable now because all prerequisites up to this step are met
            path.path_status = PathStatus.FEASIBLE
            # Product of step confidences
            prod_conf = 1.0
            for sc in step_confidences:
                prod_conf *= max(0.2, sc)
            path.path_confidence = round(min(0.85, prod_conf), 3)
            path.path_uncertainty = round(1.0 - (validated_steps / total_steps), 3)
        else:
            # Prerequisites missing further upstream or access level not yet attained
            path.path_status = PathStatus.THEORETICAL
            prod_conf = 1.0
            for sc in step_confidences:
                prod_conf *= max(0.1, sc)
            path.path_confidence = round(min(0.5, prod_conf * 0.7), 3)
            path.path_uncertainty = round(1.0 - (validated_steps / total_steps), 3)

        # 5. Risk Assessment
        is_canary = (target_asset and target_asset.is_canary_objective) or (path.canary_target is not None)
        crit = target_asset.criticality if target_asset else 0.5

        if path.path_status == PathStatus.BLOCKED:
            path.risk_level = PathRisk.LOW
        elif is_canary:
            if path.path_status == PathStatus.VERIFIED:
                path.risk_level = PathRisk.CRITICAL
            elif path.path_status == PathStatus.FEASIBLE:
                path.risk_level = PathRisk.CRITICAL
            else:
                path.risk_level = PathRisk.HIGH
        elif crit >= 0.8:
            path.risk_level = PathRisk.HIGH if path.path_status in (PathStatus.VERIFIED, PathStatus.FEASIBLE) else PathRisk.MEDIUM
        elif crit >= 0.5:
            path.risk_level = PathRisk.MEDIUM
        else:
            path.risk_level = PathRisk.LOW

        path.description = (
            f"Path status: {path.path_status.value} ({validated_steps}/{total_steps} steps validated). "
            f"Confidence: {path.path_confidence:.2f}, Uncertainty: {path.path_uncertainty:.2f}. "
            f"Canary Target: {path.canary_target or 'None'}."
        )

        return path

    async def discover_candidate_paths(self) -> List[AttackPath]:
        """
        Discover candidate multi-stage attack paths by traversing asset links from entrypoints to critical targets.
        Does NOT mark discovered paths as feasible or verified. Newly discovered paths start as THEORETICAL.
        """
        assets = await self.state.list_assets()
        if not assets:
            return []

        # Identify perimeter assets (Gateways or Hosts with public access)
        entrypoints = [
            a for a in assets
            if a.current_access_level == AccessLevel.PUBLIC
            or a.asset_type.value in ("API_GATEWAY", "ENDPOINT", "HOST")
        ]
        if not entrypoints:
            entrypoints = assets[:1]

        # Identify objectives (Canary targets or critical assets)
        objectives = [a for a in assets if a.is_canary_objective or a.criticality >= 0.8]
        if not objectives:
            objectives = [a for a in assets if a.id != entrypoints[0].id]

        discovered_paths: List[AttackPath] = []
        all_hypotheses = await self.state.list_hypotheses()

        # Map hypotheses by target asset
        hyp_by_asset: Dict[str, List[Hypothesis]] = {}
        for h in all_hypotheses:
            hyp_by_asset.setdefault(h.target_asset_id, []).append(h)

        for src in entrypoints:
            for dst in objectives:
                if src.id == dst.id:
                    continue
                asset_paths = self.graph.find_paths_between_assets(src.id, dst.id)
                for a_seq in asset_paths:
                    # Construct hypothesis sequence matching asset progression
                    h_seq: List[str] = []
                    for aid in a_seq:
                        asset_hyps = hyp_by_asset.get(aid, [])
                        if asset_hyps:
                            # Pick primary hypothesis for this asset stage
                            h_seq.append(asset_hyps[0].id)

                    if h_seq:
                        path_id = f"path_{src.id}_{dst.id}"
                        path = AttackPath(
                            path_id=path_id,
                            name=f"{src.name} --> {dst.name}",
                            source_asset_id=src.id,
                            target_asset_id=dst.id,
                            asset_sequence=a_seq,
                            hypothesis_sequence=h_seq,
                            path_status=PathStatus.THEORETICAL,
                            canary_target=dst.canary_description if dst.is_canary_objective else None,
                        )
                        evaluated_path = await self.evaluate_path(path)
                        discovered_paths.append(evaluated_path)
                        await self.state.add_attack_path(evaluated_path)

        return discovered_paths

    async def recalculate_all_paths(self) -> List[AttackPath]:
        """Re-evaluate all existing attack paths against latest evidence and graph state."""
        existing_paths = await self.state.list_attack_paths()
        updated_paths: List[AttackPath] = []
        for p in existing_paths:
            updated = await self.evaluate_path(p)
            await self.state.add_attack_path(updated)
            updated_paths.append(updated)
        return self.compare_paths(updated_paths)

    def compare_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """
        Rank attack paths based on verification status, confidence, uncertainty, and threat risk.
        Ranking priority: VERIFIED > FEASIBLE > THEORETICAL > BLOCKED.
        """
        status_weights = {
            PathStatus.VERIFIED: 4,
            PathStatus.FEASIBLE: 3,
            PathStatus.THEORETICAL: 2,
            PathStatus.BLOCKED: 1,
        }
        risk_weights = {
            PathRisk.CRITICAL: 4,
            PathRisk.HIGH: 3,
            PathRisk.MEDIUM: 2,
            PathRisk.LOW: 1,
        }

        def sort_key(p: AttackPath):
            s_weight = status_weights.get(p.path_status, 0)
            r_weight = risk_weights.get(p.risk_level, 0)
            # Higher status weight, higher confidence, lower uncertainty, higher risk
            return (s_weight, p.path_confidence, -p.path_uncertainty, r_weight)

        return sorted(paths, key=sort_key, reverse=True)
