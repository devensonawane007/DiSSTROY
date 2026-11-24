"""Tests for SwarmManager concurrent task execution and cancellation."""

import pytest
from disstroy.config import DiSSTROYConfig
from disstroy.evidence.engine import EvidenceEngine
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.enums import HypothesisCategory, HypothesisStatus
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.simulator.environment import SimulatedSecurityEnvironment
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState
from disstroy.swarm.manager import SwarmManager


@pytest.mark.asyncio
async def test_swarm_concurrency_and_execution():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    config = DiSSTROYConfig(max_concurrent_workers=2)
    evidence_engine = EvidenceEngine(state)
    failure_intel = FailureIntelligenceEngine(state)
    simulator = SimulatedSecurityEnvironment()

    for asset in simulator.assets.values():
        await state.add_asset(asset)

    swarm = SwarmManager(
        shared_state=state,
        evidence_engine=evidence_engine,
        failure_intelligence=failure_intel,
        simulator=simulator,
        config=config,
    )

    step = ProbeStep(
        action_type="check_debug_route",
        parameters={"target_asset_id": "asset_api_gw", "path": "/debug/vars"},
        expected_indicators=["upstreams", "200"],
    )
    hyp1 = Hypothesis(
        id="hyp_swarm_1",
        target_asset_id="asset_api_gw",
        category=HypothesisCategory.INFORMATION_DISCLOSURE,
        title="Debug route open",
        description="Verify",
        test_plan=[step],
        status=HypothesisStatus.PROPOSED,
    )
    hyp2 = Hypothesis(
        id="hyp_swarm_2",
        target_asset_id="asset_api_gw",
        category=HypothesisCategory.INFORMATION_DISCLOSURE,
        title="Debug route open 2",
        description="Verify",
        test_plan=[step],
        status=HypothesisStatus.PROPOSED,
    )

    await state.add_hypothesis(hyp1)
    await state.add_hypothesis(hyp2)

    # Dispatch tasks
    t1 = swarm.dispatch_hypothesis(hyp1)
    t2 = swarm.dispatch_hypothesis(hyp2)
    assert t1 is not None
    assert t2 is not None
    assert swarm.has_available_capacity() is False

    # Wait for completion
    results = await swarm.wait_for_any_completed()
    assert len(results) >= 1
    assert swarm.has_available_capacity() is True

    await swarm.stop_all()
    await db.close()
