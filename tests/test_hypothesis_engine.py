"""Tests for HypothesisEngine and DynamicHypothesisPrioritizer."""

import pytest
from disstroy.config import DiSSTROYConfig
from disstroy.hypothesis.engine import HypothesisEngine
from disstroy.hypothesis.prioritizer import DynamicHypothesisPrioritizer
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.llm.mock import MockLLMProvider
from disstroy.models.asset import Asset
from disstroy.models.enums import AssetType, HypothesisStatus, ObservationKind
from disstroy.models.observation import Observation
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState


@pytest.mark.asyncio
async def test_hypothesis_generation_and_reprioritization():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    config = DiSSTROYConfig()
    intel = FailureIntelligenceEngine(state)
    prioritizer = DynamicHypothesisPrioritizer(state, intel, config)
    llm = MockLLMProvider()
    engine = HypothesisEngine(state, llm, prioritizer)

    asset = Asset(id="asset_api_gw", name="API Gateway", asset_type=AssetType.API_GATEWAY, criticality=0.8)
    await state.add_asset(asset)

    obs = Observation(
        id="obs_gw_debug",
        asset_id="asset_api_gw",
        kind=ObservationKind.HTTP_HEADER,
        title="Gateway exposes upstream debug route",
        confidence=0.9,
    )
    await state.add_observation(obs)

    # Generate hypotheses
    hyps = await engine.generate_hypotheses_for_asset("asset_api_gw")
    assert len(hyps) >= 1
    assert hyps[0].target_asset_id == "asset_api_gw"
    assert hyps[0].priority_score > 0.0

    # Reprioritize
    reprioritized = await engine.reprioritize_all_open_hypotheses()
    assert len(reprioritized) >= 1

    await db.close()
