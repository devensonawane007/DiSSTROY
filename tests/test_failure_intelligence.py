"""Tests for FailureIntelligenceEngine and adaptive penalty policies."""

import pytest
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.asset import Asset
from disstroy.models.enums import AssetType, FailureCategory, HypothesisCategory
from disstroy.models.hypothesis import Hypothesis
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState


@pytest.mark.asyncio
async def test_failure_classification_and_penalties():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    intel = FailureIntelligenceEngine(state)

    asset = Asset(id="asset_auth", name="Auth Service", asset_type=AssetType.AUTH_PROVIDER)
    await state.add_asset(asset)

    hyp = Hypothesis(
        id="hyp_auth_test",
        target_asset_id="asset_auth",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Unsigned JWT accepted",
        description="Premise",
    )
    await state.add_hypothesis(hyp)

    # 1. Simulate hard denial
    probe_output = {
        "status_code": 401,
        "body": "Signature verification failed: invalid key.",
    }
    failure_record = await intel.diagnose_and_learn(
        hypothesis=hyp,
        worker_id="worker_01",
        probe_output=probe_output,
    )

    assert failure_record.failure_category == FailureCategory.ACCESS_DENIED_HARD
    failures = await state.list_failures()
    assert len(failures) == 1

    lessons = await state.list_lessons()
    assert len(lessons) == 1
    assert lessons[0].penalty_factor == 0.25

    # 2. Verify penalty multiplier applies to matching hypothesis
    multiplier = await intel.compute_penalty_multiplier(hyp)
    assert multiplier == 0.25

    # 3. Verify non-matching hypothesis is unaffected
    other_hyp = Hypothesis(
        id="hyp_other",
        target_asset_id="asset_different",
        category=HypothesisCategory.INFORMATION_DISCLOSURE,
        title="Info disclosure",
        description="Premise",
    )
    unaffected_multiplier = await intel.compute_penalty_multiplier(other_hyp)
    assert unaffected_multiplier == 1.0

    await db.close()
