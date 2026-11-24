"""Tests for EvidenceEngine verification and hypothesis status transitions."""

import pytest
from disstroy.evidence.engine import EvidenceEngine
from disstroy.models.asset import Asset
from disstroy.models.enums import AssetType, HypothesisCategory, HypothesisStatus
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState


@pytest.mark.asyncio
async def test_evidence_verification_and_hypothesis_validation():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    engine = EvidenceEngine(state)

    # Insert asset for foreign key constraint
    asset = Asset(id="asset_test", name="Test Asset", asset_type=AssetType.SERVICE)
    await state.add_asset(asset)

    step = ProbeStep(
        action_type="check_debug_flag",
        parameters={"path": "/debug"},
        expected_indicators=["debug=true", "200"],
        refuting_indicators=["404", "access denied"],
    )
    hyp = Hypothesis(
        id="hyp_ev_test",
        target_asset_id="asset_test",
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="Debug flag active",
        description="Verify",
        test_plan=[step],
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(hyp)

    # 1. Provide validating probe response
    probe_output = {
        "status_code": 200,
        "body": "Response payload contains debug=true for diagnostics.",
    }
    evidence, updated_hyp = await engine.evaluate_probe_result(
        hypothesis=hyp,
        step=step,
        worker_id="w_01",
        probe_output=probe_output,
    )

    assert evidence.supports_hypothesis is True
    assert evidence.validation_power == 1.0
    assert updated_hyp.status == HypothesisStatus.VALIDATED
    assert updated_hyp.confidence > 0.9

    await db.close()


@pytest.mark.asyncio
async def test_evidence_refutation():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    engine = EvidenceEngine(state)

    # Insert asset for foreign key constraint
    asset = Asset(id="asset_test", name="Test Asset", asset_type=AssetType.SERVICE)
    await state.add_asset(asset)

    step = ProbeStep(
        action_type="check_debug_flag",
        parameters={"path": "/debug"},
        expected_indicators=["debug=true"],
        refuting_indicators=["404", "not found"],
    )
    hyp = Hypothesis(
        id="hyp_ev_refute",
        target_asset_id="asset_test",
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="Debug route check",
        description="Verify",
        test_plan=[step],
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(hyp)

    # Provide refuting response
    probe_output = {
        "status_code": 404,
        "body": "Route not found on host.",
    }
    evidence, updated_hyp = await engine.evaluate_probe_result(
        hypothesis=hyp,
        step=step,
        worker_id="w_01",
        probe_output=probe_output,
    )

    assert evidence.supports_hypothesis is False
    assert evidence.falsification_power == 1.0
    assert updated_hyp.status == HypothesisStatus.REFUTED

    await db.close()
