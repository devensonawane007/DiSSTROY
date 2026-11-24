"""Tests for SQLite persistence and SharedState reactive operations."""

import pytest
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState
from disstroy.models.asset import Asset
from disstroy.models.observation import Observation
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.evidence import EvidenceRecord
from disstroy.models.failure import FailureRecord, FailureLesson
from disstroy.models.enums import AssetType, ObservationKind, HypothesisCategory, HypothesisStatus, EvidenceType, FailureCategory


@pytest.mark.asyncio
async def test_shared_state_lifecycle():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)

    events = []
    async def listener(event):
        events.append(event.event_type)

    state.subscribe(listener)

    # 1. Add Asset
    asset = Asset(id="srv_api", name="API Gateway", asset_type=AssetType.API_GATEWAY, criticality=0.9)
    await state.add_asset(asset)

    fetched_asset = await state.get_asset("srv_api")
    assert fetched_asset is not None
    assert fetched_asset.name == "API Gateway"
    assert fetched_asset.criticality == 0.9

    # 2. Add Observation
    obs = Observation(
        id="obs_header",
        asset_id="srv_api",
        kind=ObservationKind.HTTP_HEADER,
        title="Server exposes Werkzeug Debug flag",
        raw_payload={"X-Debug": "1", "Server": "Werkzeug/2.2.2"},
        confidence=0.95
    )
    await state.add_observation(obs)

    observations = await state.list_observations("srv_api")
    assert len(observations) == 1
    assert observations[0].title == "Server exposes Werkzeug Debug flag"

    # 3. Add Hypothesis
    step = ProbeStep(action_type="check_debug_route", parameters={"path": "/console"})
    hyp = Hypothesis(
        id="hyp_debug_eval",
        target_asset_id="srv_api",
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="Interactive debug console is accessible without authentication",
        description="Verify whether Werkzeug console PIN bypass is possible",
        test_plan=[step],
        status=HypothesisStatus.PROPOSED,
        priority_score=0.85
    )
    await state.add_hypothesis(hyp)

    hyp_list = await state.list_hypotheses()
    assert len(hyp_list) == 1
    assert hyp_list[0].id == "hyp_debug_eval"
    assert len(hyp_list[0].test_plan) == 1

    # 4. Add Evidence
    ev = EvidenceRecord(
        hypothesis_id="hyp_debug_eval",
        worker_id="worker_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data={"status_code": 200, "body_snippet": "Werkzeug powered console"},
        supports_hypothesis=True,
        validation_power=0.9
    )
    await state.add_evidence(ev)

    evidence_list = await state.list_evidence("hyp_debug_eval")
    assert len(evidence_list) == 1
    assert evidence_list[0].supports_hypothesis is True
    assert evidence_list[0].content_hash != ""

    # 5. Add Failure & Lesson
    fail = FailureRecord(
        hypothesis_id="hyp_debug_eval",
        worker_id="worker_01",
        failure_category=FailureCategory.ACCESS_DENIED_HARD,
        error_message="Console is locked behind mutual TLS",
        diagnostic_details={"tls_status": "require_client_cert"}
    )
    await state.add_failure(fail)

    lesson = FailureLesson(
        source_failure_id=fail.id,
        target_asset_id="srv_api",
        affected_category=HypothesisCategory.CONFIGURATION_DEFECT,
        penalty_factor=0.3,
        rule_description="Mutual TLS protects internal debug interfaces on srv_api"
    )
    await state.add_lesson(lesson)

    lessons = await state.list_lessons()
    assert len(lessons) == 1
    assert lessons[0].penalty_factor == 0.3

    # Verify event notifications and history
    assert "ASSET_ADDED" in events
    assert "OBSERVATION_ADDED" in events
    assert "HYPOTHESIS_ADDED" in events
    assert "EVIDENCE_ADDED" in events
    assert "FAILURE_RECORDED" in events
    assert "LESSON_LEARNED" in events

    history = await state.list_history()
    assert len(history) == 6

    await db.close()


@pytest.mark.asyncio
async def test_attack_path_and_restart_persistence(tmp_path):
    db_file = tmp_path / "test_persistence.db"
    db = DatabaseManager(db_file)
    await db.initialize()
    state = SharedState(db)

    # 1. Insert Asset with canary objective and access level
    from disstroy.models.enums import AccessLevel, PathRisk, PathStatus
    from disstroy.models.path import AttackPath

    asset_gw = Asset(
        id="asset_gw",
        name="Public Gateway",
        asset_type=AssetType.API_GATEWAY,
        criticality=0.6,
        current_access_level=AccessLevel.PUBLIC,
    )
    asset_db = Asset(
        id="asset_db",
        name="Database Vault",
        asset_type=AssetType.DATABASE,
        criticality=1.0,
        current_access_level=AccessLevel.NONE,
        is_canary_objective=True,
        canary_description="CANARY{VAULT_ROOT_PII}",
    )
    await state.add_asset(asset_gw)
    await state.add_asset(asset_db)

    # 2. Insert Hypotheses with prerequisites and access level changes
    hyp1 = Hypothesis(
        id="hyp_bypass_gw",
        target_asset_id="asset_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Bypass gateway auth",
        description="Exploit weak token signature",
        required_access_level=AccessLevel.PUBLIC,
        enables_access_level=AccessLevel.AUTHENTICATED_USER,
        stage=1,
        priority_score=0.9,
    )
    hyp2 = Hypothesis(
        id="hyp_dump_vault",
        target_asset_id="asset_db",
        category=HypothesisCategory.UNRESTRICTED_ACCESS,
        title="Dump canary vault",
        description="Use leaked authenticated token to read DB",
        prerequisite_hypothesis_ids=["hyp_bypass_gw"],
        required_access_level=AccessLevel.AUTHENTICATED_USER,
        enables_access_level=AccessLevel.DATABASE_ROOT,
        stage=2,
        priority_score=0.95,
        status=HypothesisStatus.PENDING,
    )
    await state.add_hypothesis(hyp1)
    await state.add_hypothesis(hyp2)

    # 3. Insert AttackPath
    path = AttackPath(
        path_id="path_canary_01",
        name="Gateway to Canary Vault",
        source_asset_id="asset_gw",
        target_asset_id="asset_db",
        asset_sequence=["asset_gw", "asset_db"],
        hypothesis_sequence=["hyp_bypass_gw", "hyp_dump_vault"],
        path_status=PathStatus.FEASIBLE,
        path_confidence=0.76,
        path_uncertainty=0.24,
        risk_level=PathRisk.CRITICAL,
        is_cycle_detected=False,
        canary_target="CANARY{VAULT_ROOT_PII}",
        description="Multi-hop pivot from public gateway to canary vault",
    )
    await state.add_attack_path(path)

    # Verify state reads before close
    fetched_path = await state.get_attack_path("path_canary_01")
    assert fetched_path is not None
    assert fetched_path.path_status == PathStatus.FEASIBLE
    assert fetched_path.path_confidence == 0.76
    assert fetched_path.canary_target == "CANARY{VAULT_ROOT_PII}"

    # Close DB and simulate full process restart
    await db.close()

    # Reopen DB
    db_reopened = DatabaseManager(db_file)
    await db_reopened.initialize()
    state_reopened = SharedState(db_reopened)

    # Verify Assets
    gw_restored = await state_reopened.get_asset("asset_gw")
    assert gw_restored is not None
    assert gw_restored.current_access_level == AccessLevel.PUBLIC

    db_restored = await state_reopened.get_asset("asset_db")
    assert db_restored is not None
    assert db_restored.is_canary_objective is True
    assert db_restored.canary_description == "CANARY{VAULT_ROOT_PII}"

    # Verify Hypotheses
    hyp2_restored = await state_reopened.get_hypothesis("hyp_dump_vault")
    assert hyp2_restored is not None
    assert hyp2_restored.prerequisite_hypothesis_ids == ["hyp_bypass_gw"]
    assert hyp2_restored.required_access_level == AccessLevel.AUTHENTICATED_USER
    assert hyp2_restored.enables_access_level == AccessLevel.DATABASE_ROOT
    assert hyp2_restored.stage == 2
    assert hyp2_restored.status == HypothesisStatus.PENDING

    # Verify AttackPath
    path_restored = await state_reopened.get_attack_path("path_canary_01")
    assert path_restored is not None
    assert path_restored.name == "Gateway to Canary Vault"
    assert path_restored.asset_sequence == ["asset_gw", "asset_db"]
    assert path_restored.hypothesis_sequence == ["hyp_bypass_gw", "hyp_dump_vault"]
    assert path_restored.path_status == PathStatus.FEASIBLE
    assert path_restored.path_confidence == 0.76
    assert path_restored.path_uncertainty == 0.24
    assert path_restored.risk_level == PathRisk.CRITICAL
    assert path_restored.is_cycle_detected is False
    assert path_restored.canary_target == "CANARY{VAULT_ROOT_PII}"

    # Verify list_attack_paths
    all_paths = await state_reopened.list_attack_paths()
    assert len(all_paths) == 1
    assert all_paths[0].path_id == "path_canary_01"

    await db_reopened.close()
