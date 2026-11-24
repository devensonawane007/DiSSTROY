"""Focused behavioural tests for Milestone 03 Item 5: Swarm Integration and Dependency-Driven Scheduling."""

import asyncio
import pytest

from disstroy.config import DiSSTROYConfig
from disstroy.evidence.engine import EvidenceEngine
from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.graph.path_evaluator import AttackPathEvaluator
from disstroy.hypothesis.prioritizer import DynamicHypothesisPrioritizer
from disstroy.hypothesis.resolver import HypothesisDependencyResolver
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.asset import Asset
from disstroy.models.enums import (
    AccessLevel,
    AssetType,
    EvidenceType,
    HypothesisCategory,
    HypothesisStatus,
    PathStatus,
)
from disstroy.models.evidence import EvidenceRecord
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.path import AttackPath
from disstroy.simulator.environment import SimulatedSecurityEnvironment
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState
from disstroy.swarm.manager import SwarmManager


@pytest.fixture
async def setup_swarm_env():
    """Build shared state and swarm manager wired with dependency resolver and path evaluator."""
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    kg = KnowledgeGraph()
    state.subscribe(kg.handle_state_event)

    config = DiSSTROYConfig(max_concurrent_workers=3)
    intel = FailureIntelligenceEngine(state)
    prioritizer = DynamicHypothesisPrioritizer(state, intel, config)
    path_evaluator = AttackPathEvaluator(kg, state)
    resolver = HypothesisDependencyResolver(state, kg, prioritizer, path_evaluator)

    simulator = SimulatedSecurityEnvironment()
    evidence_engine = EvidenceEngine(state)
    swarm = SwarmManager(
        shared_state=state,
        evidence_engine=evidence_engine,
        failure_intelligence=intel,
        simulator=simulator,
        config=config,
        dependency_resolver=resolver,
        path_evaluator=path_evaluator,
    )

    # Assets
    gw = Asset(id="gw", name="Gateway", asset_type=AssetType.API_GATEWAY, current_access_level=AccessLevel.PUBLIC, criticality=0.5)
    auth = Asset(id="auth", name="Auth Service", asset_type=AssetType.AUTH_PROVIDER, current_access_level=AccessLevel.NONE, criticality=0.7)
    admin = Asset(id="admin", name="Admin Portal", asset_type=AssetType.SERVICE, current_access_level=AccessLevel.NONE, criticality=0.8)
    db_vault = Asset(id="db_vault", name="DB Vault", asset_type=AssetType.DATABASE, current_access_level=AccessLevel.NONE, criticality=1.0, is_canary_objective=True, canary_description="CANARY{FLAG_DB_VAULT}")

    await state.add_asset(gw)
    await state.add_asset(auth)
    await state.add_asset(admin)
    await state.add_asset(db_vault)

    kg.add_asset_dependency("gw", "auth")
    kg.add_asset_dependency("auth", "admin")
    kg.add_asset_dependency("admin", "db_vault")

    yield {
        "db": db,
        "state": state,
        "kg": kg,
        "prioritizer": prioritizer,
        "path_evaluator": path_evaluator,
        "resolver": resolver,
        "swarm": swarm,
        "evidence_engine": evidence_engine,
        "simulator": simulator,
    }

    await swarm.stop_all()
    await db.close()


@pytest.mark.asyncio
async def test_1_blocked_hypothesis_excluded_from_scheduling_and_worker_capacity(setup_swarm_env):
    """
    Test 1 & 5:
    A hypothesis with unresolved prerequisites is excluded from candidate evaluation
    and NEVER consumes a worker slot.
    """
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]

    h_prereq = Hypothesis(
        id="h_root",
        target_asset_id="gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Check Gateway",
        description="Verify initial gateway",
        status=HypothesisStatus.PROPOSED,
        priority_score=0.8,
    )
    h_blocked = Hypothesis(
        id="h_child",
        target_asset_id="admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Admin Escalation",
        description="Requires root gateway verification",
        prerequisite_hypothesis_ids=["h_root"],
        status=HypothesisStatus.PROPOSED,
        priority_score=0.95,  # Higher base priority, but blocked!
    )
    await state.add_hypothesis(h_prereq)
    await state.add_hypothesis(h_blocked)

    # Evaluate scheduling candidates
    candidates = await swarm.evaluate_scheduling_candidates()
    candidate_ids = [c.id for c in candidates]

    # h_child must be excluded despite having higher priority score
    assert "h_root" in candidate_ids
    assert "h_child" not in candidate_ids

    # Run scheduler cycle
    dispatched = await swarm.schedule_cycle()
    assert len(dispatched) == 1
    assert swarm.active_worker_count == 1
    # Only h_root was dispatched
    assert "h_root" in swarm.active_tasks
    assert "h_child" not in swarm.active_tasks

    await swarm.wait_for_any_completed()


@pytest.mark.asyncio
async def test_2_required_scenario_prerequisite_unlock_and_dynamic_scheduling(setup_swarm_env):
    """
    Required behavioural scenario:
    Initial: H1 (eligible), H2 (blocked, requires H1), H3 (eligible), H4 (eligible).
    With 3 workers: allocation drawn from H1, H3, H4. H2 is NOT dispatched.
    H1 completes and becomes VERIFIED.
    Scheduler observes state change -> H2 becomes eligible, enters actionable set, and is selected by scheduler.
    """
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]
    resolver = setup_swarm_env["resolver"]

    step = ProbeStep(action_type="inspect_headers", parameters={"include_auth": True})

    h1 = Hypothesis(id="H1", target_asset_id="gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="Prerequisite H1", description="Prereq investigation", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.85)
    h2 = Hypothesis(id="H2", target_asset_id="admin", category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK, title="Dependent H2", description="Dependent on H1", test_plan=[step], prerequisite_hypothesis_ids=["H1"], status=HypothesisStatus.PROPOSED, priority_score=0.95)
    h3 = Hypothesis(id="H3", target_asset_id="auth", category=HypothesisCategory.CONFIGURATION_DEFECT, title="Independent H3", description="Independent investigation 3", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.70)
    h4 = Hypothesis(id="H4", target_asset_id="admin", category=HypothesisCategory.INFORMATION_DISCLOSURE, title="Independent H4", description="Independent investigation 4", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.60)

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await state.add_hypothesis(h3)
    await state.add_hypothesis(h4)

    # Initial scheduling cycle with 3 worker capacity
    dispatched = await swarm.schedule_cycle()
    assert len(dispatched) == 3
    active_hyps = set(swarm.active_tasks.keys())

    # Worker allocation drawn strictly from H1, H3, H4. H2 must NOT be dispatched!
    assert active_hyps == {"H1", "H3", "H4"}
    assert "H2" not in active_hyps

    # Verify H2 state in SQLite is PENDING with blocking reason
    h2_state = await state.get_hypothesis("H2")
    assert h2_state.status == HypothesisStatus.PENDING
    assert h2_state.metadata.get("is_blocked") is True

    # Complete H1 and record validating evidence
    h1_task = swarm.active_tasks["H1"]
    await h1_task
    # Clear completed H1 from active swarm
    await swarm.wait_for_any_completed()
    assert swarm.has_available_capacity() is True

    ev1 = EvidenceRecord(
        hypothesis_id="H1",
        worker_id="worker_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data={"status": 200, "token": "jwt_valid"},
        supports_hypothesis=True,
        validation_power=0.95,
    )
    await state.add_evidence(ev1)
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)

    # Process completed investigation (triggers automatic prerequisite unlocking)
    await resolver.evaluate_and_unlock_dependent_hypotheses("H1")

    # Verify H2 has entered the actionable candidate pool
    candidates = await swarm.evaluate_scheduling_candidates()
    candidate_ids = [c.id for c in candidates]
    assert "H2" in candidate_ids

    # Next scheduling cycle: scheduler itself must autonomously select H2!
    new_dispatched = await swarm.schedule_cycle()
    assert len(new_dispatched) >= 1
    assert "H2" in swarm.active_tasks


@pytest.mark.asyncio
async def test_3_newly_unlocked_hypothesis_outranks_existing_work(setup_swarm_env):
    """
    Dynamic reprioritization:
    Prove that a newly unlocked hypothesis outranks lower-priority existing candidates.
    Before unlock: H3 = 0.70 (eligible), H2 = blocked.
    After H1 validation: H2 = 0.90 (unlocked). Next scheduling cycle prefers H2 over H3.
    """
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]
    resolver = setup_swarm_env["resolver"]

    step = ProbeStep(action_type="inspect_headers", parameters={})
    h1 = Hypothesis(id="H1", target_asset_id="gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="H1", description="Prereq", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.8)
    h2 = Hypothesis(id="H2", target_asset_id="admin", category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK, title="H2", description="High-priority dependent", test_plan=[step], prerequisite_hypothesis_ids=["H1"], status=HypothesisStatus.PROPOSED, priority_score=0.90)
    h3 = Hypothesis(id="H3", target_asset_id="auth", category=HypothesisCategory.CONFIGURATION_DEFECT, title="H3", description="Medium-priority independent", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.70)

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await state.add_hypothesis(h3)

    # Before unlock: Candidates are [H1 (0.8), H3 (0.7)]. H2 is blocked.
    initial_candidates = await swarm.evaluate_scheduling_candidates()
    assert [c.id for c in initial_candidates] == ["H1", "H3"]

    # Validate H1
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)
    await resolver.evaluate_and_unlock_dependent_hypotheses("H1")

    # After unlock: H2 enters candidates and outranks H3!
    updated_candidates = await swarm.evaluate_scheduling_candidates()
    assert updated_candidates[0].id == "H2"
    assert updated_candidates[1].id == "H3"


@pytest.mark.asyncio
async def test_4_duplicate_concurrent_dispatch_prevented(setup_swarm_env):
    """Test 6: SwarmManager prevents duplicate concurrent dispatch of the same hypothesis."""
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]

    step = ProbeStep(action_type="inspect_headers", parameters={})
    h = Hypothesis(id="H_dup", target_asset_id="gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="Dup Test", description="Test duplicate prevention", test_plan=[step], status=HypothesisStatus.PROPOSED)
    await state.add_hypothesis(h)

    # First dispatch succeeds
    t1 = swarm.dispatch_hypothesis(h)
    assert t1 is not None
    assert "H_dup" in swarm.active_tasks

    # Second dispatch of identical hypothesis while running returns None
    t2 = swarm.dispatch_hypothesis(h)
    assert t2 is None
    assert swarm.active_worker_count == 1

    await swarm.wait_for_any_completed()


@pytest.mark.asyncio
async def test_5_prerequisite_refutation_prevents_dispatch_and_picks_alternative(setup_swarm_env):
    """
    Failure behavior:
    H1 is REFUTED -> H2 is blocked/invalidated -> H2 is NOT dispatched.
    Scheduler autonomously considers alternative viable hypothesis instead.
    """
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]
    resolver = setup_swarm_env["resolver"]

    step = ProbeStep(action_type="inspect_headers", parameters={})
    h1 = Hypothesis(id="H1_fail", target_asset_id="gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="Flawed premise", description="Premise will refute", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.8)
    h2 = Hypothesis(id="H2_blocked", target_asset_id="admin", category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK, title="Dependent on flawed premise", description="Cannot succeed", test_plan=[step], prerequisite_hypothesis_ids=["H1_fail"], status=HypothesisStatus.PROPOSED, priority_score=0.95)
    h3 = Hypothesis(id="H3_alt", target_asset_id="auth", category=HypothesisCategory.CONFIGURATION_DEFECT, title="Alternative vector", description="Independent viable vector", test_plan=[step], status=HypothesisStatus.PROPOSED, priority_score=0.65)

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await state.add_hypothesis(h3)

    # H1 is refuted
    h1.status = HypothesisStatus.REFUTED
    await state.update_hypothesis(h1)
    await resolver.evaluate_and_block_dependent_hypotheses("H1_fail")

    # Evaluate candidates
    candidates = await swarm.evaluate_scheduling_candidates()
    candidate_ids = [c.id for c in candidates]

    # H2 is permanently blocked and excluded; H3 is scheduled as alternative
    assert "H2_blocked" not in candidate_ids
    assert "H3_alt" in candidate_ids

    dispatched = await swarm.schedule_cycle()
    assert len(dispatched) == 1
    assert "H3_alt" in swarm.active_tasks

    await swarm.wait_for_any_completed()


@pytest.mark.asyncio
async def test_6_cancellation_and_capacity_release(setup_swarm_env):
    """Test 8 & 9: Worker completion and cancellation release capacity cleanly."""
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]

    step = ProbeStep(action_type="inspect_headers", parameters={})
    h = Hypothesis(id="H_cancel", target_asset_id="gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="Cancel Test", description="Testing cancellation", test_plan=[step], status=HypothesisStatus.PROPOSED)
    await state.add_hypothesis(h)

    t = swarm.dispatch_hypothesis(h)
    assert t is not None
    assert swarm.active_worker_count == 1

    # Cancel investigation
    stopped = swarm.stop_investigation("H_cancel")
    assert stopped is True

    # Await cleanup
    results = await swarm.wait_for_any_completed()
    assert len(results) == 1
    assert results[0].was_canceled is True
    assert swarm.active_worker_count == 0
    assert swarm.has_available_capacity() is True


@pytest.mark.asyncio
async def test_7_critical_end_to_end_orchestration_path(setup_swarm_env):
    """
    Critical Integration Test:
    1. Create H1, H2 (H2 depends on H1), H3.
    2. Start swarm scheduling cycle.
    3. Verify H2 is NOT dispatched.
    4. Allow H1 to complete and become VERIFIED.
    5. Trigger normal state-change / replanning cycle.
    6. Verify H2 becomes eligible.
    7. Verify scheduler autonomously selects H2.
    8. Verify H2 executes and requires own evidence.
    9. Verify resulting AttackPath is reevaluated to VERIFIED.
    """
    state = setup_swarm_env["state"]
    swarm = setup_swarm_env["swarm"]
    evaluator = setup_swarm_env["path_evaluator"]

    step1 = ProbeStep(action_type="inspect_headers", parameters={"include_auth": True})
    h1 = Hypothesis(id="H1_e2e", target_asset_id="gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="E2E Step 1", description="Extract Auth Token", test_plan=[step1], required_access_level=AccessLevel.PUBLIC, enables_access_level=AccessLevel.AUTHENTICATED_USER, status=HypothesisStatus.PROPOSED, priority_score=0.85)

    step2 = ProbeStep(action_type="test_token_signature", parameters={"token": "simulated_admin_jwt"})
    h2 = Hypothesis(id="H2_e2e", target_asset_id="admin", category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK, title="E2E Step 2", description="Admin Escalation", test_plan=[step2], prerequisite_hypothesis_ids=["H1_e2e"], required_access_level=AccessLevel.AUTHENTICATED_USER, enables_access_level=AccessLevel.ADMIN_PRIVILEGE, status=HypothesisStatus.PROPOSED, priority_score=0.90)

    step3 = ProbeStep(action_type="inspect_headers", parameters={})
    h3 = Hypothesis(id="H3_e2e", target_asset_id="auth", category=HypothesisCategory.CONFIGURATION_DEFECT, title="E2E Step 3", description="Config Check", test_plan=[step3], status=HypothesisStatus.PROPOSED, priority_score=0.60)

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await state.add_hypothesis(h3)

    # Attack path connecting Gateway to Admin
    path = AttackPath(
        path_id="path_e2e_swarm",
        name="Gateway to Admin Escalation",
        source_asset_id="gw",
        target_asset_id="admin",
        asset_sequence=["gw", "admin"],
        hypothesis_sequence=["H1_e2e", "H2_e2e"],
        path_status=PathStatus.THEORETICAL,
    )
    await state.add_attack_path(path)

    # 1. Schedule initial cycle
    dispatched = await swarm.schedule_cycle()
    active_ids = set(swarm.active_tasks.keys())
    assert "H2_e2e" not in active_ids
    assert "H1_e2e" in active_ids

    # 2. Allow H1 to complete
    completed_h1 = []
    while "H1_e2e" in swarm.active_tasks:
        c = await swarm.wait_for_any_completed()
        completed_h1.extend(c)

    # Record validating evidence for H1
    ev1 = EvidenceRecord(
        hypothesis_id="H1_e2e",
        worker_id="worker_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data={"token_signature_valid": True},
        supports_hypothesis=True,
        validation_power=0.95,
    )
    await state.add_evidence(ev1)
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)

    # 3. Process completed investigations (triggers dependency unlocking)
    await swarm.process_completed_investigations(completed_h1)

    # 4. Schedule next cycle: scheduler autonomously selects H2
    second_dispatched = await swarm.schedule_cycle()
    assert "H2_e2e" in swarm.active_tasks

    # 5. Allow H2 to complete
    completed_h2 = []
    while "H2_e2e" in swarm.active_tasks:
        c = await swarm.wait_for_any_completed()
        completed_h2.extend(c)
    assert any(r.hypothesis_id == "H2_e2e" for r in completed_h2)

    # Record validating evidence for H2
    ev2 = EvidenceRecord(
        hypothesis_id="H2_e2e",
        worker_id="worker_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data={"privilege_escalation_successful": True},
        supports_hypothesis=True,
        validation_power=0.95,
    )
    await state.add_evidence(ev2)
    h2.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h2)

    # Re-evaluate AttackPath
    updated_path = await evaluator.evaluate_path(path)
    assert updated_path.path_status == PathStatus.VERIFIED
    assert updated_path.path_uncertainty == 0.0
    assert updated_path.path_confidence >= 0.70
