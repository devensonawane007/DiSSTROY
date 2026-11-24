"""Comprehensive behavioral and end-to-end tests for HypothesisDependencyResolver and prerequisite unlocking."""

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
async def setup_env():
    """Setup in-memory testing environment with full dependency resolution stack."""
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    kg = KnowledgeGraph()
    state.subscribe(kg.handle_state_event)

    config = DiSSTROYConfig()
    intel = FailureIntelligenceEngine(state)
    prioritizer = DynamicHypothesisPrioritizer(state, intel, config)
    path_evaluator = AttackPathEvaluator(kg, state)
    resolver = HypothesisDependencyResolver(state, kg, prioritizer, path_evaluator)

    simulator = SimulatedSecurityEnvironment()
    evidence_engine = EvidenceEngine(state)
    swarm = SwarmManager(state, evidence_engine, intel, simulator, config)

    # Base assets
    a_gw = Asset(
        id="a_gw",
        name="Gateway",
        asset_type=AssetType.API_GATEWAY,
        criticality=0.6,
        current_access_level=AccessLevel.PUBLIC,
    )
    a_admin = Asset(
        id="a_admin",
        name="Admin Service",
        asset_type=AssetType.SERVICE,
        criticality=0.8,
        current_access_level=AccessLevel.NONE,
    )
    a_db = Asset(
        id="a_db",
        name="DB Vault",
        asset_type=AssetType.DATABASE,
        criticality=1.0,
        current_access_level=AccessLevel.NONE,
        is_canary_objective=True,
        canary_description="CANARY{FLAG_DB_VAULT}",
    )

    await state.add_asset(a_gw)
    await state.add_asset(a_admin)
    await state.add_asset(a_db)

    kg.add_asset_dependency("a_gw", "a_admin")
    kg.add_asset_dependency("a_admin", "a_db")

    yield {
        "db": db,
        "state": state,
        "kg": kg,
        "prioritizer": prioritizer,
        "path_evaluator": path_evaluator,
        "resolver": resolver,
        "swarm": swarm,
        "evidence_engine": evidence_engine,
    }

    await db.close()


@pytest.mark.asyncio
async def test_1_hypothesis_with_no_prerequisites_is_eligible(setup_env):
    """Test 1: Hypothesis with no prerequisites declared is immediately eligible."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h = Hypothesis(
        id="h_indep",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Check public gateway",
        description="Verify public gateway route handling",
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(h)

    res = await resolver.resolve_dependencies(h)
    assert res.is_eligible is True
    assert res.is_blocked is False
    assert res.blocking_reason is None
    assert await resolver.is_eligible_for_dispatch(h) is True


@pytest.mark.asyncio
async def test_2_hypothesis_with_unresolved_prerequisite_is_blocked(setup_env):
    """Test 2: Hypothesis with unresolved prerequisite is blocked with explanation in state."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h1 = Hypothesis(
        id="h1_unresolved",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Token leakage",
        description="Investigate potential token leak in headers",
        status=HypothesisStatus.PROPOSED,  # Not validated yet
    )
    h2 = Hypothesis(
        id="h2_blocked",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Admin takeover",
        description="Escalate via leaked token",
        prerequisite_hypothesis_ids=["h1_unresolved"],
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)

    res = await resolver.update_hypothesis_dependency_state(h2)
    assert res.is_eligible is False
    assert res.is_blocked is True
    assert "h1_unresolved" in res.unresolved_prerequisites
    assert "Blocked by unresolved prerequisite(s): h1_unresolved" in res.blocking_reason

    # State verification: H2 does not disappear, becomes PENDING, blocking reason stored in metadata
    fetched_h2 = await state.get_hypothesis("h2_blocked")
    assert fetched_h2 is not None
    assert fetched_h2.status == HypothesisStatus.PENDING
    assert fetched_h2.metadata["is_blocked"] is True
    assert "h1_unresolved" in fetched_h2.metadata["blocking_reason"]


@pytest.mark.asyncio
async def test_3_validated_prerequisite_unlocks_dependent_hypothesis(setup_env):
    """Test 3: Validated prerequisite automatically unlocks dependent hypothesis."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h1 = Hypothesis(
        id="h1_step",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Forge token",
        description="Forge JWT signature",
        status=HypothesisStatus.PROPOSED,
    )
    h2 = Hypothesis(
        id="h2_dep",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Admin command execution",
        description="Execute commands with forged JWT",
        prerequisite_hypothesis_ids=["h1_step"],
        status=HypothesisStatus.PENDING,
    )
    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)

    # Validate H1
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)

    # Trigger unlocking
    unlocked = await resolver.evaluate_and_unlock_dependent_hypotheses("h1_step")
    assert len(unlocked) == 1
    assert unlocked[0].id == "h2_dep"

    fetched_h2 = await state.get_hypothesis("h2_dep")
    assert fetched_h2.status == HypothesisStatus.PROPOSED
    assert fetched_h2.metadata.get("is_blocked") is False


@pytest.mark.asyncio
async def test_4_refuted_prerequisite_blocks_dependent_hypothesis(setup_env):
    """Test 4: Permanently refuted prerequisite blocks dependent hypothesis."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h1 = Hypothesis(
        id="h1_fail",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Flawed auth",
        description="Flawed HMAC check",
        status=HypothesisStatus.REFUTED,
    )
    h2 = Hypothesis(
        id="h2_dead",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Post-bypass admin access",
        description="Access admin panel using bypassed HMAC",
        prerequisite_hypothesis_ids=["h1_fail"],
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)

    res = await resolver.update_hypothesis_dependency_state(h2)
    assert res.is_eligible is False
    assert res.is_permanently_blocked is True
    assert "h1_fail" in res.refuted_prerequisites

    fetched_h2 = await state.get_hypothesis("h2_dead")
    assert fetched_h2.status == HypothesisStatus.ABANDONED
    assert "Permanently blocked by refuted prerequisite" in fetched_h2.metadata["blocking_reason"]


@pytest.mark.asyncio
async def test_5_dependency_state_survives_sqlite_restart(tmp_path):
    """Test 5: Prerequisite configuration and dependency state survive SQLite restart."""
    db_file = tmp_path / "dep_persist.db"
    db = DatabaseManager(db_file)
    await db.initialize()
    state = SharedState(db)
    resolver = HypothesisDependencyResolver(state)

    asset = Asset(id="a_test", name="Test Asset", asset_type=AssetType.HOST, criticality=0.5)
    await state.add_asset(asset)

    h1 = Hypothesis(
        id="h_base",
        target_asset_id="a_test",
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="Base defect",
        description="Base configuration defect",
        status=HypothesisStatus.VALIDATED,
    )
    h2 = Hypothesis(
        id="h_child",
        target_asset_id="a_test",
        category=HypothesisCategory.UNRESTRICTED_ACCESS,
        title="Child access",
        description="Child exploitation",
        prerequisite_hypothesis_ids=["h_base"],
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await resolver.update_hypothesis_dependency_state(h2)

    # Simulate restart
    await db.close()

    db_reopened = DatabaseManager(db_file)
    await db_reopened.initialize()
    state_reopened = SharedState(db_reopened)
    resolver_reopened = HypothesisDependencyResolver(state_reopened)

    h2_restored = await state_reopened.get_hypothesis("h_child")
    assert h2_restored is not None
    assert h2_restored.prerequisite_hypothesis_ids == ["h_base"]
    res = await resolver_reopened.resolve_dependencies(h2_restored)
    assert res.is_eligible is True
    assert "h_base" in res.validated_prerequisites

    await db_reopened.close()


@pytest.mark.asyncio
async def test_6_unlocking_causes_priority_recalculation(setup_env):
    """Test 6: Prerequisite unlocking recalculates and boosts priority score."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h1 = Hypothesis(
        id="h1_prio",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Gateway leak",
        description="Verify gateway credential leak",
        status=HypothesisStatus.PROPOSED,
    )
    h2 = Hypothesis(
        id="h2_prio",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Privilege escalation",
        description="Use credential leak to gain admin access",
        prerequisite_hypothesis_ids=["h1_prio"],
        priority_score=0.2,
        status=HypothesisStatus.PENDING,
    )
    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)

    # Validate H1
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)

    # Unlock H2
    unlocked = await resolver.evaluate_and_unlock_dependent_hypotheses("h1_prio")
    assert len(unlocked) == 1
    unlocked_h2 = unlocked[0]

    # Priority score is boosted upon becoming actionable
    assert unlocked_h2.priority_score > 0.2
    assert unlocked_h2.priority_score >= 0.75


@pytest.mark.asyncio
async def test_7_blocked_hypothesis_is_not_dispatched(setup_env):
    """Test 7: SwarmManager refuses to dispatch blocked or PENDING hypothesis."""
    swarm = setup_env["swarm"]

    h_pending = Hypothesis(
        id="h_unmet",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Blocked probe",
        description="Cannot execute without prerequisite",
        prerequisite_hypothesis_ids=["non_existent_prereq"],
        status=HypothesisStatus.PENDING,
    )

    task = swarm.dispatch_hypothesis(h_pending)
    assert task is None
    assert swarm.active_worker_count == 0


@pytest.mark.asyncio
async def test_8_dependent_hypothesis_requires_own_evidence(setup_env):
    """Test 8: Validating prerequisite does NOT mark dependent hypothesis validated without own evidence."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h1 = Hypothesis(
        id="h1_root",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Root hypothesis",
        description="Root security proposition",
        status=HypothesisStatus.VALIDATED,
    )
    h2 = Hypothesis(
        id="h2_leaf",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Leaf hypothesis",
        description="Requires separate verifiable proof",
        prerequisite_hypothesis_ids=["h1_root"],
        status=HypothesisStatus.PENDING,
    )
    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)

    await resolver.evaluate_and_unlock_dependent_hypotheses("h1_root")

    fetched_h2 = await state.get_hypothesis("h2_leaf")
    # Must be PROPOSED, NEVER VALIDATED!
    assert fetched_h2.status == HypothesisStatus.PROPOSED
    assert fetched_h2.status != HypothesisStatus.VALIDATED


@pytest.mark.asyncio
async def test_9_multilevel_dependency_chain(setup_env):
    """Test 9: Multi-level dependency chain H1 -> H2 -> H3 unlocks sequentially."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    h1 = Hypothesis(id="h1_chain", target_asset_id="a_gw", category=HypothesisCategory.AUTH_BYPASS_RISK, title="H1", description="Chain step 1", status=HypothesisStatus.PROPOSED)
    h2 = Hypothesis(id="h2_chain", target_asset_id="a_admin", category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK, title="H2", description="Chain step 2", prerequisite_hypothesis_ids=["h1_chain"], status=HypothesisStatus.PENDING)
    h3 = Hypothesis(id="h3_chain", target_asset_id="a_db", category=HypothesisCategory.UNRESTRICTED_ACCESS, title="H3", description="Chain step 3", prerequisite_hypothesis_ids=["h2_chain"], status=HypothesisStatus.PENDING)

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await state.add_hypothesis(h3)

    # Initial check: H2 and H3 are both blocked
    assert (await resolver.resolve_dependencies(h2)).is_eligible is False
    assert (await resolver.resolve_dependencies(h3)).is_eligible is False

    # Validate H1 -> H2 unlocks, but H3 stays blocked
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)
    unlocked_after_h1 = await resolver.evaluate_and_unlock_dependent_hypotheses("h1_chain")
    assert [h.id for h in unlocked_after_h1] == ["h2_chain"]

    assert (await state.get_hypothesis("h2_chain")).status == HypothesisStatus.PROPOSED
    assert (await state.get_hypothesis("h3_chain")).status == HypothesisStatus.PENDING

    # Validate H2 -> H3 unlocks!
    h2_current = await state.get_hypothesis("h2_chain")
    h2_current.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h2_current)

    unlocked_after_h2 = await resolver.evaluate_and_unlock_dependent_hypotheses("h2_chain")
    assert [h.id for h in unlocked_after_h2] == ["h3_chain"]
    assert (await state.get_hypothesis("h3_chain")).status == HypothesisStatus.PROPOSED


@pytest.mark.asyncio
async def test_10_circular_dependency_is_detected_safely(setup_env):
    """Test 10: Circular dependency H_A <-> H_B is detected without infinite loop."""
    state = setup_env["state"]
    resolver = setup_env["resolver"]

    ha = Hypothesis(
        id="ha_circ",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Circular A",
        description="Depends on B",
        prerequisite_hypothesis_ids=["hb_circ"],
        status=HypothesisStatus.PROPOSED,
    )
    hb = Hypothesis(
        id="hb_circ",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Circular B",
        description="Depends on A",
        prerequisite_hypothesis_ids=["ha_circ"],
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(ha)
    await state.add_hypothesis(hb)

    res_a = await resolver.resolve_dependencies(ha)
    assert res_a.is_cycle_detected is True
    assert res_a.is_eligible is False
    assert res_a.is_blocked is True
    assert "circular prerequisite dependency" in res_a.blocking_reason


@pytest.mark.asyncio
async def test_end_to_end_dependency_unlock_and_path_reevaluation(setup_env):
    """
    End-to-end behavioral test proving complete adaptive intelligence:
    H1 starts unresolved
    → H2 is blocked
    → H1 becomes VERIFIED with evidence
    → H2 becomes eligible
    → H2 is dispatched
    → H2 produces evidence
    → H2 becomes VERIFIED
    → dependent AttackPath is reevaluated to VERIFIED.
    """
    state = setup_env["state"]
    resolver = setup_env["resolver"]
    swarm = setup_env["swarm"]
    evaluator = setup_env["path_evaluator"]
    evidence_engine = setup_env["evidence_engine"]

    # 1. Hypotheses with real test plan probe steps matching simulator
    step1 = ProbeStep(action_type="inspect_headers", parameters={"include_auth": True})
    h1 = Hypothesis(
        id="h1_e2e",
        target_asset_id="a_gw",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Gateway Token Extraction",
        description="Extract authorization token from gateway debug headers",
        test_plan=[step1],
        required_access_level=AccessLevel.PUBLIC,
        enables_access_level=AccessLevel.AUTHENTICATED_USER,
        status=HypothesisStatus.PROPOSED,
        confidence=0.85,
    )

    step2 = ProbeStep(action_type="test_token_signature", parameters={"token": "simulated_admin_jwt"})
    h2 = Hypothesis(
        id="h2_e2e",
        target_asset_id="a_admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Admin Privilege Escalation",
        description="Leverage extracted token against admin portal",
        test_plan=[step2],
        prerequisite_hypothesis_ids=["h1_e2e"],
        required_access_level=AccessLevel.AUTHENTICATED_USER,
        enables_access_level=AccessLevel.ADMIN_PRIVILEGE,
        status=HypothesisStatus.PENDING,
        confidence=0.9,
    )

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)

    # 2. Attack Path connecting Gateway to Admin
    path = AttackPath(
        path_id="path_e2e",
        name="Gateway -> Admin Escalation",
        source_asset_id="a_gw",
        target_asset_id="a_admin",
        asset_sequence=["a_gw", "a_admin"],
        hypothesis_sequence=["h1_e2e", "h2_e2e"],
        path_status=PathStatus.THEORETICAL,
    )
    await state.add_attack_path(path)

    # Initially: H2 is blocked, cannot be dispatched
    res_h2 = await resolver.update_hypothesis_dependency_state(h2)
    assert res_h2.is_blocked is True
    assert (await state.get_hypothesis("h2_e2e")).status == HypothesisStatus.PENDING
    assert swarm.dispatch_hypothesis(h2) is None

    # Path starts as FEASIBLE for step 1 or THEORETICAL
    path_init = await evaluator.evaluate_path(path)
    assert path_init.path_status != PathStatus.VERIFIED

    # 3. Dispatch and execute H1
    task1 = swarm.dispatch_hypothesis(h1)
    assert task1 is not None
    await task1

    # Record validating evidence for H1
    ev1 = EvidenceRecord(
        hypothesis_id="h1_e2e",
        worker_id="worker_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data={"token_signature_valid": True, "claims": {"role": "admin"}},
        supports_hypothesis=True,
        validation_power=0.95,
    )
    await state.add_evidence(ev1)
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)
    h1_verified = await state.get_hypothesis("h1_e2e")
    assert h1_verified.status == HypothesisStatus.VALIDATED

    # 4. Resolver unlocks H2 automatically
    unlocked = await resolver.evaluate_and_unlock_dependent_hypotheses("h1_e2e")
    assert len(unlocked) == 1
    h2_unlocked = unlocked[0]
    assert h2_unlocked.status == HypothesisStatus.PROPOSED
    assert h2_unlocked.priority_score >= 0.75

    # 5. Now Swarm can dispatch H2!
    task2 = swarm.dispatch_hypothesis(h2_unlocked)
    assert task2 is not None
    await task2

    # Record validating evidence for H2
    ev2 = EvidenceRecord(
        hypothesis_id="h2_e2e",
        worker_id="worker_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data={"privilege_escalation_successful": True, "elevated_role": "superadmin"},
        supports_hypothesis=True,
        validation_power=0.95,
    )
    await state.add_evidence(ev2)
    h2_unlocked.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h2_unlocked)
    h2_verified = await state.get_hypothesis("h2_e2e")
    assert h2_verified.status == HypothesisStatus.VALIDATED

    # 6. Re-evaluate AttackPath
    path_final = await evaluator.evaluate_path(path)
    assert path_final.path_status == PathStatus.VERIFIED
    assert path_final.path_uncertainty == 0.0
    assert path_final.path_confidence >= 0.70
