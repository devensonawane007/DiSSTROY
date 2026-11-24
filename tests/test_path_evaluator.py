"""Unit and behavioral tests for AttackPathEvaluator."""

import pytest
from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.graph.path_evaluator import AttackPathEvaluator
from disstroy.models.asset import Asset
from disstroy.models.enums import AccessLevel, AssetType, HypothesisCategory, HypothesisStatus, PathRisk, PathStatus
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.path import AttackPath
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState


@pytest.mark.asyncio
async def test_path_evaluator_lifecycle():
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    kg = KnowledgeGraph()
    state.subscribe(kg.handle_state_event)

    evaluator = AttackPathEvaluator(kg, state)

    # 1. Create simulated assets: GW -> Auth -> Admin -> DB (Canary)
    gw = Asset(id="gw", name="Gateway", asset_type=AssetType.API_GATEWAY, current_access_level=AccessLevel.PUBLIC, criticality=0.5)
    auth = Asset(id="auth", name="Auth", asset_type=AssetType.AUTH_PROVIDER, current_access_level=AccessLevel.NONE, criticality=0.7)
    admin = Asset(id="admin", name="Admin Portal", asset_type=AssetType.SERVICE, current_access_level=AccessLevel.NONE, criticality=0.8)
    db_asset = Asset(
        id="db",
        name="DB Cluster",
        asset_type=AssetType.DATABASE,
        current_access_level=AccessLevel.NONE,
        criticality=1.0,
        is_canary_objective=True,
        canary_description="CANARY{VAULT_PII}",
    )

    await state.add_asset(gw)
    await state.add_asset(auth)
    await state.add_asset(admin)
    await state.add_asset(db_asset)

    kg.add_asset_dependency("gw", "auth")
    kg.add_asset_dependency("auth", "admin")
    kg.add_asset_dependency("admin", "db")

    # 2. Hypotheses:
    # H1: Forge Auth token (requires PUBLIC access, enables AUTHENTICATED_USER)
    h1 = Hypothesis(
        id="h1",
        target_asset_id="auth",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Forge Auth token",
        description="Verify whether auth token signing key can be bypassed to acquire user session",
        required_access_level=AccessLevel.PUBLIC,
        enables_access_level=AccessLevel.AUTHENTICATED_USER,
        stage=1,
        status=HypothesisStatus.PROPOSED,
        confidence=0.8,
    )
    # H2: Pivot to Admin (requires AUTHENTICATED_USER, enables ADMIN_PRIVILEGE)
    h2 = Hypothesis(
        id="h2",
        target_asset_id="admin",
        category=HypothesisCategory.PRIVILEGE_ESCALATION_RISK,
        title="Admin takeover",
        description="Escalate privileges on admin portal using authenticated session token",
        prerequisite_hypothesis_ids=["h1"],
        required_access_level=AccessLevel.AUTHENTICATED_USER,
        enables_access_level=AccessLevel.ADMIN_PRIVILEGE,
        stage=2,
        status=HypothesisStatus.PENDING,
        confidence=0.75,
    )
    # H3: Exfiltrate Canary from DB (requires ADMIN_PRIVILEGE, enables DATABASE_ROOT)
    h3 = Hypothesis(
        id="h3",
        target_asset_id="db",
        category=HypothesisCategory.UNRESTRICTED_ACCESS,
        title="Dump canary vault",
        description="Extract sensitive records and canary token from database cluster",
        prerequisite_hypothesis_ids=["h2"],
        required_access_level=AccessLevel.ADMIN_PRIVILEGE,
        enables_access_level=AccessLevel.DATABASE_ROOT,
        stage=3,
        status=HypothesisStatus.PENDING,
        confidence=0.9,
    )

    await state.add_hypothesis(h1)
    await state.add_hypothesis(h2)
    await state.add_hypothesis(h3)

    # 3. Create candidate AttackPath
    path = AttackPath(
        path_id="path_canary",
        name="GW -> Auth -> Admin -> DB",
        source_asset_id="gw",
        target_asset_id="db",
        asset_sequence=["gw", "auth", "admin", "db"],
        hypothesis_sequence=["h1", "h2", "h3"],
    )

    # Initially, H1 has no prerequisite blocks and source is PUBLIC, so immediate step H1 is actionable!
    # Status should be FEASIBLE (or THEORETICAL if initial prereqs were blocked)
    evaluated = await evaluator.evaluate_path(path)
    assert evaluated.path_status == PathStatus.FEASIBLE
    assert evaluated.canary_target == "CANARY{VAULT_PII}"
    assert evaluated.risk_level == PathRisk.CRITICAL
    assert 0.0 < evaluated.path_confidence <= 0.85
    assert evaluated.path_uncertainty == 1.0  # 0 of 3 validated

    # 4. Now validate H1
    h1.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h1)
    # Update graph node
    kg.g.nodes["h1"]["status"] = "VALIDATED"

    evaluated2 = await evaluator.evaluate_path(path)
    assert evaluated2.path_status == PathStatus.FEASIBLE
    assert round(evaluated2.path_uncertainty, 2) == 0.67  # 1 of 3 validated

    # 5. Validate H2 and H3 to achieve VERIFIED
    h2.status = HypothesisStatus.VALIDATED
    h3.status = HypothesisStatus.VALIDATED
    await state.update_hypothesis(h2)
    await state.update_hypothesis(h3)
    kg.g.nodes["h2"]["status"] = "VALIDATED"
    kg.g.nodes["h3"]["status"] = "VALIDATED"

    evaluated3 = await evaluator.evaluate_path(path)
    assert evaluated3.path_status == PathStatus.VERIFIED
    assert evaluated3.path_uncertainty == 0.0
    assert evaluated3.path_confidence >= 0.7
    assert evaluated3.risk_level == PathRisk.CRITICAL

    # 6. Test REFUTATION / BLOCKED
    # If H1 is refuted, the entire downstream path is blocked
    h1.status = HypothesisStatus.REFUTED
    await state.update_hypothesis(h1)
    kg.g.nodes["h1"]["status"] = "REFUTED"

    evaluated_blocked = await evaluator.evaluate_path(path)
    assert evaluated_blocked.path_status == PathStatus.BLOCKED
    assert evaluated_blocked.path_confidence == 0.0
    assert evaluated_blocked.path_uncertainty == 1.0

    await db.close()
