"""Tests for NetworkX KnowledgeGraph representation and analytics."""

import pytest
from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.state.shared_state import StateChangeEvent


@pytest.mark.asyncio
async def test_knowledge_graph_event_sync():
    kg = KnowledgeGraph()

    # Asset Event
    await kg.handle_state_event(
        StateChangeEvent(
            "ASSET_ADDED",
            "srv_gw",
            {"id": "srv_gw", "name": "API Gateway", "asset_type": "API_GATEWAY", "criticality": 0.8},
        )
    )

    # Observation Event
    await kg.handle_state_event(
        StateChangeEvent(
            "OBSERVATION_ADDED",
            "obs_header",
            {
                "id": "obs_header",
                "asset_id": "srv_gw",
                "kind": "HTTP_HEADER",
                "title": "Debug Header Expose",
                "confidence": 0.9,
            },
        )
    )

    # Hypothesis Event
    await kg.handle_state_event(
        StateChangeEvent(
            "HYPOTHESIS_ADDED",
            "hyp_debug",
            {
                "id": "hyp_debug",
                "target_asset_id": "srv_gw",
                "category": "CONFIGURATION_DEFECT",
                "title": "Debug mode active",
                "status": "PROPOSED",
                "priority_score": 0.75,
                "supporting_observation_ids": ["obs_header"],
            },
        )
    )

    # Evidence Event
    await kg.handle_state_event(
        StateChangeEvent(
            "EVIDENCE_ADDED",
            "ev_01",
            {
                "id": "ev_01",
                "hypothesis_id": "hyp_debug",
                "evidence_type": "PROBE_RESPONSE",
                "supports_hypothesis": True,
                "validation_power": 0.85,
                "falsification_power": 0.0,
            },
        )
    )

    # Failure Event
    await kg.handle_state_event(
        StateChangeEvent(
            "FAILURE_RECORDED",
            "fail_01",
            {
                "id": "fail_01",
                "hypothesis_id": "hyp_debug",
                "failure_category": "PROBE_TIMEOUT",
                "error_message": "Timed out",
            },
        )
    )

    summary = kg.summary()
    assert summary["total_nodes"] == 5
    assert summary["nodes_by_type"]["ASSET"] == 1
    assert summary["nodes_by_type"]["OBSERVATION"] == 1
    assert summary["nodes_by_type"]["HYPOTHESIS"] == 1
    assert summary["nodes_by_type"]["EVIDENCE"] == 1
    assert summary["nodes_by_type"]["FAILURE"] == 1

    # Verify edge connectivity
    obs = kg.get_asset_observations("srv_gw")
    assert "obs_header" in obs

    # Add second asset and path
    kg.add_asset_node("srv_db", "Internal DB", "DATABASE", 1.0)
    kg.add_asset_dependency("srv_gw", "srv_db", "DEPENDS_ON")

    paths = kg.find_paths_between_assets("srv_gw", "srv_db")
    assert len(paths) == 1
    assert paths[0] == ["srv_gw", "srv_db"]

    # Correlation test
    kg.add_observation_node("obs_db_leak", "srv_db", "CONFIG_LEAK", "DB password hash leak", 0.95)
    kg.correlate_observations("obs_header", "obs_db_leak", "Correlation via leaked backend session key")
    correlated = kg.get_correlated_observations("obs_header")
    assert len(correlated) == 1
    assert correlated[0][0] == "obs_db_leak"


@pytest.mark.asyncio
async def test_multihop_reasoning_and_prerequisites():
    kg = KnowledgeGraph()

    # 1. Add multi-hop asset topology: Gateway -> Auth -> Admin -> Database
    kg.add_asset_node("gw", "Gateway", "API_GATEWAY", 0.5)
    kg.add_asset_node("auth", "Auth Service", "AUTH_PROVIDER", 0.7)
    kg.add_asset_node("admin", "Admin Console", "SERVICE", 0.8)
    kg.add_asset_node("db", "DB Cluster", "DATABASE", 1.0, is_canary_objective=True, canary_description="CANARY{FLAG}")

    kg.add_asset_dependency("gw", "auth", "ROUTES_TO")
    kg.add_asset_dependency("auth", "admin", "TRUSTS")
    kg.add_asset_dependency("admin", "db", "QUERIES")

    # Multi-hop path discovery
    candidate_paths = kg.find_paths_between_assets("gw", "db")
    assert len(candidate_paths) == 1
    assert candidate_paths[0] == ["gw", "auth", "admin", "db"]

    # 2. Add Hypotheses with prerequisites
    kg.add_hypothesis_node(
        hyp_id="hyp_token_forge",
        target_asset_id="auth",
        category="AUTH_BYPASS_RISK",
        title="Forge Auth JWT",
        status="PROPOSED",
        priority_score=0.8,
    )
    kg.add_hypothesis_node(
        hyp_id="hyp_admin_takeover",
        target_asset_id="admin",
        category="PRIVILEGE_ESCALATION_RISK",
        title="Escalate to Admin using forged JWT",
        status="PENDING",
        priority_score=0.85,
        prerequisite_hypothesis_ids=["hyp_token_forge"],
    )
    kg.add_hypothesis_node(
        hyp_id="hyp_db_exfil",
        target_asset_id="db",
        category="UNRESTRICTED_ACCESS",
        title="Exfiltrate DB records",
        status="PENDING",
        priority_score=0.9,
        prerequisite_hypothesis_ids=["hyp_admin_takeover"],
    )

    # Verify prerequisite traversal
    prereqs = kg.get_prerequisite_hypotheses("hyp_admin_takeover")
    assert prereqs == ["hyp_token_forge"]

    dependents = kg.get_dependent_hypotheses("hyp_admin_takeover")
    assert dependents == ["hyp_db_exfil"]

    # Verify reachability distinction: graph connectivity != validated reachability
    # Initially none are validated
    assert kg.is_path_reachable_strictly_validated(["hyp_token_forge", "hyp_admin_takeover", "hyp_db_exfil"]) is False

    # Simulate validation of all steps
    kg.g.nodes["hyp_token_forge"]["status"] = "VALIDATED"
    assert kg.is_path_reachable_strictly_validated(["hyp_token_forge", "hyp_admin_takeover", "hyp_db_exfil"]) is False

    kg.g.nodes["hyp_admin_takeover"]["status"] = "VALIDATED"
    kg.g.nodes["hyp_db_exfil"]["status"] = "VALIDATED"
    # Now all steps are validated
    assert kg.is_path_reachable_strictly_validated(["hyp_token_forge", "hyp_admin_takeover", "hyp_db_exfil"]) is True

    # 3. Test cycle detection
    # Introduce circular dependency
    kg.add_prerequisite_dependency("hyp_db_exfil", "hyp_token_forge")
    cycles = kg.detect_cycles()
    assert len(cycles) >= 1
    cycle_nodes = set()
    for c in cycles:
        cycle_nodes.update(c)
    assert "hyp_token_forge" in cycle_nodes
    assert "hyp_db_exfil" in cycle_nodes

    # 4. Test invalidated branch pruning
    # Mark root hypothesis as REFUTED
    kg.g.nodes["hyp_token_forge"]["status"] = "REFUTED"
    invalidated = kg.get_invalidated_branches()
    assert "hyp_token_forge" in invalidated
    assert "hyp_admin_takeover" in invalidated
    assert "hyp_db_exfil" in invalidated
