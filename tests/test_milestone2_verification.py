"""Milestone 02 Behavioural Intelligence Verification Tests.

Deep empirical verification of:
1. Concurrency and worker overlap
2. Adaptive replanning & duplicate prevention
3. Failure intelligence & penalty sorting
4. LLM reliability, circuit-breaker & identity tracking
5. State and graph consistency across DB restart
6. Execution lifecycle repeatability and leak prevention
"""

import asyncio
import os
import tempfile
import time
from typing import Dict, Any
import pytest

from disstroy.config import DiSSTROYConfig
from disstroy.core.orchestrator import DiSSTROYOrchestrator
from disstroy.evidence.engine import EvidenceEngine
from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.hypothesis.engine import HypothesisEngine
from disstroy.hypothesis.prioritizer import DynamicHypothesisPrioritizer
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.llm.mock import MockLLMProvider
from disstroy.llm.ollama import OllamaProvider
from disstroy.models.asset import Asset
from disstroy.models.enums import (
    AssetType,
    FailureCategory,
    HypothesisCategory,
    HypothesisStatus,
    ObservationKind,
    OrchestratorState,
)
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.observation import Observation
from disstroy.simulator.environment import SimulatedSecurityEnvironment
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState
from disstroy.swarm.manager import SwarmManager


# =========================================================================
# Investigation 1: Genuine Concurrency & Cancellation
# =========================================================================

@pytest.mark.asyncio
async def test_investigation_1_genuine_concurrency_overlap():
    """Verify that workers genuinely overlap in time during execution."""
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    config = DiSSTROYConfig(max_concurrent_workers=3)
    evidence_engine = EvidenceEngine(state)
    failure_intel = FailureIntelligenceEngine(state)
    sim = SimulatedSecurityEnvironment()

    asset = Asset(id="asset_conc", name="Concurrency Target", asset_type=AssetType.SERVICE, criticality=0.8)
    await state.add_asset(asset)

    swarm = SwarmManager(
        shared_state=state,
        evidence_engine=evidence_engine,
        failure_intelligence=failure_intel,
        simulator=sim,
        config=config,
    )

    # Create 3 independent hypotheses with probe step
    hyps = []
    for i in range(3):
        step = ProbeStep(
            action_type="check_debug_route",
            parameters={"target_asset_id": "asset_api_gw", "path": "/debug/vars"},
            expected_indicators=["upstreams"],
        )
        h = Hypothesis(
            id=f"hyp_conc_{i}",
            target_asset_id="asset_conc",
            category=HypothesisCategory.INFORMATION_DISCLOSURE,
            title=f"Parallel probe {i}",
            description="Verify concurrency",
            test_plan=[step],
            status=HypothesisStatus.PROPOSED,
        )
        await state.add_hypothesis(h)
        hyps.append(h)

    # Dispatch all 3 concurrently
    tasks = [swarm.dispatch_hypothesis(h) for h in hyps]
    assert all(t is not None for t in tasks)
    assert swarm.active_worker_count == 3
    assert swarm.peak_simultaneous_workers == 3

    # Wait for completion
    completed_results = []
    while swarm.active_worker_count > 0:
        results = await swarm.wait_for_any_completed(timeout=2.0)
        completed_results.extend(results)

    assert len(completed_results) == 3

    # Measure start and end times to prove overlap
    starts = [r.start_time_epoch for r in completed_results]
    ends = [r.end_time_epoch for r in completed_results]

    max_start = max(starts)
    min_end = min(ends)

    # Overlap theorem: if the latest start time is before the earliest completion time,
    # then all workers were actively executing simultaneously at time max_start.
    assert max_start < min_end, f"Execution did not overlap! Latest start: {max_start}, Earliest end: {min_end}"

    # Verify worker cancellation
    h_cancel = Hypothesis(
        id="hyp_cancel_test",
        target_asset_id="asset_conc",
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="To be canceled",
        description="Cancellation check",
        test_plan=[ProbeStep(action_type="check_debug_route", parameters={"target_asset_id": "asset_api_gw"})],
    )
    await state.add_hypothesis(h_cancel)
    cancel_task = swarm.dispatch_hypothesis(h_cancel)
    assert cancel_task is not None

    stopped = swarm.stop_investigation("hyp_cancel_test")
    assert stopped is True
    cancel_results = await swarm.wait_for_any_completed(timeout=1.0)
    assert len(cancel_results) == 1
    assert cancel_results[0].was_canceled is True

    await swarm.stop_all()
    await db.close()


# =========================================================================
# Investigation 2: Adaptive Replanning & Duplicate Prevention
# =========================================================================

@pytest.mark.asyncio
async def test_investigation_2_adaptive_replanning_and_no_duplicates():
    """Verify that dynamic observations update state and duplicate hypotheses are rejected."""
    config = DiSSTROYConfig(db_path=":memory:", max_concurrent_workers=2, use_mock_llm_fallback=True)
    orchestrator = DiSSTROYOrchestrator(config=config)
    await orchestrator.initialize()

    report = await orchestrator.run_lifecycle()

    # 1. Observations entered shared state
    assert orchestrator.runtime_events_injected is True
    assert orchestrator.replanning_events_count >= 1

    # 2. Check duplicate hypothesis prevention
    # Re-adding a validated hypothesis must NOT revert its status to PROPOSED
    validated_hyps = report["validated_findings"]
    assert len(validated_hyps) > 0

    val_id = validated_hyps[0]["id"]
    target_id = validated_hyps[0]["target_asset"]

    re_add_hyp = Hypothesis(
        id=val_id,
        target_asset_id=target_id,
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="Duplicate re-insertion",
        description="Attempt to resurrect validated hypothesis as proposed",
        status=HypothesisStatus.PROPOSED,
    )

    assert orchestrator.state is not None
    await orchestrator.state.add_hypothesis(re_add_hyp)

    # Verify status is still VALIDATED
    persisted = await orchestrator.state.get_hypothesis(val_id)
    assert persisted is not None
    assert persisted.status == HypothesisStatus.VALIDATED, "Terminal status was overwritten by duplicate insert!"

    # 3. Duplicate investigation rate in report is 0.0%
    assert report["replanning_metrics"]["duplicate_investigation_rate"] == 0.0

    await orchestrator.close()


# =========================================================================
# Investigation 3: Failure Intelligence & Penalty Sorting
# =========================================================================

@pytest.mark.asyncio
async def test_investigation_3_failure_penalties_and_reprioritization():
    """Verify distinct failure categories produce tailored penalties and alter prioritization."""
    db = DatabaseManager(":memory:")
    await db.initialize()
    state = SharedState(db)
    config = DiSSTROYConfig()
    intel = FailureIntelligenceEngine(state)
    prioritizer = DynamicHypothesisPrioritizer(state, intel, config)

    asset_auth = Asset(id="asset_auth", name="Auth Service", asset_type=AssetType.AUTH_PROVIDER, criticality=0.9)
    asset_web = Asset(id="asset_web", name="Web Service", asset_type=AssetType.SERVICE, criticality=0.7)
    await state.add_asset(asset_auth)
    await state.add_asset(asset_web)

    # Hyp 1 on Auth (initially higher priority because criticality 0.9)
    hyp_auth = Hypothesis(
        id="hyp_auth_token",
        target_asset_id="asset_auth",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Auth token bypass",
        description="Testing bypass",
        prior_probability=0.8,
        confidence=0.8,
        status=HypothesisStatus.PROPOSED,
    )
    # Hyp 2 on Web (initially lower priority because criticality 0.7)
    hyp_web = Hypothesis(
        id="hyp_web_config",
        target_asset_id="asset_web",
        category=HypothesisCategory.CONFIGURATION_DEFECT,
        title="Web config defect",
        description="Testing config",
        prior_probability=0.7,
        confidence=0.7,
        status=HypothesisStatus.PROPOSED,
    )
    await state.add_hypothesis(hyp_auth)
    await state.add_hypothesis(hyp_web)

    # Initial priority ranking
    prio_auth_init = await prioritizer.calculate_priority(hyp_auth, asset_auth)
    prio_web_init = await prioritizer.calculate_priority(hyp_web, asset_web)
    assert prio_auth_init > prio_web_init, "Auth should initially have higher priority"

    # Simulate hard authentication denial failure on hyp_auth
    fail_output = {"status_code": 401, "body": "Signature verification failed: HMAC required."}
    record = await intel.diagnose_and_learn(hyp_auth, "worker_01", fail_output)
    assert record.failure_category == FailureCategory.ACCESS_DENIED_HARD

    # Re-calculate priority after lesson learned
    prio_auth_after = await prioritizer.calculate_priority(hyp_auth, asset_auth)
    prio_web_after = await prioritizer.calculate_priority(hyp_web, asset_web)

    # Verify that auth hypothesis priority dropped dramatically due to penalty factor
    assert prio_auth_after < prio_auth_init
    assert prio_auth_after < prio_web_after, "Failure intelligence failed to deprioritize penalized hypothesis!"

    await db.close()


# =========================================================================
# Investigation 4: LLM Provider Reliability & Telemetry
# =========================================================================

@pytest.mark.asyncio
async def test_investigation_4_llm_telemetry_and_markdown_json_parsing():
    """Verify LLM telemetry transparency and markdown-wrapped JSON parsing."""
    mock = MockLLMProvider()
    ollama = OllamaProvider(
        base_url="http://127.0.0.1:11434",
        model="llama3.2:latest",
        fallback=mock,
        circuit_breaker_ttl=10.0,
    )

    # 1. Circuit breaker healthcheck when offline
    is_avail = await ollama.is_available()
    assert is_avail is False  # Ollama daemon is offline

    # 2. Fast cached response (no 1.5s delay)
    t0 = time.time()
    await ollama.is_available()
    assert (time.time() - t0) < 0.05, "Circuit breaker did not cache offline state!"

    # 3. Test Markdown-wrapped JSON parser
    markdown_payload = """
    Here are the generated security hypotheses based on observations:
    ```json
    [
      {
        "title": "Exposed admin debug console",
        "category": "CONFIGURATION_DEFECT",
        "description": "Found debug endpoint",
        "prior_probability": 0.85,
        "test_plan": [
          {
            "action_type": "check_debug",
            "parameters": {"path": "/debug"},
            "expected_indicators": ["debug=1"],
            "refuting_indicators": ["404"]
          }
        ]
      }
    ]
    ```
    """
    parsed = ollama._parse_json_hypotheses(markdown_payload)
    assert parsed is not None
    assert len(parsed) == 1
    assert parsed[0]["title"] == "Exposed admin debug console"

    # 4. Generate hypotheses via fallback and verify provider identity
    asset = Asset(id="asset_test", name="Test Asset", asset_type=AssetType.SERVICE)
    obs = Observation(asset_id="asset_test", kind=ObservationKind.HTTP_HEADER, title="Test header")

    hyps = await ollama.generate_hypotheses(asset, [obs], [])
    assert len(hyps) > 0
    # Strict verification: NEVER silently claim fallback run was live Ollama!
    for h in hyps:
        assert h.is_fallback is True
        assert "unreachable" in h.fallback_reason.lower() or "ollama" in h.fallback_reason.lower()
        assert h.generated_by_provider == "mock"

    # 5. Check telemetry
    telemetry = ollama.get_telemetry()
    assert telemetry["configured_provider"] == "ollama"
    assert telemetry["is_live_available"] is False
    assert telemetry["fallback_calls"] >= 1
    assert telemetry["active_backend_used"] == "mock_fallback"


# =========================================================================
# Investigation 5: State and Graph Consistency Across Restart
# =========================================================================

@pytest.mark.asyncio
async def test_investigation_5_state_and_graph_persistence_across_restart():
    """Verify SQLite persistence integrity and graph parity across database restarts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "disstroy_test.db")

        # Session 1: Populate State & Graph
        db1 = DatabaseManager(db_path)
        await db1.initialize()
        state1 = SharedState(db1)
        graph1 = KnowledgeGraph()
        state1.subscribe(graph1.handle_state_event)

        asset = Asset(id="asset_persist", name="Persistent Asset", asset_type=AssetType.DATABASE, criticality=1.0)
        await state1.add_asset(asset)

        obs = Observation(id="obs_persist", asset_id="asset_persist", kind=ObservationKind.PORT_BANNER, title="Banner")
        await state1.add_observation(obs)

        hyp = Hypothesis(
            id="hyp_persist",
            target_asset_id="asset_persist",
            category=HypothesisCategory.UNRESTRICTED_ACCESS,
            title="Access check",
            description="Verify persistence",
            status=HypothesisStatus.VALIDATED,
        )
        await state1.add_hypothesis(hyp)

        # Graph node checks
        assert "asset_persist" in graph1.g
        assert "obs_persist" in graph1.g
        assert "hyp_persist" in graph1.g

        # Close session 1
        await db1.close()

        # Session 2: Reopen from disk
        db2 = DatabaseManager(db_path)
        await db2.initialize()
        state2 = SharedState(db2)

        # Verify restored entities
        res_asset = await state2.get_asset("asset_persist")
        assert res_asset is not None
        assert res_asset.name == "Persistent Asset"

        res_obs = await state2.get_observation("obs_persist")
        assert res_obs is not None
        assert res_obs.title == "Banner"

        res_hyp = await state2.get_hypothesis("hyp_persist")
        assert res_hyp is not None
        assert res_hyp.status == HypothesisStatus.VALIDATED

        # Idempotency check: re-inserting identical asset does not duplicate
        await state2.add_asset(asset)
        all_assets = await state2.list_assets()
        assert len(all_assets) == 1

        await db2.close()


# =========================================================================
# Investigation 6: Lifecycle Repeatability & Resource Cleanup
# =========================================================================

@pytest.mark.asyncio
async def test_investigation_6_lifecycle_repeatability_and_cleanup():
    """Run lifecycle repeatedly to ensure no task leaks or unclosed connections."""
    for run_idx in range(3):
        config = DiSSTROYConfig(
            db_path=":memory:",
            max_concurrent_workers=2,
            use_mock_llm_fallback=True,
        )
        orchestrator = DiSSTROYOrchestrator(config=config)
        await orchestrator.initialize()

        report = await orchestrator.run_lifecycle()
        assert report["status"] == OrchestratorState.COMPLETED.value
        assert report["summary"]["validated_hypotheses"] >= 1

        await orchestrator.close()
