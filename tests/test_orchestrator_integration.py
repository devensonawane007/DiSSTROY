"""End-to-end integration tests for DiSSTROY Orchestrator milestone."""

import pytest
from disstroy.config import DiSSTROYConfig
from disstroy.core.orchestrator import DiSSTROYOrchestrator
from disstroy.models.enums import HypothesisStatus, OrchestratorState


@pytest.mark.asyncio
async def test_full_autonomous_lifecycle():
    config = DiSSTROYConfig(
        db_path=":memory:",
        max_concurrent_workers=3,
        use_mock_llm_fallback=True,
    )

    orchestrator = DiSSTROYOrchestrator(config=config)
    await orchestrator.initialize()

    # Execute full lifecycle
    report = await orchestrator.run_lifecycle()

    assert report["status"] == OrchestratorState.COMPLETED.value
    summary = report["summary"]

    # Verify Assets
    assert summary["total_assets"] >= 4

    # Verify Observations (Initial + Dynamic mid-flight observation)
    assert summary["total_observations"] >= 4

    # Verify Hypotheses (multiple competing hypotheses tested)
    assert summary["total_hypotheses"] >= 3
    assert summary["validated_hypotheses"] >= 1
    assert summary["refuted_hypotheses"] >= 1

    # Verify Evidence Chain
    assert summary["total_evidence_records"] >= 3
    assert summary["audit_trail_events"] > 10

    # Verify Failure Intelligence & Learned Lessons
    assert summary["total_failures"] >= 1
    assert summary["active_lessons_learned"] >= 1

    # Verify dynamic observation arrived mid-execution
    assert orchestrator.runtime_events_injected is True

    # Verify NetworkX graph metrics
    graph_metrics = report["graph_metrics"]
    assert graph_metrics["total_nodes"] > 10
    assert graph_metrics["total_edges"] > 10
    assert "ASSET" in graph_metrics["nodes_by_type"]
    assert "HYPOTHESIS" in graph_metrics["nodes_by_type"]
    assert "OBSERVATION" in graph_metrics["nodes_by_type"]
    assert "EVIDENCE" in graph_metrics["nodes_by_type"]

    await orchestrator.close()
