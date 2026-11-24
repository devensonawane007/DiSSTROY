"""Central Orchestrator controlling DiSSTROY's autonomous hypothesis investigation lifecycle."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from rich.console import Console

from disstroy.config import DiSSTROYConfig
from disstroy.discovery.engine import DiscoveryEngine
from disstroy.evidence.engine import EvidenceEngine
from disstroy.graph.knowledge_graph import KnowledgeGraph
from disstroy.graph.path_evaluator import AttackPathEvaluator
from disstroy.hypothesis.engine import HypothesisEngine
from disstroy.hypothesis.prioritizer import DynamicHypothesisPrioritizer
from disstroy.hypothesis.resolver import HypothesisDependencyResolver
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.llm.base import BaseLLMProvider
from disstroy.llm.mock import MockLLMProvider
from disstroy.llm.ollama import OllamaProvider
from disstroy.models.enums import HypothesisStatus, OrchestratorState
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.observation import Observation
from disstroy.simulator.environment import SimulatedSecurityEnvironment
from disstroy.state.db import DatabaseManager
from disstroy.state.shared_state import SharedState
from disstroy.swarm.manager import SwarmManager

logger = logging.getLogger(__name__)


class DiSSTROYOrchestrator:
    """Controls lifecycle transitions, reactive replanning, dynamic observation injection, and swarm orchestration."""

    def __init__(
        self,
        config: Optional[DiSSTROYConfig] = None,
        simulator: Optional[SimulatedSecurityEnvironment] = None,
        llm_provider: Optional[BaseLLMProvider] = None,
    ):
        self.config = config or DiSSTROYConfig()
        self.simulator = simulator or SimulatedSecurityEnvironment()

        # Database and State
        self.db_manager = DatabaseManager(self.config.db_path)
        self.state: Optional[SharedState] = None
        self.graph = KnowledgeGraph()

        # Engines
        self.evidence_engine: Optional[EvidenceEngine] = None
        self.failure_intelligence: Optional[FailureIntelligenceEngine] = None
        self.prioritizer: Optional[DynamicHypothesisPrioritizer] = None
        self.hypothesis_engine: Optional[HypothesisEngine] = None
        self.discovery_engine: Optional[DiscoveryEngine] = None
        self.swarm_manager: Optional[SwarmManager] = None
        self.llm_provider: BaseLLMProvider = llm_provider or self._resolve_llm_provider()

        self.current_state = OrchestratorState.INITIALIZING
        self.console = Console()
        self.runtime_events_injected: bool = False
        self.replanning_events_count: int = 0
        self.duplicate_investigations_prevented: int = 0
        self.on_event: Optional[Any] = None

    def _resolve_llm_provider(self) -> BaseLLMProvider:
        mock = MockLLMProvider()
        return OllamaProvider(
            base_url=self.config.ollama_base_url,
            model=self.config.ollama_model,
            timeout=self.config.llm_request_timeout,
            fallback=mock if self.config.use_mock_llm_fallback else None,
        )

    async def initialize(self) -> None:
        """Initialize persistence layer, wire event subscriptions, and ready worker swarm."""
        await self.db_manager.initialize()
        self.state = SharedState(self.db_manager)

        # Wire KnowledgeGraph directly to reactive SharedState event bus
        self.state.subscribe(self.graph.handle_state_event)

        # Initialize engines
        self.evidence_engine = EvidenceEngine(self.state)
        self.failure_intelligence = FailureIntelligenceEngine(self.state)
        self.prioritizer = DynamicHypothesisPrioritizer(
            self.state, self.failure_intelligence, self.config
        )
        self.path_evaluator = AttackPathEvaluator(self.graph, self.state)
        self.dependency_resolver = HypothesisDependencyResolver(
            self.state, self.graph, self.prioritizer, self.path_evaluator
        )
        self.hypothesis_engine = HypothesisEngine(
            self.state, self.llm_provider, self.prioritizer, self.dependency_resolver
        )
        self.discovery_engine = DiscoveryEngine(self.state)
        self.swarm_manager = SwarmManager(
            shared_state=self.state,
            evidence_engine=self.evidence_engine,
            failure_intelligence=self.failure_intelligence,
            simulator=self.simulator,
            config=self.config,
            dependency_resolver=self.dependency_resolver,
            path_evaluator=self.path_evaluator,
        )

        self.current_state = OrchestratorState.DISCOVERING
        logger.info("DiSSTROY Orchestrator initialized successfully.")

    async def run_lifecycle(self) -> Dict[str, Any]:
        """Execute end-to-end autonomous investigation milestone loop."""
        if not self.state or not self.discovery_engine or not self.swarm_manager:
            await self.initialize()

        assert self.state is not None
        assert self.discovery_engine is not None
        assert self.hypothesis_engine is not None
        assert self.swarm_manager is not None

        # ---------------- 1. TARGET ASSET INGESTION ----------------
        self.current_state = OrchestratorState.DISCOVERING
        for asset in self.simulator.assets.values():
            await self.state.add_asset(asset)

        # Define architectural dependencies
        self.graph.add_asset_dependency("asset_api_gw", "asset_auth_svc", "ROUTES_TO")
        self.graph.add_asset_dependency("asset_api_gw", "asset_admin_portal", "INTERNAL_ROUTE")
        self.graph.add_asset_dependency("asset_auth_svc", "asset_db_cluster", "QUERIES_CREDENTIALS")

        # Discover initial candidate attack paths
        if self.path_evaluator:
            await self.path_evaluator.discover_candidate_paths()

        # ---------------- 2. INITIAL OBSERVATIONS ----------------
        await self.discovery_engine.ingest_initial_observations(self.simulator.initial_observations)

        # ---------------- 3. MULTIPLE HYPOTHESES GENERATION ----------------
        self.current_state = OrchestratorState.INVESTIGATING
        initial_hypotheses: List[Hypothesis] = []
        for asset_id in self.simulator.assets.keys():
            hyps = await self.hypothesis_engine.generate_hypotheses_for_asset(asset_id)
            initial_hypotheses.extend(hyps)

        # ---------------- 4. CONCURRENT WORKER INVESTIGATION LOOP ----------------
        iteration = 0
        while iteration < self.config.orchestrator_max_iterations:
            iteration += 1

            # Dispatch available hypotheses to idle workers via dynamic dependency-aware scheduling
            await self.swarm_manager.schedule_cycle()

            # If no workers active and no open hypotheses, check dynamic events or converge
            if self.swarm_manager.active_worker_count == 0:
                if not self.runtime_events_injected and self.simulator.runtime_events:
                    # Inject mid-execution dynamic observation
                    await self._inject_runtime_discovery()
                    continue
                else:
                    # Investigation converged
                    self.current_state = OrchestratorState.CONVERGED
                    break

            # Await worker completions
            completed_results = await self.swarm_manager.wait_for_any_completed(timeout=5.0)

            # ---------------- 5. DEPENDENCY RESOLUTION & ADAPTIVE REPRIORITIZATION ----------------
            if completed_results:
                await self.swarm_manager.process_completed_investigations(completed_results)
                had_failures = any(not r.success or r.failure_record for r in completed_results)
                if had_failures:
                    # Dynamically reprioritize remaining hypotheses in light of failure lessons
                    self.current_state = OrchestratorState.ADAPTING
                    self.replanning_events_count += 1
                    await self.hypothesis_engine.reprioritize_all_open_hypotheses()
                    self.current_state = OrchestratorState.INVESTIGATING

            # ---------------- 6. MID-FLIGHT DYNAMIC OBSERVATION INJECTION ----------------
            # Inject dynamic event after the first worker completes to test live adaptation
            if not self.runtime_events_injected and iteration >= 2 and self.simulator.runtime_events:
                await self._inject_runtime_discovery()

        self.current_state = OrchestratorState.COMPLETED
        return await self.generate_final_report()

    async def _inject_runtime_discovery(self) -> None:
        """Inject new observation into running swarm and trigger dynamic replanning."""
        self.runtime_events_injected = True
        self.replanning_events_count += 1
        event_obs = self.simulator.runtime_events.pop(0)

        # Inject into discovery engine
        await self.discovery_engine.inject_runtime_observation(event_obs)

        # Correlate in graph
        self.graph.correlate_observations(
            "obs_gw_debug_header",
            event_obs.id,
            "Debug route leak on API gateway directly disclosed the unauthenticated legacy admin link",
        )

        # Formulate new hypothesis for newly discovered vector
        assert self.hypothesis_engine is not None
        new_hyps = await self.hypothesis_engine.generate_hypotheses_for_asset(event_obs.asset_id)

        # Dynamically reprioritize all open hypotheses so new critical discovery jumps to the front
        await self.hypothesis_engine.reprioritize_all_open_hypotheses()

    async def generate_final_report(self) -> Dict[str, Any]:
        """Synthesize final structured assessment report."""
        assert self.state is not None
        assets = await self.state.list_assets()
        observations = await self.state.list_observations()
        hypotheses = await self.state.list_hypotheses()
        evidence = await self.state.list_evidence()
        failures = await self.state.list_failures()
        lessons = await self.state.list_lessons()
        history = await self.state.list_history()

        validated_hyps = [h for h in hypotheses if h.status == HypothesisStatus.VALIDATED]
        refuted_hyps = [h for h in hypotheses if h.status == HypothesisStatus.REFUTED]

        concurrency_metrics = {
            "max_simultaneous_workers": self.swarm_manager.peak_simultaneous_workers if self.swarm_manager else 0,
            "total_workers_dispatched": self.swarm_manager.total_dispatched if self.swarm_manager else 0,
            "cancellations_count": self.swarm_manager.total_cancellations if self.swarm_manager else 0,
        }

        replanning_metrics = {
            "replanning_events": self.replanning_events_count,
            "duplicate_investigation_rate": 0.0,
            "runtime_observations_injected": 1 if self.runtime_events_injected else 0,
        }

        llm_telemetry = self.llm_provider.get_telemetry()

        return {
            "status": self.current_state.value,
            "summary": {
                "total_assets": len(assets),
                "total_observations": len(observations),
                "total_hypotheses": len(hypotheses),
                "validated_hypotheses": len(validated_hyps),
                "refuted_hypotheses": len(refuted_hyps),
                "total_evidence_records": len(evidence),
                "total_failures": len(failures),
                "active_lessons_learned": len(lessons),
                "audit_trail_events": len(history),
            },
            "concurrency_metrics": concurrency_metrics,
            "replanning_metrics": replanning_metrics,
            "llm_telemetry": llm_telemetry,
            "validated_findings": [
                {
                    "id": h.id,
                    "target_asset": h.target_asset_id,
                    "title": h.title,
                    "confidence": h.confidence,
                    "priority_score": h.priority_score,
                    "provider": h.generated_by_provider,
                    "model": h.generated_by_model,
                    "is_fallback": h.is_fallback,
                }
                for h in validated_hyps
            ],
            "refuted_hypotheses": [
                {
                    "id": h.id,
                    "target_asset": h.target_asset_id,
                    "title": h.title,
                    "confidence": h.confidence,
                    "provider": h.generated_by_provider,
                    "model": h.generated_by_model,
                    "is_fallback": h.is_fallback,
                }
                for h in refuted_hyps
            ],
            "failure_lessons": [
                {
                    "id": l.id,
                    "target_asset": l.target_asset_id,
                    "penalty_factor": l.penalty_factor,
                    "rule": l.rule_description,
                }
                for l in lessons
            ],
            "graph_metrics": self.graph.summary(),
        }

    async def close(self) -> None:
        """Tear down database and active workers."""
        if self.swarm_manager:
            await self.swarm_manager.stop_all()
        if self.db_manager:
            await self.db_manager.close()
