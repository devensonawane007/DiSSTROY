"""Swarm Manager coordinating concurrent workers and dynamic task scheduling."""

import asyncio
import logging
from typing import Dict, List, Optional, Set
from disstroy.config import DiSSTROYConfig
from disstroy.evidence.engine import EvidenceEngine
from disstroy.graph.path_evaluator import AttackPathEvaluator
from disstroy.hypothesis.resolver import HypothesisDependencyResolver
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.enums import HypothesisStatus, PathStatus, WorkerState
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.worker import WorkerInfo, WorkerResult
from disstroy.simulator.environment import SimulatedSecurityEnvironment
from disstroy.state.shared_state import SharedState
from disstroy.swarm.worker import InvestigationWorker

logger = logging.getLogger(__name__)


class SwarmManager:
    """Manages worker pool, hypothesis dispatch, concurrency throttling, and mid-flight cancellations."""

    def __init__(
        self,
        shared_state: SharedState,
        evidence_engine: EvidenceEngine,
        failure_intelligence: FailureIntelligenceEngine,
        simulator: SimulatedSecurityEnvironment,
        config: DiSSTROYConfig,
        dependency_resolver: Optional[HypothesisDependencyResolver] = None,
        path_evaluator: Optional[AttackPathEvaluator] = None,
    ):
        self.state = shared_state
        self.evidence_engine = evidence_engine
        self.failure_intel = failure_intelligence
        self.simulator = simulator
        self.max_workers = config.max_concurrent_workers
        self.dependency_resolver = dependency_resolver or HypothesisDependencyResolver(self.state)
        self.path_evaluator = path_evaluator
        self.evidence_engine = evidence_engine
        self.failure_intel = failure_intelligence
        self.simulator = simulator
        self.max_workers = config.max_concurrent_workers

        self.workers: Dict[str, InvestigationWorker] = {}
        self.active_tasks: Dict[str, asyncio.Task] = {}  # hypothesis_id -> Task
        self.task_to_hyp: Dict[asyncio.Task, str] = {}
        self._results: List[WorkerResult] = []
        self.peak_simultaneous_workers: int = 0
        self.total_dispatched: int = 0
        self.total_cancellations: int = 0

        # Pre-initialize worker instances
        for i in range(self.max_workers):
            wid = f"worker_{i + 1:02d}"
            self.workers[wid] = InvestigationWorker(
                worker_id=wid,
                shared_state=self.state,
                evidence_engine=self.evidence_engine,
                failure_intelligence=self.failure_intel,
                simulator=self.simulator,
            )

    @property
    def active_worker_count(self) -> int:
        """Count of currently executing tasks."""
        return len(self.active_tasks)

    def has_available_capacity(self) -> bool:
        """Check if concurrency limits permit dispatching another worker."""
        return self.active_worker_count < self.max_workers

    def get_idle_worker(self) -> Optional[InvestigationWorker]:
        """Find an idle worker instance."""
        for worker in self.workers.values():
            if worker.info.state in (WorkerState.IDLE, WorkerState.COMPLETED, WorkerState.STOPPED):
                return worker
        return None

    def dispatch_hypothesis(self, hypothesis: Hypothesis) -> Optional[asyncio.Task]:
        """Assign hypothesis to an available worker and launch background task."""
        # Enforce prerequisite eligibility gate: never dispatch blocked or pending hypotheses
        if hypothesis.status == HypothesisStatus.PENDING or hypothesis.metadata.get("is_blocked"):
            logger.info("Hypothesis %s is PENDING or blocked by unmet prerequisites; skipping dispatch.", hypothesis.id)
            return None

        # Prevent duplicate concurrent dispatch
        if hypothesis.id in self.active_tasks:
            logger.info("Hypothesis %s is already actively executing; duplicate dispatch prevented.", hypothesis.id)
            return None

        if not self.has_available_capacity():
            return None

        worker = self.get_idle_worker()
        if not worker:
            return None

        worker.info.current_hypothesis_id = hypothesis.id
        worker.info.state = WorkerState.RUNNING
        task = asyncio.create_task(worker.execute_hypothesis(hypothesis))
        self.active_tasks[hypothesis.id] = task
        self.task_to_hyp[task] = hypothesis.id
        self.total_dispatched += 1
        self.peak_simultaneous_workers = max(self.peak_simultaneous_workers, len(self.active_tasks))
        return task

    async def evaluate_scheduling_candidates(self) -> List[Hypothesis]:
        """
        Evaluate and rank all hypotheses for scheduling eligibility.
        Considers status, dependency eligibility, blocked state, priority, path relevance,
        expected information gain, and prevents duplicate active dispatches.
        """
        all_hyps = await self.state.list_hypotheses()
        active_ids = set(self.active_tasks.keys())

        # Exclude terminal and already running hypotheses
        open_candidates = [
            h for h in all_hyps
            if h.status not in (HypothesisStatus.VALIDATED, HypothesisStatus.REFUTED, HypothesisStatus.ABANDONED)
            and h.id not in active_ids
        ]

        eligible_candidates: List[Hypothesis] = []
        for hyp in open_candidates:
            # 1. Dependency and prerequisite evaluation
            if self.dependency_resolver:
                resolution = await self.dependency_resolver.resolve_dependencies(hyp)
                if resolution.is_blocked:
                    if hyp.status != HypothesisStatus.PENDING:
                        hyp.status = HypothesisStatus.PENDING
                        hyp.metadata["is_blocked"] = True
                        hyp.metadata["blocking_reason"] = resolution.blocking_reason
                        await self.state.update_hypothesis(hyp)
                    continue
                else:
                    if hyp.status == HypothesisStatus.PENDING:
                        hyp.status = HypothesisStatus.PROPOSED
                        hyp.metadata["is_blocked"] = False
                        hyp.metadata.pop("blocking_reason", None)
                        await self.state.update_hypothesis(hyp)

            # 2. Path relevance bonus (e.g. canary target or active attack path)
            relevance_boost = 0.0
            if self.path_evaluator:
                paths = await self.state.list_attack_paths()
                for p in paths:
                    if hyp.id in p.hypothesis_sequence:
                        if p.canary_target:
                            relevance_boost = max(relevance_boost, 0.15)
                        elif p.path_status in (PathStatus.FEASIBLE, PathStatus.THEORETICAL):
                            relevance_boost = max(relevance_boost, 0.08)

            # 3. Information gain bonus from supporting observation density
            info_gain = min(0.05, len(hyp.supporting_observation_ids) * 0.02)

            effective_score = round(min(1.0, hyp.priority_score + relevance_boost + info_gain), 4)
            hyp.metadata["scheduling_score"] = effective_score
            eligible_candidates.append(hyp)

        # Sort descending by effective scheduling score, fallback to priority_score
        eligible_candidates.sort(
            key=lambda h: (h.metadata.get("scheduling_score", h.priority_score), h.priority_score),
            reverse=True,
        )
        return eligible_candidates

    async def schedule_cycle(self) -> List[asyncio.Task]:
        """
        Run an autonomous scheduling cycle:
        Evaluates candidate hypotheses, enforces dependency eligibility, and dispatches to idle workers.
        """
        if not self.has_available_capacity():
            return []

        candidates = await self.evaluate_scheduling_candidates()
        dispatched_tasks: List[asyncio.Task] = []

        for hyp in candidates:
            if not self.has_available_capacity():
                break
            hyp.status = HypothesisStatus.QUEUED
            await self.state.update_hypothesis(hyp)
            task = self.dispatch_hypothesis(hyp)
            if task:
                dispatched_tasks.append(task)

        return dispatched_tasks

    async def process_completed_investigations(self, completed_results: List[WorkerResult]) -> None:
        """Process completed investigation results: unlock dependent hypotheses on validation, block on refutation."""
        for r in completed_results:
            hyp = await self.state.get_hypothesis(r.hypothesis_id)
            if not hyp:
                continue
            if hyp.status == HypothesisStatus.VALIDATED:
                if self.dependency_resolver:
                    await self.dependency_resolver.evaluate_and_unlock_dependent_hypotheses(hyp.id)
            elif hyp.status in (HypothesisStatus.REFUTED, HypothesisStatus.ABANDONED):
                if self.dependency_resolver:
                    await self.dependency_resolver.evaluate_and_block_dependent_hypotheses(hyp.id)

    def stop_investigation(self, hypothesis_id: str) -> bool:
        """Request immediate cessation of a running investigation due to superseding evidence."""
        task = self.active_tasks.get(hypothesis_id)
        if not task or task.done():
            return False

        # Find worker assigned to this hypothesis
        for worker in self.workers.values():
            if worker.info.current_hypothesis_id == hypothesis_id:
                worker.request_stop()
                task.cancel()
                self.total_cancellations += 1
                logger.info(f"Signaled worker {worker.worker_id} to halt investigation of {hypothesis_id}")
                return True

        task.cancel()
        self.total_cancellations += 1
        return True

    async def wait_for_any_completed(self, timeout: Optional[float] = None) -> List[WorkerResult]:
        """Wait until at least one worker task completes, clean up bookkeeping, and return results."""
        if not self.active_tasks:
            return []

        done, pending = await asyncio.wait(
            self.active_tasks.values(), return_when=asyncio.FIRST_COMPLETED, timeout=timeout
        )

        completed_results: List[WorkerResult] = []
        for task in done:
            hyp_id = self.task_to_hyp.pop(task, None)
            if hyp_id and hyp_id in self.active_tasks:
                del self.active_tasks[hyp_id]

            try:
                res = task.result()
                if isinstance(res, WorkerResult):
                    completed_results.append(res)
                    self._results.append(res)
            except asyncio.CancelledError:
                res = WorkerResult(
                    task_id=f"run_{hyp_id}_canceled",
                    worker_id="canceled",
                    hypothesis_id=hyp_id or "unknown",
                    success=False,
                    stopped_early=True,
                    was_canceled=True,
                    cancellation_reason="Task was canceled by swarm manager",
                )
                completed_results.append(res)
                self._results.append(res)
            except Exception as e:
                logger.error(f"Task for {hyp_id} raised unhandled exception: {e}")

        return completed_results

    async def stop_all(self) -> None:
        """Stop all running workers cleanly."""
        for worker in self.workers.values():
            worker.request_stop()

        if self.active_tasks:
            await asyncio.gather(*self.active_tasks.values(), return_exceptions=True)
            self.active_tasks.clear()
            self.task_to_hyp.clear()

    def get_all_worker_statuses(self) -> List[WorkerInfo]:
        """Get live status snapshot of all workers."""
        return [w.info for w in self.workers.values()]
