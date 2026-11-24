"""Swarm Manager coordinating concurrent workers and dynamic task scheduling."""

import asyncio
import logging
from typing import Dict, List, Optional, Set
from disstroy.config import DiSSTROYConfig
from disstroy.evidence.engine import EvidenceEngine
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.enums import WorkerState
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
    ):
        self.state = shared_state
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
