"""Investigation Worker executing verifiable probe plans and reporting structured findings."""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from disstroy.evidence.engine import EvidenceEngine
from disstroy.intelligence.failure import FailureIntelligenceEngine
from disstroy.models.enums import HypothesisStatus, WorkerState
from disstroy.models.evidence import EvidenceRecord
from disstroy.models.hypothesis import Hypothesis
from disstroy.models.worker import WorkerInfo, WorkerResult
from disstroy.simulator.environment import SimulatedSecurityEnvironment
from disstroy.state.shared_state import SharedState

logger = logging.getLogger(__name__)


class InvestigationWorker:
    """Concurrent worker executing discrete probe plans against target systems."""

    def __init__(
        self,
        worker_id: str,
        shared_state: SharedState,
        evidence_engine: EvidenceEngine,
        failure_intelligence: FailureIntelligenceEngine,
        simulator: SimulatedSecurityEnvironment,
    ):
        self.worker_id = worker_id
        self.state = shared_state
        self.evidence_engine = evidence_engine
        self.failure_intel = failure_intelligence
        self.simulator = simulator

        self.info = WorkerInfo(worker_id=worker_id, state=WorkerState.IDLE)
        self._stop_event = asyncio.Event()
        self._current_task: Optional[asyncio.Task] = None

    def request_stop(self) -> None:
        """Signal worker to stop active investigation immediately."""
        self._stop_event.set()
        self.info.state = WorkerState.STOPPED

    async def execute_hypothesis(self, hypothesis: Hypothesis) -> WorkerResult:
        """Execute the probe plan for a hypothesis, evaluate evidence, and diagnose failures."""
        start_perf = time.perf_counter()
        start_epoch = time.time()
        self._stop_event.clear()
        self.info.state = WorkerState.RUNNING
        self.info.current_hypothesis_id = hypothesis.id

        hypothesis.status = HypothesisStatus.TESTING
        hypothesis.assigned_worker_id = self.worker_id
        await self.state.update_hypothesis(hypothesis)

        evidence_collected: List[EvidenceRecord] = []
        failure_record = None
        stopped_early = False

        try:
            for step in hypothesis.test_plan:
                if self._stop_event.is_set():
                    stopped_early = True
                    break

                # Execute probe against simulated target
                probe_output = await self.simulator.execute_probe(step.action_type, step.parameters)

                # Evaluate output against evidence criteria
                evidence, updated_hyp = await self.evidence_engine.evaluate_probe_result(
                    hypothesis=hypothesis,
                    step=step,
                    worker_id=self.worker_id,
                    probe_output=probe_output,
                )
                evidence_collected.append(evidence)

                # If probe produced refuting evidence or failure code, invoke Failure Intelligence
                if not evidence.supports_hypothesis:
                    failure_record = await self.failure_intel.diagnose_and_learn(
                        hypothesis=updated_hyp,
                        worker_id=self.worker_id,
                        probe_output=probe_output,
                        error_msg=f"Probe step '{step.action_type}' failed validation.",
                    )
                    # If hypothesis is definitively refuted, abort remaining plan steps
                    if updated_hyp.status == HypothesisStatus.REFUTED:
                        stopped_early = True
                        break

            self.info.tasks_completed += 1
            self.info.state = WorkerState.COMPLETED if not stopped_early else WorkerState.STOPPED

        except asyncio.CancelledError:
            stopped_early = True
            self.info.state = WorkerState.STOPPED
        except Exception as e:
            logger.error(f"Worker {self.worker_id} crashed during investigation: {e}", exc_info=True)
            self.info.state = WorkerState.FAILED
            failure_record = await self.failure_intel.diagnose_and_learn(
                hypothesis=hypothesis,
                worker_id=self.worker_id,
                probe_output={"exception": str(e)},
                error_msg=f"Worker exception: {e}",
            )

        finally:
            self.info.current_hypothesis_id = None
            elapsed_ms = (time.perf_counter() - start_perf) * 1000
            end_epoch = time.time()

        was_canceled = stopped_early
        cancellation_reason = "Canceled by swarm manager during dynamic replanning" if was_canceled else None

        return WorkerResult(
            task_id=f"run_{hypothesis.id}_{self.worker_id}",
            worker_id=self.worker_id,
            hypothesis_id=hypothesis.id,
            success=not stopped_early and self.info.state == WorkerState.COMPLETED,
            evidence_records=evidence_collected,
            failure_record=failure_record,
            execution_time_ms=elapsed_ms,
            start_time_epoch=start_epoch,
            end_time_epoch=end_epoch,
            stopped_early=stopped_early,
            was_canceled=was_canceled,
            cancellation_reason=cancellation_reason,
        )
