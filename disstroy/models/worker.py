"""Models for swarm workers, tasks, and investigation outcomes."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import WorkerState
from disstroy.models.evidence import EvidenceRecord
from disstroy.models.failure import FailureRecord
from disstroy.models.hypothesis import ProbeStep


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class WorkerTask(BaseModel):
    """Assigned workload for a swarm worker."""

    task_id: str = Field(default_factory=lambda: f"task_{uuid4().hex[:8]}")
    hypothesis_id: str = Field(description="Target hypothesis ID")
    target_asset_id: str = Field(description="Asset to probe")
    steps: List[ProbeStep] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now_iso)


class WorkerResult(BaseModel):
    """Final output from a worker investigation run."""

    task_id: str
    worker_id: str
    hypothesis_id: str
    success: bool
    evidence_records: List[EvidenceRecord] = Field(default_factory=list)
    failure_record: Optional[FailureRecord] = Field(default=None)
    execution_time_ms: float = Field(default=0.0)
    start_time_epoch: float = Field(default=0.0, description="Epoch start timestamp for concurrency verification")
    end_time_epoch: float = Field(default=0.0, description="Epoch completion timestamp")
    stopped_early: bool = Field(default=False)
    was_canceled: bool = Field(default=False, description="True if canceled by swarm manager due to replanning")
    cancellation_reason: Optional[str] = Field(default=None)
    timestamp: str = Field(default_factory=_now_iso)


class WorkerInfo(BaseModel):
    """Runtime tracking record for a swarm worker."""

    worker_id: str
    state: WorkerState = Field(default=WorkerState.IDLE)
    current_hypothesis_id: Optional[str] = Field(default=None)
    tasks_completed: int = Field(default=0)
    spawned_at: str = Field(default_factory=_now_iso)
    last_heartbeat: str = Field(default_factory=_now_iso)
