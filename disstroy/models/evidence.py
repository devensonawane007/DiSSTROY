"""Evidence model representing traceable, verifiable investigation findings."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import EvidenceType


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_sha256(payload: Any) -> str:
    """Compute deterministic SHA-256 checksum of arbitrary payload."""
    try:
        serialized = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        serialized = str(payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class EvidenceRecord(BaseModel):
    """An immutable, cryptographically verifiable record of investigation evidence."""

    id: str = Field(default_factory=lambda: f"ev_{uuid4().hex[:10]}")
    hypothesis_id: str = Field(description="Hypothesis tested by this evidence")
    step_id: Optional[str] = Field(default=None, description="Probe step ID that yielded this evidence")
    worker_id: str = Field(description="Worker ID that gathered the evidence")
    evidence_type: EvidenceType = Field(default=EvidenceType.PROBE_RESPONSE)
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw response payload or telemetry")
    content_hash: str = Field(default="", description="Cryptographic SHA-256 digest of raw_data")
    supports_hypothesis: bool = Field(description="True if evidence validates hypothesis; False if it refutes")
    validation_power: float = Field(default=0.0, ge=0.0, le=1.0, description="Strength of validation signal (0.0-1.0)")
    falsification_power: float = Field(default=0.0, ge=0.0, le=1.0, description="Strength of falsification signal (0.0-1.0)")
    interpretation: str = Field(default="", description="Structured reasoning regarding the outcome")
    timestamp: str = Field(default_factory=_now_iso)

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash:
            self.content_hash = compute_sha256(self.raw_data)
