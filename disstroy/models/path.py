"""Data model representing multi-stage attack paths and relationship sequences."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import PathRisk, PathStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackPath(BaseModel):
    """A modeled multi-stage progression sequence from an entrypoint to an objective."""

    path_id: str = Field(default_factory=lambda: f"path_{uuid4().hex[:8]}")
    name: str = Field(description="Descriptive name of the multi-stage path")
    source_asset_id: str = Field(description="Initial entrypoint asset")
    target_asset_id: str = Field(description="Ultimate target or canary objective asset")
    asset_sequence: List[str] = Field(default_factory=list, description="Ordered asset IDs traversed along the path")
    hypothesis_sequence: List[str] = Field(default_factory=list, description="Ordered hypothesis IDs forming the dependency chain")
    path_status: PathStatus = Field(default=PathStatus.THEORETICAL, description="Current verification state of the path")
    path_confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Aggregate confidence score along the path")
    path_uncertainty: float = Field(default=1.0, ge=0.0, le=1.0, description="Epistemic uncertainty regarding unverified steps")
    risk_level: PathRisk = Field(default=PathRisk.MEDIUM, description="Calculated threat impact")
    is_cycle_detected: bool = Field(default=False, description="True if cyclic loops exist in the trajectory")
    blocked_step_id: Optional[str] = Field(default=None, description="Hypothesis ID that refuted/blocked the path")
    canary_target: Optional[str] = Field(default=None, description="Canary identifier or flag targeted by this path")
    description: str = Field(default="", description="Technical narrative of the multi-hop trajectory")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    updated_at: str = Field(default_factory=_now_iso)
