"""Observation model representing raw and structured findings discovered in the environment."""

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import ObservationKind


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Observation(BaseModel):
    """A structured finding or telemetry record tied to an asset."""

    id: str = Field(default_factory=lambda: f"obs_{uuid4().hex[:10]}")
    asset_id: str = Field(description="Target asset ID this observation pertains to")
    kind: ObservationKind = Field(description="Classification of observation")
    title: str = Field(description="Short human-readable summary of the finding")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Structured attributes or payload")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in accuracy of this observation")
    source: str = Field(default="discovery_engine", description="Origin of the observation (e.g. initial_scan, dynamic_probe)")
    tags: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=_now_iso)
