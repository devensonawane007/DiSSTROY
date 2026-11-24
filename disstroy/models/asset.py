"""Asset model representing entities in the target infrastructure."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import AccessLevel, AssetType


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Asset(BaseModel):
    """An identified network host, service, endpoint, or internal component."""

    id: str = Field(default_factory=lambda: f"asset_{uuid4().hex[:10]}")
    name: str = Field(description="Descriptive name or hostname of the asset")
    asset_type: AssetType = Field(default=AssetType.SERVICE)
    criticality: float = Field(default=0.5, ge=0.0, le=1.0, description="Criticality score from 0.0 (low) to 1.0 (mission critical)")
    network_location: str = Field(default="", description="IP, hostname, URL, or internal route identifier")
    current_access_level: AccessLevel = Field(default=AccessLevel.NONE, description="Current simulated access level achieved on this asset")
    is_canary_objective: bool = Field(default=False, description="True if asset hosts a critical canary objective/target")
    canary_description: Optional[str] = Field(default=None, description="Description of the canary flag or high-value data")
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)
