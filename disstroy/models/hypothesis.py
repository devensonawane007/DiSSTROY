"""Hypothesis model representing security propositions subjected to investigation."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import AccessLevel, HypothesisCategory, HypothesisStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProbeStep(BaseModel):
    """A discrete verifiable action in a hypothesis test plan."""

    step_id: str = Field(default_factory=lambda: f"step_{uuid4().hex[:8]}")
    action_type: str = Field(description="Action identifier matching simulator capabilities")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters passed to the probe")
    expected_indicators: List[str] = Field(default_factory=list, description="Keys or patterns that substantiate hypothesis")
    refuting_indicators: List[str] = Field(default_factory=list, description="Keys or patterns that refute hypothesis")


class Hypothesis(BaseModel):
    """An autonomous hypothesis formulated from observations."""

    id: str = Field(default_factory=lambda: f"hyp_{uuid4().hex[:10]}")
    target_asset_id: str = Field(description="Asset ID this hypothesis targets")
    category: HypothesisCategory = Field(description="Hypothesis security classification")
    title: str = Field(description="Brief premise of the hypothesis")
    description: str = Field(description="Comprehensive technical explanation")
    supporting_observation_ids: List[str] = Field(default_factory=list)
    refuting_observation_ids: List[str] = Field(default_factory=list)
    prerequisite_hypothesis_ids: List[str] = Field(default_factory=list, description="IDs of hypotheses that must be VALIDATED prior to execution")
    required_access_level: AccessLevel = Field(default=AccessLevel.NONE, description="Minimum simulated access level required")
    enables_access_level: Optional[AccessLevel] = Field(default=None, description="Access level granted if validated")
    stage: int = Field(default=1, description="Investigation stage / hop distance from perimeter")
    prior_probability: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    priority_score: float = Field(default=0.5, description="Dynamic prioritization metric")
    status: HypothesisStatus = Field(default=HypothesisStatus.PROPOSED)
    test_plan: List[ProbeStep] = Field(default_factory=list)
    assigned_worker_id: Optional[str] = Field(default=None)
    generated_by_provider: str = Field(default="unknown", description="Name of LLM provider (e.g. ollama, mock)")
    generated_by_model: str = Field(default="unknown", description="Model identifier used")
    is_fallback: bool = Field(default=False, description="True if generated via fallback mechanism")
    fallback_reason: Optional[str] = Field(default=None, description="Reason fallback was invoked")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_now_iso)
    updated_at: str = Field(default_factory=_now_iso)
