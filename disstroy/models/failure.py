"""Failure intelligence models for tracking failed hypotheses and derived lessons."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from disstroy.models.enums import FailureCategory, HypothesisCategory


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FailureRecord(BaseModel):
    """Structured record of an unsuccessful investigation attempt or refuted premise."""

    id: str = Field(default_factory=lambda: f"fail_{uuid4().hex[:10]}")
    hypothesis_id: str = Field(description="Hypothesis that proved invalid or failed execution")
    worker_id: str = Field(description="Worker executing the task")
    failure_category: FailureCategory = Field(description="Diagnosed category of the failure")
    error_message: str = Field(description="Summary of the failure outcome")
    diagnostic_details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=_now_iso)


class FailureLesson(BaseModel):
    """Actionable negative heuristic or policy derived from failure intelligence."""

    id: str = Field(default_factory=lambda: f"lesson_{uuid4().hex[:10]}")
    source_failure_id: str = Field(description="ID of the failure record this lesson originated from")
    target_asset_id: Optional[str] = Field(default=None, description="Specific asset penalized, or None for global")
    affected_category: Optional[HypothesisCategory] = Field(default=None, description="Hypothesis category penalized")
    penalty_factor: float = Field(default=0.5, ge=0.0, le=1.0, description="Dampening factor on priority (0.0=total suppress, 1.0=no penalty)")
    rule_description: str = Field(description="Human/LLM readable rule describing what was learned")
    active: bool = Field(default=True)
    created_at: str = Field(default_factory=_now_iso)
