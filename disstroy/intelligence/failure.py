"""Failure Intelligence subsystem for analyzing failed investigations and deriving learning penalties."""

from typing import Any, Dict, List, Optional
from disstroy.models.enums import FailureCategory, HypothesisCategory
from disstroy.models.failure import FailureLesson, FailureRecord
from disstroy.models.hypothesis import Hypothesis
from disstroy.state.shared_state import SharedState


class FailureIntelligenceEngine:
    """Diagnoses unsuccessful investigations and produces adaptive penalties."""

    def __init__(self, shared_state: SharedState):
        self.state = shared_state

    async def diagnose_and_learn(
        self,
        hypothesis: Hypothesis,
        worker_id: str,
        probe_output: Dict[str, Any],
        error_msg: Optional[str] = None,
    ) -> FailureRecord:
        """Analyze a probe failure or refuted hypothesis, record failure, and generate lessons."""
        # 1. Categorize failure
        category, explanation, penalty, rule_desc = self._classify_failure(hypothesis, probe_output, error_msg)

        failure_record = FailureRecord(
            hypothesis_id=hypothesis.id,
            worker_id=worker_id,
            failure_category=category,
            error_message=explanation,
            diagnostic_details=probe_output,
        )
        await self.state.add_failure(failure_record)

        # 2. Formulate and record lesson
        lesson = FailureLesson(
            source_failure_id=failure_record.id,
            target_asset_id=hypothesis.target_asset_id,
            affected_category=hypothesis.category,
            penalty_factor=penalty,
            rule_description=rule_desc,
            active=True,
        )
        await self.state.add_lesson(lesson)

        return failure_record

    def _classify_failure(
        self, hypothesis: Hypothesis, output: Dict[str, Any], error_msg: Optional[str]
    ) -> tuple[FailureCategory, str, float, str]:
        status_code = output.get("status_code", 0)
        body = str(output.get("body", "")).lower()
        headers = {str(k).lower(): str(v).lower() for k, v in output.get("headers", {}).items()}

        if error_msg and "timeout" in error_msg.lower():
            return (
                FailureCategory.PROBE_TIMEOUT,
                f"Probe timed out against asset {hypothesis.target_asset_id}: {error_msg}",
                0.6,
                f"Asset {hypothesis.target_asset_id} experiences network latency or blackholing on probed routes.",
            )

        if status_code == 429 or "rate limit" in body or "blocked by waf" in body:
            return (
                FailureCategory.COUNTERMEASURE_DETECTED,
                "Active countermeasure or rate-limiter engaged.",
                0.3,
                f"Active defense / rate-limiting detected on {hypothesis.target_asset_id}. Deprioritize aggressive probes.",
            )

        if status_code in (401, 403):
            if "signature" in body or "hmac" in body:
                return (
                    FailureCategory.ACCESS_DENIED_HARD,
                    "Cryptographic signature check enforced by endpoint.",
                    0.25,
                    f"Asset {hypothesis.target_asset_id} strictly verifies token signatures. Falsified bypass vectors penalized.",
                )
            return (
                FailureCategory.ACCESS_DENIED_HARD,
                f"Access strictly forbidden (HTTP {status_code}).",
                0.4,
                f"Rigid authorization boundary detected on {hypothesis.target_asset_id}.",
            )

        if status_code == 404:
            return (
                FailureCategory.INVALID_PREMISE,
                "Probed endpoint or resource not found (HTTP 404).",
                0.35,
                f"Premise that asset {hypothesis.target_asset_id} hosts probed route proved false.",
            )

        if "patched" in body or "fixed" in body:
            return (
                FailureCategory.PATCH_VERIFIED,
                "Endpoint verified as remediated/patched against hypothesized vulnerability.",
                0.1,
                f"Patch verified on {hypothesis.target_asset_id} for {hypothesis.category.value}. Suppress related hypotheses.",
            )

        return (
            FailureCategory.INVALID_PREMISE,
            error_msg or "Probe outcome did not meet validation criteria; premise refuted.",
            0.5,
            f"Hypothesis {hypothesis.title} refuted by negative probe evidence on {hypothesis.target_asset_id}.",
        )

    async def compute_penalty_multiplier(self, hypothesis: Hypothesis) -> float:
        """Compute the cumulative penalty multiplier for a hypothesis based on active lessons."""
        lessons = await self.state.list_lessons(active_only=True)
        multiplier = 1.0

        for lesson in lessons:
            # Check if lesson matches target asset and/or category
            asset_match = lesson.target_asset_id is None or lesson.target_asset_id == hypothesis.target_asset_id
            cat_match = lesson.affected_category is None or lesson.affected_category == hypothesis.category

            if asset_match and cat_match:
                # Apply penalty factor (compounded with a lower bound floor of 0.05)
                multiplier *= lesson.penalty_factor

        return max(multiplier, 0.05)
