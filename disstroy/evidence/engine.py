"""Evidence Engine for cryptographic verification, validation scoring, and hypothesis resolution."""

from typing import Any, Dict, List, Optional
from disstroy.models.enums import EvidenceType, HypothesisStatus
from disstroy.models.evidence import EvidenceRecord, compute_sha256
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.state.shared_state import SharedState


class EvidenceEngine:
    """Manages traceable evidence records, verification criteria, and hypothesis transitions."""

    def __init__(self, shared_state: SharedState):
        self.state = shared_state

    async def evaluate_probe_result(
        self,
        hypothesis: Hypothesis,
        step: ProbeStep,
        worker_id: str,
        probe_output: Dict[str, Any],
    ) -> tuple[EvidenceRecord, Hypothesis]:
        """Evaluate raw probe output against step criteria, generate EvidenceRecord, and update Hypothesis."""
        body = str(probe_output.get("body", ""))
        headers = probe_output.get("headers", {})
        status_code = probe_output.get("status_code", 0)

        # Build searchable string corpus from headers, body, status
        corpus = f"{status_code} {headers} {body}".lower()

        # Check positive indicators
        matched_expected = [ind for ind in step.expected_indicators if ind.lower() in corpus]
        matched_refuting = [ind for ind in step.refuting_indicators if ind.lower() in corpus]

        validation_score = (
            len(matched_expected) / len(step.expected_indicators) if step.expected_indicators else 0.0
        )
        falsification_score = (
            len(matched_refuting) / len(step.refuting_indicators) if step.refuting_indicators else 0.0
        )

        supports = validation_score > falsification_score and validation_score > 0.0

        interpretation = (
            f"Matched expected indicators: {matched_expected}. "
            f"Refuting indicators: {matched_refuting}."
        )

        evidence_type = EvidenceType.PROBE_RESPONSE
        if "header" in step.action_type:
            evidence_type = EvidenceType.HEADER_ANALYSIS
        elif "dump" in step.action_type or "config" in step.action_type:
            evidence_type = EvidenceType.CONFIGURATION_DUMP

        record = EvidenceRecord(
            hypothesis_id=hypothesis.id,
            step_id=step.step_id,
            worker_id=worker_id,
            evidence_type=evidence_type,
            raw_data=probe_output,
            content_hash=compute_sha256(probe_output),
            supports_hypothesis=supports,
            validation_power=validation_score,
            falsification_power=falsification_score,
            interpretation=interpretation,
        )

        # Persist evidence
        await self.state.add_evidence(record)

        # Update hypothesis confidence and state
        updated_hyp = await self._recalculate_hypothesis_status(hypothesis, record)
        return record, updated_hyp

    async def _recalculate_hypothesis_status(
        self, hypothesis: Hypothesis, latest_record: EvidenceRecord
    ) -> Hypothesis:
        """Fetch all evidence for hypothesis and dynamically resolve its status."""
        evidence_records = await self.state.list_evidence(hypothesis.id)

        supporting_power = sum(e.validation_power for e in evidence_records if e.supports_hypothesis)
        refuting_power = sum(e.falsification_power for e in evidence_records if not e.supports_hypothesis)

        total_weight = supporting_power + refuting_power + 1e-6
        new_confidence = max(0.0, min(1.0, supporting_power / total_weight))
        hypothesis.confidence = new_confidence

        if supporting_power >= 0.8 and refuting_power < 0.3:
            hypothesis.status = HypothesisStatus.VALIDATED
        elif refuting_power >= 0.7 or (supporting_power == 0.0 and len(evidence_records) >= len(hypothesis.test_plan)):
            hypothesis.status = HypothesisStatus.REFUTED
        else:
            hypothesis.status = HypothesisStatus.TESTING

        await self.state.update_hypothesis(hypothesis)
        return hypothesis
