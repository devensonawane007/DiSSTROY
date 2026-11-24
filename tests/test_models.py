"""Tests for DiSSTROY data models."""

from disstroy.models.asset import Asset
from disstroy.models.enums import AssetType, EvidenceType, HypothesisCategory, HypothesisStatus, ObservationKind
from disstroy.models.evidence import EvidenceRecord, compute_sha256
from disstroy.models.failure import FailureLesson, FailureRecord
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.observation import Observation


def test_asset_model():
    asset = Asset(name="Auth Node", asset_type=AssetType.AUTH_PROVIDER, criticality=0.9)
    assert asset.id.startswith("asset_")
    assert asset.criticality == 0.9
    dump = asset.model_dump()
    assert dump["name"] == "Auth Node"


def test_evidence_sha256_integrity():
    raw_payload = {"status_code": 200, "token": "valid_mock_token"}
    hash_1 = compute_sha256(raw_payload)
    hash_2 = compute_sha256(raw_payload)
    assert hash_1 == hash_2
    assert len(hash_1) == 64  # SHA-256 hex string

    ev = EvidenceRecord(
        hypothesis_id="hyp_01",
        worker_id="w_01",
        evidence_type=EvidenceType.PROBE_RESPONSE,
        raw_data=raw_payload,
        supports_hypothesis=True,
    )
    assert ev.content_hash == hash_1


def test_hypothesis_model():
    step = ProbeStep(action_type="ping", parameters={"host": "127.0.0.1"})
    hyp = Hypothesis(
        target_asset_id="asset_test",
        category=HypothesisCategory.AUTH_BYPASS_RISK,
        title="Bypass risk",
        description="Testing auth bypass",
        test_plan=[step],
    )
    assert hyp.id.startswith("hyp_")
    assert hyp.status == HypothesisStatus.PROPOSED
    assert len(hyp.test_plan) == 1
