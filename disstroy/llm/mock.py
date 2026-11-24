"""Deterministic heuristic reasoning engine emulating LLM hypothesis generation and failure diagnosis."""

from typing import Any, Dict, List, Optional
from disstroy.llm.base import BaseLLMProvider
from disstroy.models.asset import Asset
from disstroy.models.enums import FailureCategory, HypothesisCategory, HypothesisStatus
from disstroy.models.failure import FailureLesson
from disstroy.models.hypothesis import Hypothesis, ProbeStep
from disstroy.models.observation import Observation


class MockLLMProvider(BaseLLMProvider):
    """Deterministic local reasoning provider for offline test suites and non-GPU environments."""

    def __init__(self, model_name: str = "mock:heuristic-v1"):
        self._model_name = model_name
        self.total_calls: int = 0
        self.successful_calls: int = 0

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return self._model_name

    async def is_available(self) -> bool:
        return True

    async def generate_text(self, prompt: str, system: Optional[str] = None) -> str:
        self.total_calls += 1
        self.successful_calls += 1
        return "Reasoning completed successfully."

    async def generate_hypotheses(
        self,
        asset: Asset,
        observations: List[Observation],
        active_lessons: List[FailureLesson],
    ) -> List[Hypothesis]:
        """Synthesize concrete hypotheses based on domain heuristics and observation patterns."""
        self.total_calls += 1
        hypotheses: List[Hypothesis] = []
        obs_ids = [o.id for o in observations]

        # 1. API Gateway Analysis
        if asset.id == "asset_api_gw":
            for obs in observations:
                if "debug" in obs.title.lower() or "upstream" in obs.title.lower():
                    step1 = ProbeStep(
                        action_type="check_debug_route",
                        parameters={"target_asset_id": asset.id, "path": "/debug/vars"},
                        expected_indicators=["upstreams", "uptime", "200"],
                        refuting_indicators=["404", "401", "403"],
                    )
                    hyp = Hypothesis(
                        id=f"hyp_{asset.id}_debug_exposure",
                        target_asset_id=asset.id,
                        category=HypothesisCategory.INFORMATION_DISCLOSURE,
                        title="Gateway exposes internal topology via unauthenticated /debug/vars",
                        description="Passive crawler noted X-Debug-Route. If /debug/vars is open, internal cluster routes are leaked.",
                        supporting_observation_ids=[obs.id],
                        prior_probability=0.75,
                        confidence=0.7,
                        priority_score=0.8,
                        status=HypothesisStatus.PROPOSED,
                        test_plan=[step1],
                        generated_by_provider="mock",
                        generated_by_model=self.model_name,
                        is_fallback=False,
                    )
                    hypotheses.append(hyp)

        # 2. Auth Service Analysis
        elif asset.id == "asset_auth_svc":
            # Check if an active lesson warns against token bypass
            bypass_penalized = any(
                (l.target_asset_id is None or l.target_asset_id == asset.id)
                and (l.affected_category is None or l.affected_category == HypothesisCategory.AUTH_BYPASS_RISK)
                for l in active_lessons
            )

            step_auth = ProbeStep(
                action_type="test_unsigned_token_bypass",
                parameters={"target_asset_id": asset.id, "path": "/auth/validate", "alg": "none"},
                expected_indicators=["200", "authenticated", "valid"],
                refuting_indicators=["401", "signature verification failed", "disallowed"],
            )
            initial_prio = 0.4 if bypass_penalized else 0.85
            hyp_auth = Hypothesis(
                id=f"hyp_{asset.id}_unsigned_token",
                target_asset_id=asset.id,
                category=HypothesisCategory.AUTH_BYPASS_RISK,
                title="Auth service permits signature bypass using 'none' algorithm token",
                description="Specification observation indicated support for 'none' algorithm. Testing whether verification is bypassed.",
                supporting_observation_ids=obs_ids,
                prior_probability=0.6,
                confidence=0.5,
                priority_score=initial_prio,
                status=HypothesisStatus.PROPOSED,
                test_plan=[step_auth],
                generated_by_provider="mock",
                generated_by_model=self.model_name,
                is_fallback=False,
            )
            hypotheses.append(hyp_auth)

        # 3. Admin Console Analysis
        elif asset.id == "asset_admin_portal":
            step_admin = ProbeStep(
                action_type="probe_unauthenticated_status",
                parameters={"target_asset_id": asset.id, "path": "/admin/status"},
                expected_indicators=["environment_dump", "db_pass", "200"],
                refuting_indicators=["401", "403", "404", "login required"],
            )
            hyp_admin = Hypothesis(
                id=f"hyp_{asset.id}_unauthenticated_env_dump",
                target_asset_id=asset.id,
                category=HypothesisCategory.CONFIGURATION_DEFECT,
                title="Legacy Admin exposes unauthenticated credentials dump on /admin/status",
                description="Observation reported configuration leak revealing internal status endpoint.",
                supporting_observation_ids=obs_ids,
                prior_probability=0.9,
                confidence=0.8,
                priority_score=0.95,
                status=HypothesisStatus.PROPOSED,
                test_plan=[step_admin],
                generated_by_provider="mock",
                generated_by_model=self.model_name,
                is_fallback=False,
            )
            hypotheses.append(hyp_admin)

        # 4. Database Cluster Analysis
        elif asset.id == "asset_db_cluster":
            step_db = ProbeStep(
                action_type="probe_direct_network_access",
                parameters={"target_asset_id": asset.id, "port": 5432},
                expected_indicators=["connected", "postgresql"],
                refuting_indicators=["connection refused", "403", "blocked"],
            )
            hyp_db = Hypothesis(
                id=f"hyp_{asset.id}_direct_db_exposure",
                target_asset_id=asset.id,
                category=HypothesisCategory.UNRESTRICTED_ACCESS,
                title="Database cluster allows unsegmented direct ingress from edge network",
                description="Verifying whether database enforces network isolation boundaries.",
                supporting_observation_ids=obs_ids,
                prior_probability=0.3,
                confidence=0.3,
                priority_score=0.4,
                status=HypothesisStatus.PROPOSED,
                test_plan=[step_db],
                generated_by_provider="mock",
                generated_by_model=self.model_name,
                is_fallback=False,
            )
            hypotheses.append(hyp_db)

        # 5. Generic analysis for custom/arbitrary assets
        if not hypotheses:
            step_gen = ProbeStep(
                action_type="inspect_service_endpoint",
                parameters={"target_asset_id": asset.id, "location": asset.network_location},
                expected_indicators=["200", "status", "ok"],
                refuting_indicators=["404", "error"],
            )
            hyp_gen = Hypothesis(
                id=f"hyp_{asset.id}_general_assessment",
                target_asset_id=asset.id,
                category=HypothesisCategory.CONFIGURATION_DEFECT,
                title=f"Configuration posture assessment for {asset.name}",
                description=f"Autonomous assessment targeting {asset.name} based on {len(observations)} observations.",
                supporting_observation_ids=obs_ids,
                prior_probability=0.6,
                confidence=0.5,
                priority_score=0.65,
                status=HypothesisStatus.PROPOSED,
                test_plan=[step_gen],
                generated_by_provider="mock",
                generated_by_model=self.model_name,
                is_fallback=False,
            )
            hypotheses.append(hyp_gen)

        self.successful_calls += 1
        return hypotheses

    async def diagnose_failure(
        self,
        hypothesis: Hypothesis,
        probe_output: Dict[str, Any],
    ) -> tuple[FailureCategory, str, float]:
        self.total_calls += 1
        status_code = probe_output.get("status_code", 0)
        body = str(probe_output.get("body", "")).lower()

        self.successful_calls += 1
        if "signature" in body or status_code == 401:
            return (
                FailureCategory.ACCESS_DENIED_HARD,
                "Strict cryptographic verification enforced; unsigned tokens rejected.",
                0.25,
            )
        if status_code == 429:
            return (
                FailureCategory.COUNTERMEASURE_DETECTED,
                "Rate limiter or defensive countermeasure triggered.",
                0.3,
            )
        return (
            FailureCategory.INVALID_PREMISE,
            "Negative probe outcome refuted hypothesis premise.",
            0.5,
        )

    def get_telemetry(self) -> Dict[str, Any]:
        return {
            "provider_name": self.provider_name,
            "model_name": self.model_name,
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "fallback_calls": 0,
            "is_live_backend": False,
        }
