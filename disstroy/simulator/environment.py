"""Simulated Security Environment for repeatable hypothesis benchmarks and test scenarios."""

import asyncio
from typing import Any, Dict, List, Optional
from disstroy.models.asset import Asset
from disstroy.models.enums import AssetType, ObservationKind
from disstroy.models.observation import Observation


class SimulatedSecurityEnvironment:
    """Provides a synthetic target environment modeling microservice network topology and security defects."""

    def __init__(self):
        self.assets: Dict[str, Asset] = {}
        self.initial_observations: List[Observation] = []
        self.runtime_events: List[Observation] = []
        self.request_counts: Dict[str, int] = {}
        self._setup_default_scenario()

    def _setup_default_scenario(self) -> None:
        """Construct a realistic multi-service enterprise target landscape."""
        # 1. Assets
        gw = Asset(
            id="asset_api_gw",
            name="Public Edge Gateway",
            asset_type=AssetType.API_GATEWAY,
            criticality=0.7,
            network_location="https://api.internal-corp.local",
            tags=["edge", "public", "reverse-proxy"],
        )
        auth = Asset(
            id="asset_auth_svc",
            name="Authentication & Identity Service",
            asset_type=AssetType.AUTH_PROVIDER,
            criticality=0.95,
            network_location="http://auth-svc.cluster.local:8081",
            tags=["internal", "pki", "tokens"],
        )
        admin = Asset(
            id="asset_admin_portal",
            name="Legacy Admin Console",
            asset_type=AssetType.SERVICE,
            criticality=0.85,
            network_location="http://admin-console.cluster.local:8888",
            tags=["internal", "legacy", "management"],
        )
        db = Asset(
            id="asset_db_cluster",
            name="Enterprise Customer DB",
            asset_type=AssetType.DATABASE,
            criticality=1.0,
            network_location="postgres://db.cluster.local:5432",
            tags=["database", "pci-dss", "isolated"],
        )

        self.assets = {
            gw.id: gw,
            auth.id: auth,
            admin.id: admin,
            db.id: db,
        }

        # 2. Initial Discovery Observations
        self.initial_observations = [
            Observation(
                id="obs_gw_banner",
                asset_id=gw.id,
                kind=ObservationKind.PORT_BANNER,
                title="Edge Gateway exposes Nginx reverse-proxy on port 443",
                raw_payload={"port": 443, "banner": "nginx/1.24.0 (Ubuntu)", "tls": "TLSv1.3"},
                confidence=1.0,
                source="port_scanner",
            ),
            Observation(
                id="obs_gw_debug_header",
                asset_id=gw.id,
                kind=ObservationKind.HTTP_HEADER,
                title="Gateway header exposes upstream route 'X-Upstream-Service: auth-svc'",
                raw_payload={"X-Upstream-Service": "auth-svc", "X-Debug-Route": "/debug/vars"},
                confidence=0.9,
                source="passive_crawler",
            ),
            Observation(
                id="obs_auth_token_scheme",
                asset_id=auth.id,
                kind=ObservationKind.AUTH_SCHEME,
                title="Auth service signs RS256 and legacy HS256 tokens",
                raw_payload={"supported_algs": ["RS256", "none", "HS256"], "jwks_uri": "/auth/jwks"},
                confidence=0.85,
                source="spec_analyzer",
            ),
        ]

        # 3. Dynamic observations that arrive mid-execution
        self.runtime_events = [
            Observation(
                id="obs_dynamic_admin_leak",
                asset_id=admin.id,
                kind=ObservationKind.CONFIG_LEAK,
                title="Runtime Event: Internal metrics route /debug/vars exposed legacy admin link",
                raw_payload={
                    "discovered_url": "http://admin-console.cluster.local:8888/admin/status",
                    "contains_env_dump": True,
                    "exposed_secret": "DB_ROOT_CREDENTIAL_BACKUP",
                },
                confidence=0.98,
                source="runtime_discovery_stream",
            )
        ]

    async def execute_probe(self, action_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate execution of an investigative probe with realistic behavior."""
        await asyncio.sleep(0.04)  # Simulate network latency

        target_id = parameters.get("target_asset_id", "")
        path = parameters.get("path", "/")
        headers = parameters.get("headers", {})

        # Key for rate-limiting
        key = f"{target_id}:{path}"
        self.request_counts[key] = self.request_counts.get(key, 0) + 1

        # Check rate-limiting countermeasure
        if self.request_counts[key] > 4 and parameters.get("trigger_ratelimit", False):
            return {
                "status_code": 429,
                "headers": {"Retry-After": "60", "X-Defense": "ActiveRateLimiter"},
                "body": "Rate limit exceeded. Blocked by defensive shield.",
                "elapsed_ms": 42.0,
            }

        # 1. API Gateway Probes
        if target_id == "asset_api_gw":
            if action_type == "check_debug_route" or path == "/debug/vars":
                return {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json", "X-Debug": "Active"},
                    "body": '{"uptime": 45021, "upstreams": ["auth-svc.cluster.local:8081", "admin-console.cluster.local:8888"]}',
                    "elapsed_ms": 38.0,
                }
            if action_type == "test_http_headers":
                return {
                    "status_code": 200,
                    "headers": {
                        "Server": "nginx/1.24.0",
                        "X-Debug-Route": "/debug/vars",
                        "Access-Control-Allow-Origin": "*",
                    },
                    "body": "<html><body>Default Gateway Page</body></html>",
                    "elapsed_ms": 35.0,
                }

        # 2. Auth Service Probes
        if target_id == "asset_auth_svc":
            if action_type == "test_unsigned_token_bypass":
                # Simulated hardened check: strict HMAC signature validation fails
                token_alg = parameters.get("alg", "none")
                if token_alg == "none":
                    return {
                        "status_code": 401,
                        "headers": {"WWW-Authenticate": 'Bearer error="invalid_token"'},
                        "body": "Signature verification failed: 'none' algorithm is strictly disallowed.",
                        "elapsed_ms": 45.0,
                    }
            if action_type == "check_jwks_configuration":
                return {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256"}]}',
                    "elapsed_ms": 40.0,
                }

        # 3. Legacy Admin Console Probes
        if target_id == "asset_admin_portal":
            if action_type == "probe_unauthenticated_status" or path == "/admin/status":
                return {
                    "status_code": 200,
                    "headers": {"Content-Type": "text/plain", "X-Service": "Legacy-Admin"},
                    "body": "ENVIRONMENT_DUMP: DB_HOST=db.cluster.local DB_USER=admin DB_PASS=UnsafeSecret123!",
                    "elapsed_ms": 48.0,
                }
            if action_type == "probe_admin_login":
                return {
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": "<form action='/admin/login' method='POST'>Enter Master Password</form>",
                    "elapsed_ms": 41.0,
                }

        # 4. Database Cluster Probes
        if target_id == "asset_db_cluster":
            if action_type == "probe_direct_network_access":
                return {
                    "status_code": 403,
                    "headers": {"X-Firewall": "Egress-Restricted"},
                    "body": "Connection refused: direct database ports blocked by network boundary policy.",
                    "elapsed_ms": 50.0,
                }

        # Fallback default
        return {
            "status_code": 404,
            "headers": {},
            "body": f"Endpoint {path} not found on {target_id}.",
            "elapsed_ms": 30.0,
        }
