"""Tests for SimulatedSecurityEnvironment."""

import pytest
from disstroy.simulator.environment import SimulatedSecurityEnvironment


@pytest.mark.asyncio
async def test_simulator_responses():
    sim = SimulatedSecurityEnvironment()
    assert "asset_api_gw" in sim.assets
    assert len(sim.initial_observations) >= 3

    # Test API Gateway debug route probe
    res = await sim.execute_probe(
        action_type="check_debug_route",
        parameters={"target_asset_id": "asset_api_gw", "path": "/debug/vars"},
    )
    assert res["status_code"] == 200
    assert "upstreams" in res["body"]

    # Test Auth service unsigned token failure
    res_auth = await sim.execute_probe(
        action_type="test_unsigned_token_bypass",
        parameters={"target_asset_id": "asset_auth_svc", "path": "/auth/validate", "alg": "none"},
    )
    assert res_auth["status_code"] == 401
    assert "Signature verification failed" in res_auth["body"]

    # Test Legacy Admin unauthenticated status leak
    res_admin = await sim.execute_probe(
        action_type="probe_unauthenticated_status",
        parameters={"target_asset_id": "asset_admin_portal", "path": "/admin/status"},
    )
    assert res_admin["status_code"] == 200
    assert "DB_PASS" in res_admin["body"]
