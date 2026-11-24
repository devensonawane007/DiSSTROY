"""Tests for LLM providers (MockLLMProvider and Ollama fallback)."""

import pytest
from disstroy.llm.mock import MockLLMProvider
from disstroy.llm.ollama import OllamaProvider
from disstroy.models.asset import Asset
from disstroy.models.enums import AssetType, ObservationKind
from disstroy.models.observation import Observation


@pytest.mark.asyncio
async def test_mock_llm_hypothesis_generation():
    mock = MockLLMProvider()
    assert await mock.is_available() is True

    asset = Asset(id="asset_api_gw", name="API Gateway", asset_type=AssetType.API_GATEWAY)
    obs = Observation(
        asset_id=asset.id,
        kind=ObservationKind.HTTP_HEADER,
        title="Debug route X-Debug-Route: /debug/vars exposed",
    )

    hyps = await mock.generate_hypotheses(asset, [obs], [])
    assert len(hyps) == 1
    assert "debug" in hyps[0].title.lower()
    assert len(hyps[0].test_plan) == 1


@pytest.mark.asyncio
async def test_ollama_fallback_to_mock():
    # Configure Ollama with invalid port to test transparent fallback
    mock = MockLLMProvider()
    ollama = OllamaProvider(
        base_url="http://localhost:59999",  # unreachable port
        model="nonexistent:model",
        fallback=mock,
    )

    assert await ollama.is_available() is False

    asset = Asset(id="asset_api_gw", name="API Gateway", asset_type=AssetType.API_GATEWAY)
    obs = Observation(
        asset_id=asset.id,
        kind=ObservationKind.HTTP_HEADER,
        title="Debug route X-Debug-Route: /debug/vars exposed",
    )

    hyps = await ollama.generate_hypotheses(asset, [obs], [])
    assert len(hyps) == 1
    assert hyps[0].target_asset_id == "asset_api_gw"
