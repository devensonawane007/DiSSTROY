"""Discovery Engine for producing, ingesting, and streaming structured observations."""

import asyncio
from typing import List, Optional
from disstroy.models.asset import Asset
from disstroy.models.observation import Observation
from disstroy.state.shared_state import SharedState


class DiscoveryEngine:
    """Produces and manages environment observations, supporting streaming runtime telemetry."""

    def __init__(self, shared_state: SharedState):
        self.state = shared_state
        self._streaming_queue: asyncio.Queue[Observation] = asyncio.Queue()

    async def ingest_initial_observations(self, observations: List[Observation]) -> List[Observation]:
        """Bulk ingest initial baseline observations from environment scans."""
        for obs in observations:
            await self.state.add_observation(obs)
        return observations

    async def inject_runtime_observation(self, observation: Observation) -> None:
        """Inject a dynamic observation discovered during active investigation."""
        await self.state.add_observation(observation)
        await self._streaming_queue.put(observation)

    async def get_next_streamed_observation(self) -> Observation:
        """Await the next dynamically injected observation from the stream."""
        return await self._streaming_queue.get()

    def has_pending_streamed_observations(self) -> bool:
        """Check if any dynamic observations are queued."""
        return not self._streaming_queue.empty()
