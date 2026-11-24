"""Scenario loader and pre-packaged security benchmarks."""

from typing import Dict, Type
from disstroy.simulator.environment import SimulatedSecurityEnvironment


class BenchmarkScenario:
    """Descriptor for a repeatable benchmark suite."""

    def __init__(self, name: str, description: str, env_factory):
        self.name = name
        self.description = description
        self.env_factory = env_factory

    def create(self) -> SimulatedSecurityEnvironment:
        return self.env_factory()


def get_default_scenario() -> SimulatedSecurityEnvironment:
    """Return default multi-tier microservice environment."""
    return SimulatedSecurityEnvironment()
