"""Configuration management for DiSSTROY."""

from pathlib import Path
from pydantic import BaseModel, Field


class DiSSTROYConfig(BaseModel):
    """Configuration options for DiSSTROY execution."""

    # Persistence
    db_path: str = Field(default=":memory:", description="SQLite database path or :memory:")

    # Swarm & Concurrency
    max_concurrent_workers: int = Field(default=3, description="Max concurrent investigation workers")
    worker_timeout_seconds: float = Field(default=15.0, description="Timeout for a single probe execution")
    orchestrator_max_iterations: int = Field(default=20, description="Max orchestrator loop iterations")

    # LLM Settings
    ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL")
    ollama_model: str = Field(default="llama3.2:latest", description="Local LLM model to query")
    llm_request_timeout: float = Field(default=10.0, description="Timeout for local LLM inference")
    use_mock_llm_fallback: bool = Field(default=True, description="Fallback to deterministic mock if Ollama is unreachable")

    # Dynamic Prioritization weights
    criticality_weight: float = Field(default=0.4, description="Weight for asset criticality in prioritization")
    confidence_weight: float = Field(default=0.3, description="Weight for hypothesis confidence")
    observation_density_weight: float = Field(default=0.3, description="Weight for supporting observation count")

    # Logging & Debug
    log_level: str = Field(default="INFO", description="Console logging level")
    verbose: bool = Field(default=True, description="Enable rich formatted progress logging")
