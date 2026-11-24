# DiSSTROY: Adaptive Multi-Agent Security Assessment Platform

DiSSTROY is an autonomous, hypothesis-driven security assessment system built around the philosophy:

$$\text{DISCOVER} \longrightarrow \text{DESTROY}$$

Unlike conventional static scanners that execute rigid sequential playbooks, DiSSTROY maintains a dynamic, reactive model of its target landscape. It synthesizes competing investigation hypotheses, executes concurrent probe verification plans across an asynchronous worker swarm, records cryptographically traceable evidence, diagnoses failures into actionable penalty lessons, and dynamically reprioritizes its investigation as new findings emerge.

---

## Core Architecture

1. **Orchestrator (`disstroy.core`)**: Controls the full execution lifecycle (`INITIALIZING`, `DISCOVERING`, `INVESTIGATING`, `ADAPTING`, `CONVERGED`, `COMPLETED`), streaming live telemetry and coordinating replanning loops.
2. **Discovery Engine (`disstroy.discovery`)**: Ingests baseline environment telemetry and maintains an asynchronous queue for dynamic mid-flight observation injection.
3. **Hypothesis Engine & Prioritizer (`disstroy.hypothesis`)**: Synthesizes competing hypotheses with discrete probe test plans and computes dynamic priority scores using asset criticality, confidence, observation density, and negative failure penalties.
4. **Swarm Manager & Workers (`disstroy.swarm`)**: Manages concurrent investigation workers, enforces concurrency throttling, monitors execution overlaps, and supports mid-flight task cancellation.
5. **Shared State (`disstroy.state`)**: Asynchronous, ACID-compliant SQLite store (`aiosqlite` with WAL mode and foreign key cascades) coupled with a reactive pub/sub event bus.
6. **Knowledge Graph (`disstroy.graph`)**: NetworkX `MultiDiGraph` synchronized in real time with shared state events, modeling asset dependencies, observation linkages, hypotheses, and evidence chains.
7. **Failure Intelligence (`disstroy.intelligence`)**: Diagnoses probe failures into categorized failure modes (`ACCESS_DENIED_HARD`, `COUNTERMEASURE_DETECTED`, `INVALID_PREMISE`, `PROBE_TIMEOUT`, `PATCH_VERIFIED`), generating actionable lessons and adaptive penalty dampeners.
8. **Evidence Engine (`disstroy.evidence`)**: Validates raw probe telemetry against expected and refuting criteria, generating immutable SHA-256 content hashes and resolving hypothesis status (`VALIDATED`, `REFUTED`).
9. **LLM Provider (`disstroy.llm`)**: Replaceable local LLM client for Ollama models with fast circuit-breaking, robust markdown/JSON parsing, transparent telemetry, and deterministic heuristic fallback.
10. **Benchmark Simulator (`disstroy.simulator`)**: Synthetic microservice target landscape (Public Edge Gateway, Internal Auth Service, Legacy Admin Console, Isolated DB Cluster) simulating realistic network delays, defensive rate limits, and runtime observation discoveries.

---

## Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.11)
- Ollama (optional, for local LLM inference e.g., `llama3.2:latest`)

### Install Dependencies
```bash
pip install -e .
pip install pytest pytest-asyncio
```

---

## Running the Platform

### 1. Interactive Demonstration
Run the end-to-end autonomous milestone demonstration:
```bash
python demo.py
```

### 2. Command-Line Interface (CLI)
```bash
# Run with default configuration
disstroy --demo

# Run with custom worker pool and SQLite database
disstroy --workers 4 --db disstroy_run.db
```

### 3. Automated Test Suite
Run the full behavioural and architectural test suite (20 tests):
```bash
pytest -v
```
