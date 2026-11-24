"""Command Line Interface for DiSSTROY."""

import argparse
import asyncio
import sys

# Configure UTF-8 encoding with replacement error handling on Windows
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from disstroy.config import DiSSTROYConfig
from disstroy.core.orchestrator import DiSSTROYOrchestrator


def parse_args():
    parser = argparse.ArgumentParser(
        prog="disstroy",
        description="DiSSTROY: Adaptive Multi-Agent Security Assessment Platform",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=":memory:",
        help="Path to SQLite database file (default: :memory:)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Maximum concurrent swarm workers (default: 3)",
    )
    parser.add_argument(
        "--ollama-url",
        type=str,
        default="http://localhost:11434",
        help="Ollama API base URL",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="llama3.2:latest",
        help="Local Ollama model name",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run interactive end-to-end milestone demonstration",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.demo:
        from demo import run_demo
        asyncio.run(run_demo())
        return

    console = Console(safe_box=True, soft_wrap=True, highlight=False)
    console.print(f"[bold red]DiSSTROY[/bold red] v0.1.0 starting with {args.workers} workers...")

    config = DiSSTROYConfig(
        db_path=args.db,
        max_concurrent_workers=args.workers,
        ollama_base_url=args.ollama_url,
        ollama_model=args.model,
    )

    async def _run():
        orchestrator = DiSSTROYOrchestrator(config=config)
        await orchestrator.initialize()
        try:
            report = await orchestrator.run_lifecycle()
            console.print_json(data=report)
        finally:
            await orchestrator.close()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
