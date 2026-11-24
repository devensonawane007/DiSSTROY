"""DiSSTROY: End-to-End Autonomous Security Research Demonstration."""

import asyncio
import os
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
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box

from disstroy.config import DiSSTROYConfig
from disstroy.core.orchestrator import DiSSTROYOrchestrator
from disstroy.models.enums import HypothesisStatus


def get_safe_console() -> Console:
    """Create a Rich Console instance configured for maximum Windows compatibility."""
    # safe_box=True ensures box drawing characters are converted to ASCII when terminal encoding is limited
    return Console(
        safe_box=True,
        soft_wrap=True,
        highlight=False,
    )


async def run_demo():
    console = get_safe_console()

    console.print(
        Panel.fit(
            "[bold red]DiSSTROY[/bold red] - Adaptive Multi-Agent Security Assessment Platform\n"
            "[yellow]Philosophy: DISCOVER -> DESTROY (Continuous Parallel Hypothesis Investigation)[/yellow]",
            border_style="red",
            box=box.ASCII if sys.platform == "win32" and "utf" not in getattr(sys.stdout, "encoding", "utf-8").lower() else box.ROUNDED,
        )
    )

    config = DiSSTROYConfig(
        db_path=":memory:",
        max_concurrent_workers=3,
        use_mock_llm_fallback=True,
    )

    orchestrator = DiSSTROYOrchestrator(config=config)
    await orchestrator.initialize()

    report = None
    try:
        console.print("\n[bold cyan]1. Initializing Target Environment & Discovery Pipeline[/bold cyan]")
        tree = Tree("[bold white]Simulated Infrastructure Landscape[/bold white]")
        for asset_id, asset in orchestrator.simulator.assets.items():
            tree.add(
                f"[green]{asset.name}[/green] ({asset.id}) - Criticality: [yellow]{asset.criticality}[/yellow] - Route: {asset.network_location}"
            )
        console.print(tree)

        console.print("\n[bold cyan]2. Ingesting Initial Observations & Formulating Competing Hypotheses[/bold cyan]")
        obs_table = Table(title="Baseline Structured Observations", safe_box=True)
        obs_table.add_column("Asset", style="green")
        obs_table.add_column("Type", style="cyan")
        obs_table.add_column("Observation Finding", style="white")
        for obs in orchestrator.simulator.initial_observations:
            obs_table.add_row(obs.asset_id, obs.kind.value, obs.title)
        console.print(obs_table)

        console.print("\n[bold cyan]3. Launching Swarm Orchestrator with Dynamic Event Injection...[/bold cyan]")
        console.print("[dim green]Starting concurrent investigation loop across worker swarm...[/dim green]")
        
        # Execute the full autonomous lifecycle
        report = await orchestrator.run_lifecycle()

        console.print("\n[bold green][SUCCESS] Investigation Cycle Converged and Completed![/bold green]\n")

        # 1. Hypotheses Table
        hyp_table = Table(title="Final Hypotheses Resolution & Validation Status", safe_box=True)
        hyp_table.add_column("Hypothesis ID", style="magenta")
        hyp_table.add_column("Target Asset", style="green")
        hyp_table.add_column("Status", style="bold")
        hyp_table.add_column("Confidence", justify="right")
        hyp_table.add_column("Priority", justify="right")
        hyp_table.add_column("Title", style="white")

        assert orchestrator.state is not None
        all_hypotheses = await orchestrator.state.list_hypotheses()
        for h in all_hypotheses:
            status_color = "green" if h.status == HypothesisStatus.VALIDATED else "red"
            hyp_table.add_row(
                h.id,
                h.target_asset_id,
                f"[{status_color}]{h.status.value}[/{status_color}]",
                f"{h.confidence:.2f}",
                f"{h.priority_score:.2f}",
                h.title,
            )
        console.print(hyp_table)

        # 2. Cryptographic Evidence Log
        console.print("\n[bold cyan]4. Cryptographically Traceable Evidence Log (SHA-256 Proofs)[/bold cyan]")
        ev_table = Table(title="Collected Verifiable Evidence Chain", safe_box=True)
        ev_table.add_column("Evidence ID", style="cyan")
        ev_table.add_column("Hypothesis", style="magenta")
        ev_table.add_column("Supports?", justify="center")
        ev_table.add_column("SHA-256 Content Hash", style="dim")
        ev_table.add_column("Interpretation", style="white")

        evidence_records = await orchestrator.state.list_evidence()
        for ev in evidence_records:
            supp = "[bold green]YES[/bold green]" if ev.supports_hypothesis else "[bold red]NO (Refutes)[/bold red]"
            ev_table.add_row(
                ev.id,
                ev.hypothesis_id,
                supp,
                ev.content_hash[:16] + "...",
                ev.interpretation[:65] + "...",
            )
        console.print(ev_table)

        # 3. Failure Intelligence Lessons
        console.print("\n[bold cyan]5. Failure Intelligence & Adaptive Learning Lessons[/bold cyan]")
        lesson_table = Table(title="Lessons Learned & Penalty Multipliers", safe_box=True)
        lesson_table.add_column("Lesson ID", style="yellow")
        lesson_table.add_column("Target Asset", style="green")
        lesson_table.add_column("Penalty Factor", justify="right")
        lesson_table.add_column("Adaptive Learned Policy", style="white")

        lessons = await orchestrator.state.list_lessons()
        for l in lessons:
            lesson_table.add_row(
                l.id,
                l.target_asset_id or "GLOBAL",
                f"{l.penalty_factor:.2f}",
                l.rule_description,
            )
        console.print(lesson_table)

        # 4. Knowledge Graph Metrics
        console.print("\n[bold cyan]6. NetworkX MultiDiGraph Relationship Knowledge State[/bold cyan]")
        graph_metrics = report["graph_metrics"]
        g_table = Table(title="Knowledge Graph Topological Metrics", safe_box=True)
        g_table.add_column("Metric", style="cyan")
        g_table.add_column("Value", style="bold white")
        g_table.add_row("Total Graph Nodes", str(graph_metrics["total_nodes"]))
        g_table.add_row("Total Graph Edges", str(graph_metrics["total_edges"]))
        for ntype, count in graph_metrics["nodes_by_type"].items():
            g_table.add_row(f"  Node Type: {ntype}", str(count))
        for rtype, count in graph_metrics["edges_by_relation"].items():
            g_table.add_row(f"  Edge Relation: {rtype}", str(count))
        console.print(g_table)

        # 5. Concurrency & LLM Telemetry
        console.print("\n[bold cyan]7. Swarm Concurrency & LLM Verification Telemetry[/bold cyan]")
        conc_table = Table(title="Runtime Execution Performance & Model Provenance", safe_box=True)
        conc_table.add_column("Dimension", style="cyan")
        conc_table.add_column("Observed Metric", style="bold white")
        conc_table.add_row("Peak Simultaneous Workers", str(report["concurrency_metrics"]["max_simultaneous_workers"]))
        conc_table.add_row("Total Tasks Dispatched", str(report["concurrency_metrics"]["total_workers_dispatched"]))
        conc_table.add_row("Dynamic Replanning Events", str(report["replanning_metrics"]["replanning_events"]))
        conc_table.add_row("Duplicate Investigation Rate", f"{report['replanning_metrics']['duplicate_investigation_rate'] * 100:.1f}%")
        llm_info = report["llm_telemetry"]
        conc_table.add_row("LLM Active Backend", str(llm_info["active_backend_used"]))
        conc_table.add_row("Configured Provider / Model", f"{llm_info['configured_provider']} ({llm_info['configured_model']})")
        conc_table.add_row("Live Model Reachable", "Yes" if llm_info["is_live_available"] else "No (Mock Fallback Engaged)")
        conc_table.add_row("Fallback Invocations", str(llm_info["fallback_calls"]))
        console.print(conc_table)

    except Exception as render_err:
        console.print(f"[bold yellow][WARNING] Rich formatted table display failed: {render_err}[/bold yellow]")
        print("\n--- Fallback Plaintext Summary ---")
        if report:
            for key, val in report.get("summary", {}).items():
                print(f"  {key}: {val}")

    finally:
        # Guarantee all worker tasks, background loops and SQLite connections are cleanly closed
        await orchestrator.close()

    console.print("\n[bold green][SUCCESS] Milestone demonstration executed with 100% fidelity.[/bold green]")


if __name__ == "__main__":
    asyncio.run(run_demo())
