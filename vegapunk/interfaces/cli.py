"""
CLI interface — Click + Rich.

Commands:
  vegapunk ingest  <file> --source splunk|elastic|wazuh
  vegapunk chat               (interactive REPL)
  vegapunk analyze <file>     (ingest + auto-triage)
  vegapunk stats              (storage stats)
  vegapunk watch              (live Wazuh Cloud polling)
  vegapunk export             (dump Wazuh Cloud alerts to a local JSON file)
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _get_orchestrator():
    """Lazy import to avoid slow startup when not needed."""
    from vegapunk.agents.orchestrator import AgentOrchestrator
    from vegapunk.storage.manager import StorageManager
    storage = StorageManager()
    return AgentOrchestrator(storage), storage


@click.group()
@click.version_option()
def cli():
    """Vegapunk — AI-powered SIEM analysis agent."""


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--source", "-s", required=True,
              type=click.Choice(["splunk", "elastic", "wazuh"]),
              help="SIEM source type")
def ingest(file: Path, source: str):
    """Ingest a SIEM export file into the database."""
    from vegapunk.ingestion.pipeline import IngestionPipeline
    from vegapunk.storage.manager import StorageManager

    storage = StorageManager()
    pipeline = IngestionPipeline(storage)

    with console.status(f"Ingesting [bold]{file.name}[/] ({source})…"):
        chunks = asyncio.run(pipeline.ingest_file(file, source))

    console.print(f"[green]Done.[/] Stored [bold]{chunks}[/] chunks.")


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--source", "-s", required=True,
              type=click.Choice(["splunk", "elastic", "wazuh"]))
def analyze(file: Path, source: str):
    """Ingest a file and run triage + analysis on every event."""
    from vegapunk.ingestion.normalizer import normalize_event
    from vegapunk.ingestion.parsers import PARSER_REGISTRY

    orchestrator, storage = _get_orchestrator()
    parser = PARSER_REGISTRY[source]()

    raw_events = list(parser.parse_file(file))
    norm_events = [normalize_event(r) for r in raw_events]

    console.print(f"Analyzing [bold]{len(norm_events)}[/] events…")

    results = asyncio.run(orchestrator.process_events(norm_events))

    table = Table(title="Analysis Results", show_lines=True)
    table.add_column("Event ID", style="dim", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=10)
    table.add_column("Summary")
    table.add_column("Deep?", width=6)

    for triage, analysis in results:
        sev_color = {"low": "green", "medium": "yellow",
                     "high": "red", "critical": "bold red"}.get(triage.severity.value, "white")
        table.add_row(
            triage.event_id[:8] + "…",
            f"[{sev_color}]{triage.severity.value}[/]",
            f"{triage.confidence:.0%}",
            (analysis.summary if analysis else triage.summary)[:80],
            "[red]yes[/]" if triage.needs_deep_analysis else "no",
        )

    console.print(table)


@cli.command()
def chat():
    """Start an interactive chat session with the SIEM analyst."""
    orchestrator, _ = _get_orchestrator()

    console.print(Panel(
        "[bold green]Vegapunk SIEM Analyst[/]\n"
        "Ask questions about your security logs. Type [bold]exit[/] to quit.\n"
        "Type [bold]clear[/] to reset conversation memory.",
        title="Vegapunk",
    ))

    while True:
        try:
            user_input = console.input("[bold blue]You:[/] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/]")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/]")
            break
        if user_input.lower() == "clear":
            orchestrator.clear_memory()
            console.print("[dim]Memory cleared.[/]")
            continue

        with console.status("Thinking…"):
            response = orchestrator.chat(user_input)

        console.print(Panel(response, title="[bold green]Vegapunk[/]"))


@cli.command()
def stats():
    """Show storage statistics."""
    _, storage = _get_orchestrator()
    data = storage.stats()

    console.print(Panel(
        f"[bold]Vector documents:[/] {data['vector_documents']}\n"
        + "\n".join(
            f"[bold]{k}:[/] {v}"
            for k, v in data.get("events_by_severity", {}).items()
        ),
        title="Vegapunk Storage Stats",
    ))


@cli.command()
@click.option("--interval", "-i", default=None, type=int,
              help="Poll interval in seconds (default: from .env / 60)")
@click.option("--analyze/--no-analyze", default=True,
              help="Run triage+analysis on each batch (default: true)")
def watch(interval: int | None, analyze: bool):
    """Live-poll Wazuh Cloud for new alerts and ingest them continuously."""
    from vegapunk.config import settings

    if not settings.wazuh_cloud_url or not settings.wazuh_password:
        console.print("[red]Error:[/] WAZUH_CLOUD_URL and WAZUH_PASSWORD must be set in .env")
        raise SystemExit(1)

    poll_interval = interval or settings.wazuh_poll_interval

    console.print(Panel(
        f"[bold green]Vegapunk — Wazuh Cloud Watch[/]\n"
        f"URL: {settings.wazuh_cloud_url}\n"
        f"Poll interval: {poll_interval}s\n"
        f"Triage+analysis: {'on' if analyze else 'off'}\n\n"
        f"Press [bold]Ctrl+C[/] to stop.",
        title="Watching",
    ))

    async def _run():
        from vegapunk.agents.orchestrator import AgentOrchestrator
        from vegapunk.connectors.wazuh_cloud import WazuhCloudConnector
        from vegapunk.ingestion.chunker import chunk_events
        from vegapunk.ingestion.normalizer import normalize_event
        from vegapunk.storage.manager import StorageManager

        storage = StorageManager()
        orchestrator = AgentOrchestrator(storage) if analyze else None
        connector = WazuhCloudConnector()

        with console.status("Checking Wazuh Cloud connectivity…"):
            health = await connector.health_check()

        if health["status"] != "ok":
            from rich.markup import escape
            console.print(f"[red]Wazuh health check failed:[/] {escape(str(health.get('error', 'unknown error')))}")
            raise SystemExit(1)

        console.print("[green]Connected to Wazuh Cloud.[/]")
        total_events = 0

        async for raw_batch in connector.stream(interval_seconds=poll_interval):
            norm_events = [normalize_event(r) for r in raw_batch]

            chunks = list(chunk_events(norm_events))
            for chunk in chunks:
                await storage.store_chunk(chunk)

            total_events += len(norm_events)
            console.print(
                f"[dim]{_now()}[/] Ingested [bold]{len(norm_events)}[/] events "
                f"→ {len(chunks)} chunk(s) | total: {total_events}"
            )

            if orchestrator and norm_events:
                with console.status(f"Triaging {len(norm_events)} events…"):
                    results = await orchestrator.process_events(norm_events)

                escalated = sum(1 for _, a in results if a is not None)
                if escalated:
                    console.print(
                        f"  [yellow]↑ {escalated} event(s) escalated to deep analysis[/]"
                    )

                for triage, analysis in results:
                    if triage.severity.value == "critical":
                        result = analysis or triage
                        summary = getattr(result, "summary", "")
                        console.print(
                            f"  [bold red]CRITICAL:[/] {summary[:120]}"
                        )

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/]")


@cli.command()
@click.option("--hours", "-H", default=24, show_default=True,
              help="How many hours back to fetch alerts")
@click.option("--output", "-o", default=None,
              help="Output file path (default: wazuh_alerts_<timestamp>.json)")
def export(hours: int, output: str | None):
    """Export Wazuh Cloud alerts to a local JSON file for offline ingestion."""
    import json
    from datetime import datetime, timedelta, timezone
    from vegapunk.config import settings

    if not settings.wazuh_cloud_url or not settings.wazuh_password:
        console.print("[red]Error:[/] WAZUH_CLOUD_URL and WAZUH_PASSWORD must be set in .env")
        raise SystemExit(1)

    out_path = Path(output) if output else Path(f"wazuh_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    async def _run():
        from vegapunk.connectors.wazuh_cloud import WazuhCloudConnector
        from datetime import datetime, timedelta, timezone

        connector = WazuhCloudConnector()
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        connector._last_seen = since

        with console.status(f"Fetching alerts from the last {hours}h…"):
            alerts = await connector._search(since)
        await connector.aclose()
        return alerts

    alerts = asyncio.run(_run())

    if not alerts:
        console.print(f"[yellow]No alerts found in the last {hours} hours.[/]")
        return

    out_path.write_text(json.dumps(alerts, indent=2, default=str))
    console.print(
        f"[green]Exported[/] [bold]{len(alerts)}[/] alerts → [bold]{out_path}[/]\n"
        f"Now run: [bold]vegapunk ingest {out_path} --source wazuh[/]"
    )


def _now() -> str:
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")


def main():
    cli()


if __name__ == "__main__":
    main()
