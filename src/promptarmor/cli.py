from pathlib import Path

import typer
from rich.console import Console

from promptarmor import __version__

app = typer.Typer(
    name="promptarmor",
    help="Runtime defense toolkit against prompt injection for LLM APIs",
)
console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit",
    ),
) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit()

    """Display the main help banner when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        console.print("[bold cyan]PromptArmor[/bold cyan] v" + __version__)
        console.print("Runtime defense toolkit against prompt injection for LLM APIs")
        console.print()
        console.print("Usage: promptarmor [OPTIONS] COMMAND")
        console.print()
        console.print("Commands:")
        console.print("  serve    Start the proxy server")
        console.print("  test     Test a prompt against all filters")
        console.print("  policy   Manage security policies")
        console.print("  report   Generate reports from events")
        console.print()
        console.print("Use [bold]promptarmor COMMAND --help[/bold] for more info.")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8100, "--port", "-p", help="Listen port"),
    target: str = typer.Option("", "--target", "-t", help="Upstream LLM API URL"),
    api_key: str = typer.Option("", "--api-key", "-k", help="API key for upstream"),
    policy: str | None = typer.Option(None, "--policy", "-P", help="Policy file path"),
    log_level: str = typer.Option("info", "--log-level", "-L", help="Log level"),
    ssl_certfile: str | None = typer.Option(None, "--ssl-certfile", help="Path to SSL certificate file"),
    ssl_keyfile: str | None = typer.Option(None, "--ssl-keyfile", help="Path to SSL key file"),
    rate_limit: int = typer.Option(100, "--rate-limit", "-R", help="Max requests per minute per IP"),
):
    """Start the PromptArmor proxy server."""
    import logging

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    import uvicorn

    from promptarmor.models import ProxyConfig
    from promptarmor.policies.yaml_loader import YamlPolicyLoader
    from promptarmor.proxy import PromptArmorProxy

    config = ProxyConfig(
        host=host,
        port=port,
        target_url=target,
        api_key=api_key,
        log_level=log_level,
        rate_limit=rate_limit,
    )

    if policy:
        loader = YamlPolicyLoader()
        rules = loader.load(policy)
        proxy = PromptArmorProxy(config)
        for rule in rules:
            proxy.policy_engine.add_rule(rule)
        console.print(f"[green]Loaded {len(rules)} policy rules from {policy}[/green]")
    else:
        proxy = PromptArmorProxy(config)

    protocol = "https" if ssl_certfile else "http"
    console.print(
        f"[bold cyan]PromptArmor[/bold cyan] proxy starting on [underline]{protocol}://{host}:{port}[/underline]"
    )
    if target:
        console.print(f"Upstream target: [yellow]{target}[/yellow]")

    uvicorn.run(
        proxy.app,
        host=host,
        port=port,
        log_level=log_level,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )


@app.command()
def test(
    prompt: str = typer.Argument("", help="Prompt text to test"),
    file: Path | None = typer.Option(None, "--file", "-f", help="Read prompt from file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed results"),
):
    """Test a prompt against all PromptArmor filters."""
    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    if file:
        resolved = file.resolve()
        prompt = resolved.read_text()
    if not prompt:
        typer.echo("Error: either provide a prompt string or --file")
        raise typer.Exit(1)

    from promptarmor.filters import (
        ContextSanitizer,
        InjectionDetector,
        OutputValidator,
        SelfReflectionGuard,
    )

    prompt = prompt.strip()
    console.print(f"\n[bold]Testing prompt[/bold] ({len(prompt)} chars):")
    console.print(Panel(prompt[:500], border_style="blue"))

    injection = InjectionDetector()
    inj_result = injection.detect(prompt)

    reflection = SelfReflectionGuard()
    ref_result = reflection.analyze(prompt)

    sanitizer = ContextSanitizer()
    san_result = sanitizer.sanitize(prompt)

    validator = OutputValidator()
    val_result = validator.validate(prompt)

    table = Table(box=box.ROUNDED)
    table.add_column("Filter", style="cyan")
    table.add_column("Detected", style="bold")
    table.add_column("Score")
    table.add_column("Severity")
    table.add_column("Details")

    inj_status = "[red]YES[/red]" if inj_result.detected else "[green]NO[/green]"
    inj_det = ", ".join(inj_result.matched_patterns[:2]) if inj_result.matched_patterns else "-"
    table.add_row("Injection Detector", inj_status, f"{inj_result.score:.2f}", inj_result.severity.value, inj_det)

    ref_status = "[red]YES[/red]" if ref_result.detected else "[green]NO[/green]"
    ref_det = ", ".join(ref_result.triggers[:2]) if ref_result.triggers else "-"
    table.add_row("Self-Reflection Guard", ref_status, f"{ref_result.score:.2f}", ref_result.severity.value, ref_det)

    san_status = "[yellow]YES[/yellow]" if san_result.sanitized else "[green]NO[/green]"
    san_det = f"{san_result.removed_blocks} block(s) removed" if san_result.sanitized else "-"
    table.add_row("Context Sanitizer", san_status, "-", "-", san_det)

    val_status = "[red]YES[/red]" if not val_result.valid else "[green]NO[/green]"
    val_det = ""
    if val_result.has_exfiltration:
        val_det += f"Exfil: {', '.join(val_result.exfiltration_matches[:2])} "
    if val_result.has_hidden_instructions:
        val_det += f"Hidden: {', '.join(val_result.hidden_instruction_matches[:2])}"
    val_det = val_det or "-"
    table.add_row("Output Validator", val_status, "-", val_result.severity.value, val_det)

    console.print(table)

    max_score = max(inj_result.score, ref_result.score)
    if max_score >= 0.8:
        verdict = "[bold red]BLOCK[/bold red]"
    elif max_score >= 0.5:
        verdict = "[bold yellow]FLAG[/bold yellow]"
    else:
        verdict = "[bold green]ALLOW[/bold green]"

    console.print(f"\nVerdict: {verdict} (max score: {max_score:.2f})")


@app.command()
def policy(
    action: str = typer.Argument(..., help="Policy action: validate, list, generate"),
    path: str = typer.Option("", "--path", "-p", help="Policy file path"),
    output: str = typer.Option("", "--output", "-o", help="Output file for generated policy"),
):
    """Manage security policies: validate, list, or generate MCPGuard-compatible policies."""
    from promptarmor.policies.generator import MCPGuardPolicyGenerator
    from promptarmor.policies.yaml_loader import YamlPolicyLoader

    if action == "validate":
        if not path:
            console.print("[red]Error: --path required for validate[/red]")
            raise typer.Exit(1)
        loader = YamlPolicyLoader()
        valid, msg = loader.validate(path)
        if valid:
            console.print(f"[green]{msg}[/green]")
        else:
            console.print(f"[red]{msg}[/red]")

    elif action == "list":
        if not path:
            console.print("[red]Error: --path required for list[/red]")
            raise typer.Exit(1)
        loader = YamlPolicyLoader()
        rules = loader.load(path)
        from rich.table import Table

        table = Table(title=f"Policy Rules ({path})")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Action")
        table.add_column("Priority")
        table.add_column("Enabled")
        for rule in rules:
            table.add_row(rule.id, rule.name, rule.action.value, str(rule.priority), str(rule.enabled))
        console.print(table)

    elif action == "generate":
        if not path:
            console.print("[red]Error: --path required for generate[/red]")
            raise typer.Exit(1)
        loader = YamlPolicyLoader()
        rules = loader.load(path)
        generator = MCPGuardPolicyGenerator()
        yaml_output = generator.generate_yaml(rules)
        if output:
            Path(output).write_text(yaml_output)
            console.print(f"[green]MCPGuard policy written to {output}[/green]")
        else:
            console.print(yaml_output)

    else:
        console.print(f"[red]Unknown action: {action}. Use: validate, list, generate[/red]")


@app.command()
def report(
    action: str = typer.Argument(..., help="Report action: json, html, summary"),
    input: str = typer.Option("", "--input", "-i", help="Input events file (JSON)"),
    output: str = typer.Option("", "--output", "-o", help="Output report file"),
):
    """Generate reports from PromptArmor events.

    Reads a JSON events file (produced by the proxy) and outputs a console
    summary, JSON report, or styled HTML report.
    """
    import json

    from promptarmor.models import PromptArmorEvent

    if not input:
        console.print("[red]Error: --input <file> is required[/red]")
        raise typer.Exit(1)

    input_path = Path(input).resolve()
    if not input_path.exists():
        console.print(f"[red]File not found: {input}[/red]")
        raise typer.Exit(1)

    raw_events = json.loads(input_path.read_text())
    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    if action == "json":
        from promptarmor.reporters.json import JSONReporter

        j_reporter = JSONReporter()
        for ev in raw_events:
            j_reporter.report_event(PromptArmorEvent(**ev))
        path = j_reporter.save(output or None)
        console.print(f"[green]JSON report saved: {path}[/green]")

    elif action == "html":
        from promptarmor.reporters.html import HTMLReporter

        h_reporter = HTMLReporter()
        for ev in raw_events:
            h_reporter.report_event(PromptArmorEvent(**ev))
        path = h_reporter.save(output or None)
        console.print(f"[green]HTML report saved: {path}[/green]")

    elif action == "summary":
        blocked = sum(1 for e in raw_events if e.get("action") == "block" or e.get("filtered"))
        flagged = sum(1 for e in raw_events if e.get("action") == "flag")
        allowed = sum(1 for e in raw_events if e.get("action") == "allow" and not e.get("filtered"))
        console.print(f"[bold]Summary[/bold] — {len(raw_events)} events")
        console.print(f"  [red]Blocked: {blocked}[/red]")
        console.print(f"  [yellow]Flagged: {flagged}[/yellow]")
        console.print(f"  [green]Allowed: {allowed}[/green]")

    else:
        console.print(f"[red]Unknown action: {action}. Use: json, html, summary[/red]")


if __name__ == "__main__":
    app()
