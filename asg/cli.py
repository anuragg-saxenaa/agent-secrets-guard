"""Click CLI for agent-secrets-guard."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import click

from asg.detectors import DetectorRegistry
from asg.scanner import ScanResult, format_report, redact_text, scan_file, scan_stdin

__all__ = ["cli"]


@dataclass
class Context:
    """Shared CLI state."""

    registry: DetectorRegistry
    redact: bool
    json_output: bool


@click.group()
@click.option("--redact", is_flag=True, help="Output redacted version (replace secrets with ***REDACTED***).")
@click.option("--json", "json_output", is_flag=True, help="Machine-readable JSON output.")
@click.pass_context
def cli(ctx: click.Context, redact: bool, json_output: bool) -> None:
    """agent-secrets-guard — scan files or stdin for leaked secrets and redact them."""
    ctx.obj = Context(registry=DetectorRegistry(), redact=redact, json_output=json_output)


@cli.command()
@click.argument("paths", nargs=-1, type=str)
@click.option("--exclude", multiple=True, help="Exclude patterns (supports glob).")
@click.pass_context
def scan(ctx: click.Context, paths: tuple[str, ...], exclude: tuple[str, ...]) -> None:
    """Scan one or more paths (files or glob patterns)."""
    obj: Context = ctx.obj
    registry = obj.registry

    if not paths:
        click.secho("Error: no paths provided. Use 'asg scan --help' for usage.", fg="red", err=True)
        raise SystemExit(1)

    results: list[ScanResult] = []

    for path_str in paths:
        path = Path(path_str)
        if path.is_dir():
            for p in path.rglob("*"):
                if p.is_file() and not _is_excluded(p, exclude):
                    _add_result(results, p, registry)
        elif _is_excluded(path, exclude):
            continue
        else:
            _add_result(results, path, registry)

    if not results:
        click.secho("No files scanned.", fg="yellow", err=True)
        raise SystemExit(1)

    if obj.redact:
        # Redact and print each file
        for result in results:
            if result.findings:
                redacted = redact_text(Path(result.path).read_text(encoding="utf-8", errors="replace"), result.findings)
                click.echo(redacted)
        raise SystemExit(0)

    report = format_report(results, json_output=obj.json_output)
    click.echo(report)

    total = sum(len(r.findings) for r in results)
    raise SystemExit(2 if total > 0 else 0)


@cli.command()
@click.pass_context
def scanstdin(ctx: click.Context) -> None:
    """Scan from stdin.  Accepts a single text blob on stdin."""
    obj: Context = ctx.obj
    text = sys.stdin.read()
    findings = obj.registry.scan(text)

    if obj.redact:
        redacted = redact_text(text, findings)
        click.echo(redacted)
        raise SystemExit(0)

    result = ScanResult(path="<stdin>", findings=findings)
    report = format_report([result], json_output=obj.json_output)
    click.echo(report)
    raise SystemExit(2 if findings else 0)


# ─── Internal helpers ────────────────────────────────────────────────────────


def _add_result(results: list[ScanResult], path: Path, registry: DetectorRegistry) -> None:
    try:
        findings = registry.scan(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as e:
        click.secho(f"  WARNING: skipped {path}: {e}", fg="yellow", err=True)
        return
    results.append(ScanResult(path=str(path), findings=findings))


def _is_excluded(path: Path, exclude: tuple[str, ...]) -> bool:
    import fnmatch
    name = path.name
    for pat in exclude:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(str(path), pat):
            return True
    return False


if __name__ == "__main__":
    cli()
