"""
Command Line Interface for GameCleaner with Rich terminal UI.
"""
import argparse
import os
from pathlib import Path
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gamecleaner.analyzer import PEScanResult, PEScanner, ScriptScanResult, ThreatSeverity
from gamecleaner.cleaner import EmulatorReplacer, QuarantineManager
from gamecleaner.containment import FirewallManager, SandboxGenerator, is_running_as_admin, is_sandbox_supported
from gamecleaner.pipeline import GameCleanerPipeline

console = Console()


def get_severity_badge(severity: str) -> Text:
    if severity == ThreatSeverity.CRITICAL.value:
        return Text("CRITICAL", style="bold white on red")
    elif severity == ThreatSeverity.HIGH.value:
        return Text("HIGH", style="bold red")
    elif severity == ThreatSeverity.MEDIUM.value:
        return Text("MEDIUM", style="bold yellow")
    elif severity == ThreatSeverity.LOW.value:
        return Text("LOW", style="cyan")
    else:
        return Text("CLEAN", style="bold green")


def handle_scan(args):
    target = Path(args.path).resolve()
    if not target.is_dir():
        console.print(f"[bold red]Error:[/bold red] Target directory not found: {target}")
        return

    console.print(Panel(f"[bold cyan]Scanning Game Directory:[/bold cyan] {target}", title="GameCleaner Security Scan"))

    scanner = PEScanner()
    pipeline = GameCleanerPipeline(target_dir=target)
    results = pipeline.run_scan_only()

    if not results:
        console.print("[yellow]No executable (PE) binaries (.exe, .dll) found in directory.[/yellow]")
        return

    table = Table(title=f"Binary Triage Analysis ({len(results)} files found)", show_lines=True)
    table.add_column("File Name", style="bold")
    table.add_column("Arch", justify="center")
    table.add_column("Entropy", justify="right")
    table.add_column("Signed", justify="center")
    table.add_column("Threat Score", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Verdict")
    table.add_column("Action", style="bold cyan")

    for res in results:
        if isinstance(res, PEScanResult):
            arch_str = res.architecture
            entropy_str = f"{res.max_entropy:.2f}"
            signed_str = f"[green]{res.signature_status}[/green]" if res.is_signed else f"[dim]{res.signature_status}[/dim]"
        else:
            arch_str = res.extension.upper()
            entropy_str = "N/A"
            signed_str = "[dim]N/A[/dim]"

        table.add_row(
            res.file_name,
            arch_str,
            entropy_str,
            signed_str,
            f"{res.threat_score}/100",
            get_severity_badge(res.overall_severity),
            res.verdict,
            res.recommended_action,
        )

    console.print(table)


def handle_clean_all(args):
    target = Path(args.path).resolve()
    if not target.is_dir():
        console.print(f"[bold red]Error:[/bold red] Target directory not found: {target}")
        return

    console.print(Panel(
        f"[bold green]Running Full Security Pipeline on:[/bold green] {target}\n"
        "• Static PE Header & Entropy Scan\n"
        "• Hostile Malware & Infostealer Quarantine\n"
        "• Clean Open-Source Steam Emulator Replacement\n"
        "• Windows Firewall Outbound Network Isolation\n"
        "• Windows Sandbox (.wsb) Air-gapped Profile Generation",
        title="GameCleaner Pipeline Orchestration",
    ))

    pipeline = GameCleanerPipeline(
        target_dir=target,
        auto_quarantine=not args.no_quarantine,
        auto_replace_emu=not args.no_replace_emu,
        auto_firewall=not args.no_firewall,
        generate_sandbox=not args.no_sandbox,
    )

    with console.status("[bold cyan]Analyzing binaries and executing remediation..."):
        report = pipeline.run_full_pipeline()

    console.print("\n[bold green]Pipeline Completed Successfully![/bold green]\n")

    summary_table = Table(title="Remediation Summary", show_header=False)
    summary_table.add_row("Total Files Scanned", str(report.total_files_scanned))
    summary_table.add_row("Clean Binaries", f"[green]{report.clean_files}[/green]")
    summary_table.add_row("Suspicious / DRM Hooks", f"[yellow]{report.suspicious_files}[/yellow]")
    summary_table.add_row("Critical Threats", f"[red]{report.critical_threats}[/red]")
    summary_table.add_row("Quarantined Binaries", f"[red bold]{len(report.quarantined_files)}[/red bold]")
    summary_table.add_row("Replaced DRM DLLs", f"[cyan]{len(report.replaced_emulators)}[/cyan]")
    summary_table.add_row("Firewall Script", f"[dim]{report.firewall_script_created}[/dim]")
    summary_table.add_row("Sandbox Config", f"[dim]{report.sandbox_file_created}[/dim]")

    console.print(summary_table)

    if report.quarantined_files:
        console.print(f"\n[bold red]Quarantined Files:[/bold red] {', '.join(report.quarantined_files)}")
    if report.replaced_emulators:
        console.print(f"[bold green]Clean Emulators Installed:[/bold green] {', '.join(report.replaced_emulators)}")

    console.print(f"\n[cyan]Detailed audit reports saved to:[/cyan]")
    console.print(f"  • {target / 'gamecleaner_report.md'}")
    console.print(f"  • {target / 'gamecleaner_report.json'}")


def handle_firewall(args):
    target = Path(args.path).resolve()
    fm = FirewallManager(target)
    block_ps1, unblock_ps1 = fm.generate_scripts()

    elevated_msg = ""
    if getattr(args, "elevate", False):
        if fm.request_elevation_and_apply():
            elevated_msg = "\n[bold green]UAC prompt launched![/bold green] Click 'Yes' to apply rules."
        else:
            elevated_msg = "\n[bold red]Failed to trigger UAC elevation.[/bold red]"

    console.print(Panel(
        f"[bold green]Firewall Isolation Scripts Generated:[/bold green]\n"
        f"• Block Script:   [cyan]{block_ps1}[/cyan]\n"
        f"• Unblock Script: [cyan]{unblock_ps1}[/cyan]\n\n"
        "[yellow]Tip:[/yellow] Right-click [bold]block_game_network.ps1[/bold] and choose 'Run with PowerShell' as Administrator "
        f"to block all inbound and outbound traffic for this game's executables.{elevated_msg}",
        title="Firewall Network Isolation",
    ))


def handle_sandbox(args):
    target = Path(args.path).resolve()
    sg = SandboxGenerator(target)
    wsb_file = sg.generate_wsb(read_only=not args.read_write, v_gpu=True, allow_network=False)
    has_sandbox = is_sandbox_supported()

    status_str = "[bold green]Supported[/bold green]" if has_sandbox else "[bold yellow]Windows Sandbox feature not detected (Common on Home Edition)[/bold yellow]"
    offline_runner = target / "Launch_Game_Isolated.bat"

    console.print(Panel(
        f"[bold green]Windows Sandbox Profile Created:[/bold green]\n"
        f"• WSB File: [cyan]{wsb_file}[/cyan]\n"
        f"• Host Sandbox Status: {status_str}\n"
        f"• Local Offline Runner: [cyan]{offline_runner}[/cyan]\n\n"
        "• Network: [bold red]Disabled[/bold red] (air-gapped)\n"
        f"• Mount Mode: [bold]{'Read-Write' if args.read_write else 'Read-Only'}[/bold]\n"
        "• 3D Virtual GPU: [bold green]Enabled[/bold green]\n\n"
        "Double-click the .wsb file on Windows Pro/Enterprise, or use [bold]Launch_Game_Isolated.bat[/bold] on Windows Home.",
        title="Windows Sandbox Containment",
    ))


def handle_replace_emu(args):
    target = Path(args.path).resolve()
    er = EmulatorReplacer(target)
    targets = er.find_drm_targets()

    if not targets:
        console.print("[yellow]No Steam API wrapper DLLs (steam_api.dll / steam_api64.dll) found in directory.[/yellow]")
        return

    console.print(f"[cyan]Found {len(targets)} Steam wrapper targets:[/cyan]")
    for t in targets:
        custom = Path(args.custom_dll) if args.custom_dll else None
        success, msg = er.replace_with_clean_emulator(t, custom_clean_dll=custom)
        if success:
            console.print(f"  [green]✓[/green] {t.dll_name} ({t.architecture}) -> {msg}")
        else:
            console.print(f"  [red]✗[/red] {t.dll_name} ({t.architecture}) -> {msg}")


def handle_inspect(args):
    target = Path(args.binary_path).resolve()
    if not target.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {target}")
        return

    from gamecleaner.rea import EvidenceDossierCompiler
    compiler = EvidenceDossierCompiler()
    dossier = compiler.build_dossier(target)

    # Determine safe output directory
    out_dir = Path.cwd()
    out_file = out_dir / f"REA_EVIDENCE_{target.name}.md"
    try:
        out_file.write_text(dossier, encoding="utf-8")
    except Exception:
        out_file = Path.cwd() / f"REA_EVIDENCE_{target.name}.md"
        out_file.write_text(dossier, encoding="utf-8")

    console.print(Panel(
        f"[bold green]REA Reverse-Engineering Dossier Generated:[/bold green]\n"
        f"Target: [cyan]{target.name}[/cyan]\n"
        f"Saved to: [cyan]{out_file}[/cyan]\n\n"
        "This dossier contains disassembled entrypoint instructions, cross-referenced strings,\n"
        "and Steamworks interfaces for AI agent verification.",
        title="REA Binary Reverse Engineering",
    ))
    console.print(dossier[:1500] + ("\n... [truncated for display, see full file]" if len(dossier) > 1500 else ""))


def handle_setup(args):
    from gamecleaner.rea.setup_manager import REASetupManager
    manager = REASetupManager()

    console.print(Panel(
        "[bold cyan]GameCleaner & REA Automated Environment Setup[/bold cyan]\n"
        "Verifying Java, Node.js, REA MCP Server, and Ghidra Decompilation Engine...",
        title="Setup & Diagnostics",
    ))

    status = manager.check_environment()

    status_table = Table(title="Environment Readiness", show_lines=True)
    status_table.add_column("Component", style="bold")
    status_table.add_column("Status", justify="center")
    status_table.add_column("Details")

    # Java
    j_badge = "[green]Ready[/green]" if status.java_installed else "[red]Missing (Java 17+ Required)[/red]"
    status_table.add_row("Java JDK", j_badge, status.java_version or "Not found")

    # Node
    n_badge = "[green]Ready[/green]" if status.node_installed else "[red]Missing[/red]"
    status_table.add_row("Node.js Runtime", n_badge, status.node_version or "Not found")

    # REA
    r_badge = "[green]Installed[/green]" if status.rea_installed else "[yellow]Not Installed[/yellow]"
    status_table.add_row("REA CLI / MCP", r_badge, f"v{status.rea_version}" if status.rea_version else "Available via npm")

    # Ghidra
    g_badge = "[green]Ready[/green]" if status.ghidra_installed else "[yellow]Not Configured (Optional C Decompiler)[/yellow]"
    status_table.add_row("Ghidra Engine", g_badge, str(status.ghidra_path) if status.ghidra_path else "Run 'gamecleaner setup --ghidra' to auto-download")

    console.print(status_table)

    # Auto-install REA if missing
    if not status.rea_installed and status.npm_installed:
        with console.status("[cyan]Installing REA CLI globally via npm..."):
            ok, msg = manager.install_rea_globally()
        if ok:
            console.print(f"[green]✓[/green] {msg}")
        else:
            console.print(f"[red]✗[/red] {msg}")

    # Auto-download Ghidra if requested
    if args.ghidra:
        if status.ghidra_installed:
            console.print(f"[green]✓[/green] Ghidra is already installed at: {status.ghidra_path}")
        else:
            with console.status("[bold cyan]Downloading and extracting official portable Ghidra archive (this may take a few minutes)..."):
                ok, msg, path = manager.install_ghidra_portable()
            if ok:
                console.print(f"[bold green]✓[/bold green] {msg}")
            else:
                console.print(f"[bold red]✗[/bold red] {msg}")


def main():
    parser = argparse.ArgumentParser(
        prog="gamecleaner",
        description="GameCleaner: Security Triage, Malware Isolation, and Safe Containment for Games.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan and audit PE binaries in a folder")
    scan_p.add_argument("path", help="Path to game directory")

    # clean-all
    clean_p = subparsers.add_parser("clean-all", help="Run full pipeline (scan, quarantine, replace emu, firewall, sandbox)")
    clean_p.add_argument("path", help="Path to game directory")
    clean_p.add_argument("--no-quarantine", action="store_true", help="Skip automatic quarantine of critical malware")
    clean_p.add_argument("--no-replace-emu", action="store_true", help="Skip replacing Steam wrappers with Goldberg")
    clean_p.add_argument("--no-firewall", action="store_true", help="Skip generating firewall isolation rules")
    clean_p.add_argument("--no-sandbox", action="store_true", help="Skip generating Windows Sandbox profile")

    # firewall
    fw_p = subparsers.add_parser("firewall", help="Generate firewall isolation rules for all game executables")
    fw_p.add_argument("path", help="Path to game directory")
    fw_p.add_argument("--elevate", action="store_true", help="Launch UAC prompt to apply rules immediately with Admin rights")

    # sandbox
    sb_p = subparsers.add_parser("sandbox", help="Generate Windows Sandbox (.wsb) air-gapped configuration")
    sb_p.add_argument("path", help="Path to game directory")
    sb_p.add_argument("--read-write", action="store_true", help="Mount game directory as read-write instead of read-only")

    # replace-emu
    emu_p = subparsers.add_parser("replace-emu", help="Replace untrusted Steam DLLs with clean Goldberg emulator")
    emu_p.add_argument("path", help="Path to game directory")
    emu_p.add_argument("--custom-dll", help="Path to verified clean steam_api.dll or steam_api64.dll")

    # inspect (REA Deep Reverse Engineering)
    ins_p = subparsers.add_parser("inspect", help="REA deep reverse-engineering and evidence dossier on a binary")
    ins_p.add_argument("binary_path", help="Path to executable or DLL to reverse-engineer")

    # setup (Hands-free REA and Ghidra environment configuration)
    setup_p = subparsers.add_parser("setup", help="Audit and configure hands-free REA and Ghidra environment")
    setup_p.add_argument("--ghidra", action="store_true", help="Download and configure official portable Ghidra release")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        handle_scan(args)
    elif args.command == "clean-all":
        handle_clean_all(args)
    elif args.command == "firewall":
        handle_firewall(args)
    elif args.command == "sandbox":
        handle_sandbox(args)
    elif args.command == "replace-emu":
        handle_replace_emu(args)
    elif args.command == "inspect":
        handle_inspect(args)
    elif args.command == "setup":
        handle_setup(args)


if __name__ == "__main__":
    main()
