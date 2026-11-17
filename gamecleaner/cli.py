"""
GameCleaner CLI: Triage, quarantine, and contain malware packed in games.
"""
import argparse
from pathlib import Path
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from gamecleaner.analyzer import (
    PEScanner,
    ScriptScanResult,
    ThreatSeverity,
)
from gamecleaner.cleaner import EmulatorReplacer, RepackUnpacker, SaveGameMigrator
from gamecleaner.containment import FirewallManager, SandboxGenerator, ShellIntegrationManager
from gamecleaner.pipeline import GameCleanerPipeline

console = Console()


def handle_scan(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]Scanning directory:[/bold cyan] {target}\n"
        "Analyzing PE headers, Authenticode signatures, suspicious APIs, and scripts...",
        title="GameCleaner Threat Triage",
    ))

    pipeline = GameCleanerPipeline(target)
    with console.status("[bold green]Performing static triage on binaries..."):
        results = pipeline.run_scan_only()

    if not results:
        console.print("[yellow]No executable binaries (.exe, .dll) or scripts found.[/yellow]")
        return

    table = Table(title=f"Scan Results for {target.name}", show_lines=True)
    table.add_column("File Name", style="bold", no_wrap=True)
    table.add_column("Type", justify="center")
    table.add_column("Threat Score", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Verdict")
    table.add_column("Action", justify="center")

    for res in results:
        # Determine threat badge
        score = res.threat_score
        if res.overall_severity == ThreatSeverity.CRITICAL.value:
            sev_badge = f"[bold red]{res.overall_severity}[/bold red]"
            score_badge = f"[bold red]{score}[/bold red]"
        elif res.overall_severity in (ThreatSeverity.HIGH.value, ThreatSeverity.MEDIUM.value):
            sev_badge = f"[yellow]{res.overall_severity}[/yellow]"
            score_badge = f"[yellow]{score}[/yellow]"
        else:
            sev_badge = f"[green]{res.overall_severity}[/green]"
            score_badge = f"[green]{score}[/green]"

        act_badge = "[bold red]QUARANTINE[/bold red]" if res.recommended_action == "QUARANTINE" else f"[dim]{res.recommended_action}[/dim]"
        if hasattr(res, "architecture"):
            arch_str = res.architecture
        elif isinstance(res, ScriptScanResult):
            arch_str = f"Script ({res.extension})"
        else:
            arch_str = "LNK"

        table.add_row(
            res.file_name,
            arch_str,
            score_badge,
            sev_badge,
            res.verdict,
            act_badge,
        )

    console.print(table)


def handle_clean_all(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        sys.exit(1)

    # Seamless archive/installer handling: if target is a .zip, .7z, .rar, or setup.exe
    if target.is_file():
        unpacker = RepackUnpacker()
        suffix = target.suffix.lower()
        if suffix in (".zip", ".rar", ".7z", ".tar", ".gz") or unpacker.is_inno_setup(target):
            out_dir = Path(args.output).resolve() if getattr(args, "output", None) else target.with_suffix("")
            console.print(Panel(
                f"[bold cyan]Archive / Installer Detected:[/bold cyan] {target.name}\n"
                f"Destination: [green]{out_dir}[/green]\n"
                "Unpacking safely and executing full security and containment pipeline...",
                title="Pre-Install Safe Unpack & Clean",
            ))
            with console.status(f"[bold cyan]Extracting archive and cleaning files into {out_dir.name}..."):
                res = unpacker.unpack(target, out_dir, auto_clean=True)
            if res.success:
                console.print(f"\n[bold green]✓ Unpack Succeeded![/bold green] Extracted [cyan]{res.extracted_files_count}[/cyan] files via [bold]{res.extractor_used}[/bold].")
                console.print(f"[bold green]✓ Full Pipeline Applied:[/bold green] Binaries sanitized, clean emulators installed, and containment prepared.")
                console.print(f"\n[cyan]Clean game is ready to play at:[/cyan]\n  • [bold]{out_dir}[/bold]")
            else:
                console.print(f"\n[bold red]✗ Extraction Failed:[/bold red] {res.error_message}")
            return

    console.print(Panel(
        f"[bold cyan]Initiating Full Security & Remediation Pipeline:[/bold cyan] {target}\n\n"
        "• Static PE & Script Threat Analysis\n"
        "• AI-Assisted Decompiler Triage\n"
        "• Clean Goldberg Emulator Replacement (Multi-DRM)\n"
        "• Save Game & SteamID Identity Preservation\n"
        "• Quarantine Isolation of Hostile Malware\n"
        "• Windows Persistence Neutralization (Registry & Tasks)\n"
        "• Windows Firewall Outbound Network Isolation\n"
        "• Windows Sandbox (.wsb) Air-gapped Profile Generation",
        title="GameCleaner Pipeline Orchestration",
    ))

    pipeline = GameCleanerPipeline(
        target_dir=target,
        auto_quarantine=not args.no_quarantine,
        auto_replace_emu=not args.no_replace_emu,
        auto_migrate_saves=not getattr(args, "no_migrate_saves", False),
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
    if report.saves_migrated and report.saves_migrated.get("goldberg_settings_configured"):
        summary_table.add_row("Save & SteamID Migration", f"[green]Preserved (AppID {report.saves_migrated.get('app_id')})[/green]")
    summary_table.add_row("Firewall Script", f"[dim]{report.firewall_script_created}[/dim]")
    summary_table.add_row("Sandbox Config", f"[dim]{report.sandbox_file_created}[/dim]")

    console.print(summary_table)

    if report.quarantined_files:
        console.print(f"\n[bold red]Quarantined Files:[/bold red] {', '.join(report.quarantined_files)}")
    if report.replaced_emulators:
        console.print(f"[bold green]Clean Emulators Installed:[/bold green] {', '.join(report.replaced_emulators)}")
    if report.saves_migrated and report.saves_migrated.get("migrated_files"):
        console.print(f"[bold green]Saves Migrated to Goldberg:[/bold green] {len(report.saves_migrated['migrated_files'])} file(s)")

    if report.ai_triage_reports:
        console.print("\n[bold cyan]AI Decompiler Triage Findings:[/bold cyan]")
        for ai in report.ai_triage_reports:
            p_name = Path(ai['binary_path']).name
            console.print(f"  • [bold]{p_name}[/bold]: [yellow]{ai['offline_heuristic_verdict']}[/yellow] (Confidence: {ai['offline_confidence']*100:.0f}%)")

    console.print(f"\n[cyan]Detailed audit reports saved to:[/cyan]")
    console.print(f"  • {target / 'gamecleaner_report.md'}")
    console.print(f"  • {target / 'gamecleaner_report.json'}")


def handle_unpack(args):
    installer = Path(args.installer).resolve()
    out = Path(args.output).resolve() if args.output else installer.with_suffix("")
    auto_clean = not args.no_clean

    console.print(Panel(
        f"[bold cyan]Pre-Install Repack Extraction[/bold cyan]\n"
        f"Installer: [yellow]{installer}[/yellow]\n"
        f"Destination: [green]{out}[/green]\n"
        f"Auto-Clean During Installation: [bold]{'Yes (Enabled)' if auto_clean else 'No'}[/bold]",
        title="Safe Pre-Install Extractor",
    ))

    unpacker = RepackUnpacker()
    with console.status("[bold cyan]Extracting files without running setup.exe..."):
        res = unpacker.unpack(installer, out, auto_clean=auto_clean)

    if res.success:
        console.print(f"\n[bold green]✓ Extraction Succeeded![/bold green] Extracted [cyan]{res.extracted_files_count}[/cyan] files via [bold]{res.extractor_used}[/bold].")
        if res.cleaned_after_unpack:
            console.print("[bold green]✓ Auto-Clean Completed:[/bold green] Binaries sanitized, clean emulators installed, and firewall scripts prepared.")
    else:
        console.print(f"\n[bold red]✗ Extraction Failed:[/bold red] {res.error_message}")


def handle_migrate_saves(args):
    target = Path(args.path).resolve()
    migrator = SaveGameMigrator(target)
    with console.status("[bold cyan]Auditing scene crack configurations and locating save files..."):
        res = migrator.migrate_saves(app_id=args.app_id)

    console.print(Panel(
        f"[bold green]Save Game & SteamID Migration Summary[/bold green]\n"
        f"• AppID: [cyan]{res.app_id or 'Unknown'}[/cyan]\n"
        f"• Persona Name: [cyan]{res.account_name}[/cyan]\n"
        f"• SteamID: [cyan]{res.steam_id or 'Auto'}[/cyan]\n"
        f"• Goldberg Identity Configured: [bold]{'Yes' if res.goldberg_settings_configured else 'No'}[/bold]\n"
        f"• Existing Saves Found At: [dim]{res.saves_found_at or 'None detected'}[/dim]\n"
        f"• Files Migrated to Goldberg: [cyan]{len(res.migrated_files)}[/cyan]",
        title="Save Game Migrator",
    ))


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
    read_only = not args.read_write
    wsb_path = sg.generate_wsb(read_only=read_only, v_gpu=True, allow_network=False)
    bat_path = sg.generate_batch_runner()

    console.print(Panel(
        f"[bold green]Windows Sandbox & Isolated Launchers Generated:[/bold green]\n"
        f"• Sandbox Config:  [cyan]{wsb_path}[/cyan]\n"
        f"• Fallback Runner: [cyan]{bat_path}[/cyan]\n\n"
        f"Host Sandbox Support: {'[green]Enabled[/green]' if sg.is_supported else '[yellow]Disabled (Enable in Windows Features)[/yellow]'}\n\n"
        "Double-click the .wsb file to boot an isolated, air-gapped Windows desktop to test this game.",
        title="Air-Gapped Sandbox Containment",
    ))


def handle_replace_emu(args):
    target = Path(args.path).resolve()
    er = EmulatorReplacer(target)
    targets = er.find_drm_targets()

    if not targets:
        console.print("[yellow]No Steam/Epic/Ubisoft DRM wrapper DLLs found in directory.[/yellow]")
        return

    console.print(f"[cyan]Found {len(targets)} DRM wrapper targets:[/cyan]")
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

    out_file = Path.cwd() / f"REA_EVIDENCE_{target.name}.md"
    try:
        out_file.write_text(dossier, encoding="utf-8")
    except Exception:
        pass

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
    shell_mgr = ShellIntegrationManager()
    unpacker = RepackUnpacker()

    console.print(Panel(
        "[bold cyan]GameCleaner & REA Automated Environment Setup[/bold cyan]\n"
        "Verifying Java, Node.js, REA MCP Server, Ghidra Decompiler, Shell Menus, and Unpackers...",
        title="Setup & Diagnostics",
    ))

    # Setup All Flag
    if getattr(args, "all", False):
        setattr(args, "context_menu", True)
        setattr(args, "unpacker", True)

    # Context Menu Actions
    if getattr(args, "context_menu", False):
        ok, msg = shell_mgr.install()
        if ok:
            console.print(f"[bold green]✓[/bold green] {msg}")
        else:
            console.print(f"[bold red]✗[/bold red] {msg}")

    if getattr(args, "remove_context_menu", False):
        ok, msg = shell_mgr.uninstall()
        if ok:
            console.print(f"[bold green]✓[/bold green] {msg}")
        else:
            console.print(f"[bold red]✗[/bold red] {msg}")

    if getattr(args, "unpacker", False):
        with console.status("[bold cyan]Ensuring innoextract portable binary is installed..."):
            bin_path = unpacker.ensure_innoextract()
        if bin_path:
            console.print(f"[bold green]✓[/bold green] innoextract configured at: {bin_path}")
        else:
            console.print("[bold red]✗[/bold red] Failed to configure innoextract.")

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

    # Shell Integration
    sh_badge = "[green]Active[/green]" if shell_mgr.is_installed() else "[yellow]Not Installed[/yellow]"
    status_table.add_row("Explorer Context Menu", sh_badge, "Right-click 'Clean with GameCleaner' (Run 'setup --context-menu')")

    # Unpacker
    unp_bin = unpacker.ensure_innoextract()
    unp_badge = "[green]Ready[/green]" if unp_bin else "[yellow]Not Configured[/yellow]"
    status_table.add_row("Repack Unpacker (Inno)", unp_badge, str(unp_bin) if unp_bin else "Run 'setup --unpacker' to configure")

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
    clean_p = subparsers.add_parser("clean-all", help="Run full pipeline (scan, AI triage, save migration, quarantine, replace emu, firewall, sandbox)")
    clean_p.add_argument("path", help="Path to game directory or archive (.zip, .7z, .rar, setup.exe)")
    clean_p.add_argument("-o", "--output", default=None, help="Destination directory if path is an archive or installer (e.g. -o D:\\Games\\MyGame)")
    clean_p.add_argument("--no-quarantine", action="store_true", help="Skip automatic quarantine of critical malware")
    clean_p.add_argument("--no-replace-emu", action="store_true", help="Skip replacing Steam wrappers with Goldberg")
    clean_p.add_argument("--no-migrate-saves", action="store_true", help="Skip migrating existing scene saves to Goldberg")
    clean_p.add_argument("--no-firewall", action="store_true", help="Skip generating firewall isolation rules")
    clean_p.add_argument("--no-sandbox", action="store_true", help="Skip generating Windows Sandbox profile")

    # unpack (Pre-install Repack Extractor)
    unpack_p = subparsers.add_parser("unpack", help="Pre-install repack extractor: Unpack setup.exe/archives without executing code")
    unpack_p.add_argument("installer", help="Path to installer (setup.exe, archive, etc.)")
    unpack_p.add_argument("-o", "--output", default=None, help="Destination directory for unpacked game files (default: folder matching archive name)")
    unpack_p.add_argument("--clean", dest="no_clean", action="store_false", help="Auto-clean game directory during installation (Default)")
    unpack_p.add_argument("--no-clean", dest="no_clean", action="store_true", help="Do not run clean-all after unpacking")
    unpack_p.set_defaults(no_clean=False)

    # migrate-saves
    save_p = subparsers.add_parser("migrate-saves", help="Preserve scene crack saves and configure Goldberg identity")
    save_p.add_argument("path", help="Path to game directory")
    save_p.add_argument("--app-id", help="Explicit Steam AppID (optional)")

    # firewall
    fw_p = subparsers.add_parser("firewall", help="Generate firewall isolation rules for all game executables")
    fw_p.add_argument("path", help="Path to game directory")
    fw_p.add_argument("--elevate", action="store_true", help="Launch UAC prompt to apply rules immediately with Admin rights")

    # sandbox
    sb_p = subparsers.add_parser("sandbox", help="Generate Windows Sandbox (.wsb) air-gapped configuration")
    sb_p.add_argument("path", help="Path to game directory")
    sb_p.add_argument("--read-write", action="store_true", help="Mount game directory as read-write instead of read-only")

    # replace-emu
    emu_p = subparsers.add_parser("replace-emu", help="Replace untrusted Steam/Epic/Ubisoft DLLs with clean emulators")
    emu_p.add_argument("path", help="Path to game directory")
    emu_p.add_argument("--custom-dll", help="Path to verified clean emulator DLL")

    # inspect (REA Deep Reverse Engineering)
    ins_p = subparsers.add_parser("inspect", help="REA deep reverse-engineering and evidence dossier on a binary")
    ins_p.add_argument("binary_path", help="Path to executable or DLL to reverse-engineer")

    # setup (Hands-free REA, Ghidra, Shell Context Menu, and Unpacker)
    setup_p = subparsers.add_parser("setup", help="Audit and configure hands-free REA, Ghidra, and Windows Explorer shell integration")
    setup_p.add_argument("--all", action="store_true", help="One-command hands-free setup: register context menu, unpacker, and verify all tools")
    setup_p.add_argument("--check", action="store_true", help="Audit and display environment readiness")
    setup_p.add_argument("--ghidra", action="store_true", help="Download and configure official portable Ghidra release")
    setup_p.add_argument("--context-menu", action="store_true", help="Add 'Clean & Contain with GameCleaner' to Windows Explorer right-click menu")
    setup_p.add_argument("--remove-context-menu", action="store_true", help="Remove GameCleaner from Windows Explorer context menu")
    setup_p.add_argument("--unpacker", action="store_true", help="Download and configure innoextract pre-install unpacker")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        handle_scan(args)
    elif args.command == "clean-all":
        handle_clean_all(args)
    elif args.command == "unpack":
        handle_unpack(args)
    elif args.command == "migrate-saves":
        handle_migrate_saves(args)
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
