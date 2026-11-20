"""
GameCleaner CLI: Triage, quarantine, and contain malware packed in games.
"""
import argparse
from pathlib import Path
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from gamecleaner.analyzer import (
    PEScanner,
    ScriptScanResult,
    ThreatSeverity,
    SideloadAuditor,
    RuntimeAuditor,
    DriverAuditor,
    SteamStubDetector,
    CrashForensics,
    AntiCheatDetector,
    ModCompatibilityAuditor,
    MemoryScanner,
)
from gamecleaner.analyzer.runtime_auditor import DEPENDENCY_PACKAGES
from gamecleaner.cleaner import (
    EmulatorReplacer,
    QuarantineManager,
    RepackUnpacker,
    SaveGameMigrator,
    IntegrityVerifier,
    SteamlessUnpacker,
    SaveSyncManager,
    EOSReplacer,
    MultiDRMOrchestrator,
    CloudSaveSync,
)
from gamecleaner.containment import (
    FirewallManager,
    SandboxGenerator,
    ShellIntegrationManager,
    ProcessShield,
    ProtonHelper,
    NetworkMonitor,
    is_running_as_admin,
    is_sandbox_supported,
)
from gamecleaner.pipeline import GameCleanerPipeline
from gamecleaner.web import start_server

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

console = Console(legacy_windows=False, safe_box=True)


def handle_scan(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        sys.exit(1)

    target_desc = f"binary/script: {target.name}" if target.is_file() else f"directory: {target}"
    console.print(Panel(
        f"[bold cyan]Scanning {target_desc}[/bold cyan]\n"
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
                console.print(f"\n[bold green][+] Unpack Succeeded![/bold green] Extracted [cyan]{res.extracted_files_count}[/cyan] files via [bold]{res.extractor_used}[/bold].")
                console.print(f"[bold green][+] Full Pipeline Applied:[/bold green] Binaries sanitized, clean emulators installed, and containment prepared.")
                console.print(f"\n[cyan]Clean game is ready to play at:[/cyan]\n  • [bold]{out_dir}[/bold]")
            else:
                console.print(f"\n[bold red]✗ Extraction Failed:[/bold red] {res.error_message}")
                sys.exit(1)
            return
        else:
            # User passed an executable file instead of folder (e.g. C:\Games\Doom\game.exe)
            user_home = Path.home().resolve()
            dangerous_parents = {
                user_home,
                user_home / "Desktop",
                user_home / "Downloads",
                user_home / "Documents",
                Path(target.anchor).resolve(),
            }
            if target.parent.resolve() in dangerous_parents:
                console.print(f"[bold red]Error:[/bold red] Refusing to sanitize '{target.name}' by targeting its parent directory: {target.parent} (protected user/system directory).")
                console.print("[yellow]Tip:[/yellow] Please place game files in a dedicated game directory or pass an archive / installer.")
                sys.exit(1)

            console.print(f"[cyan]Target is a file; targeting parent directory:[/cyan] [bold]{target.parent}[/bold]")
            target = target.parent

    # Support -o/--output when target is an existing directory
    if getattr(args, "output", None) and target.is_dir():
        import shutil
        out_dir = Path(args.output).resolve()
        if out_dir != target:
            console.print(f"[cyan]Destination directory specified:[/cyan] [green]{out_dir}[/green]")
            with console.status(f"[cyan]Copying game directory to destination..."):
                shutil.copytree(str(target), str(out_dir), dirs_exist_ok=True)
            target = out_dir

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
    if not installer.exists():
        console.print(f"[bold red]Error:[/bold red] Installer file not found: {installer}")
        sys.exit(1)

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
        console.print(f"\n[bold green][+] Extraction Succeeded![/bold green] Extracted [cyan]{res.extracted_files_count}[/cyan] files via [bold]{res.extractor_used}[/bold].")
        if res.cleaned_after_unpack:
            console.print("[bold green][+] Auto-Clean Completed:[/bold green] Binaries sanitized, clean emulators installed, and firewall scripts prepared.")
    else:
        console.print(f"\n[bold red]✗ Extraction Failed:[/bold red] {res.error_message}")
        sys.exit(1)


def handle_migrate_saves(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

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
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

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
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

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
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    custom = None
    if getattr(args, "custom_dll", None):
        custom = Path(args.custom_dll).resolve()
        if not custom.exists():
            console.print(f"[bold red]Error:[/bold red] Custom clean DLL not found: {custom}")
            sys.exit(1)

    er = EmulatorReplacer(target)
    targets = er.find_drm_targets()

    if not targets:
        console.print("[yellow]No Steam/Epic/Ubisoft DRM wrapper DLLs found in directory.[/yellow]")
        return

    console.print(f"[cyan]Found {len(targets)} DRM wrapper targets:[/cyan]")
    for t in targets:
        success, msg = er.replace_with_clean_emulator(t, custom_clean_dll=custom)
        if success:
            console.print(f"  [green][+][/green] {t.dll_name} ({t.architecture}) -> {msg}")
        else:
            console.print(f"  [red]✗[/red] {t.dll_name} ({t.architecture}) -> {msg}")


def handle_inspect(args):
    target = Path(args.binary_path).resolve()
    if not target.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {target}")
        sys.exit(1)

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


def handle_quarantine(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    qm = QuarantineManager(target)

    # 1. Action: Restore single file
    if getattr(args, "restore", None):
        with console.status(f"[bold cyan]Restoring {args.restore} from quarantine vault..."):
            ok = qm.restore_file(args.restore)
        if ok:
            console.print(f"[bold green][+] Successfully Restored:[/bold green] {args.restore} back to its original location.")
        else:
            console.print(f"[bold red]✗ Restore Failed:[/bold red] '{args.restore}' not found in quarantine manifest or file missing.")
            sys.exit(1)
        return

    # 2. Action: Restore all files
    if getattr(args, "restore_all", False):
        items = qm.list_quarantined()
        if not items:
            console.print("[yellow]Quarantine vault is empty. Nothing to restore.[/yellow]")
            return
        restored = 0
        for item in items:
            if qm.restore_file(item.quarantined_filename):
                console.print(f"  [green][+] Restored:[/green] {item.original_rel_path} ({item.quarantined_filename})")
                restored += 1
            else:
                console.print(f"  [red]✗ Failed to restore:[/red] {item.quarantined_filename}")
        console.print(f"\n[bold green]Restoration complete:[/bold green] {restored}/{len(items)} files restored.")
        return

    # 3. Action: Manually quarantine a file
    if getattr(args, "add", None):
        file_to_q = Path(args.add).resolve()
        if not file_to_q.exists():
            console.print(f"[bold red]Error:[/bold red] File to quarantine not found: {file_to_q}")
            sys.exit(1)
        reason = getattr(args, "reason", "Manual quarantine isolation via CLI") or "Manual quarantine isolation via CLI"
        dest = qm.quarantine_file(file_to_q, reason=reason, sha256="")
        if dest:
            console.print(f"[bold green][+] File Quarantined:[/bold green] {file_to_q.name} -> {dest.name}")
        else:
            console.print(f"[bold red]✗ Quarantine Failed:[/bold red] Could not isolate {file_to_q.name}")
            sys.exit(1)
        return

    # 4. Default / Action: List quarantined files
    items = qm.list_quarantined()
    if not items:
        console.print(Panel(
            f"[bold green]Quarantine Vault Clean[/bold green]\n"
            f"Vault Location: [cyan]{qm.quarantine_dir}[/cyan]\n"
            "No files are currently quarantined or isolated in this directory.",
            title=f"Quarantine Status: {target.name}",
        ))
        return

    table = Table(title=f"Quarantined Files in {target.name} Vault ({len(items)} items)", show_lines=True)
    table.add_column("Quarantined File", style="bold red", no_wrap=True)
    table.add_column("Original Location")
    table.add_column("Verdict / Reason", style="yellow")
    table.add_column("SHA-256", style="dim", justify="center")
    table.add_column("Quarantined Date", justify="center")

    for item in items:
        sha_display = item.sha256[:12] + "..." if item.sha256 and len(item.sha256) > 12 else (item.sha256 or "N/A")
        table.add_row(
            item.quarantined_filename,
            item.original_rel_path,
            item.reason,
            sha_display,
            item.timestamp[:19] if item.timestamp else "N/A",
        )

    console.print(table)
    console.print(f"\n[yellow]Tip:[/yellow] To restore a false-positive file, run: [bold]gamecleaner quarantine \"{target}\" --restore <FILENAME>[/bold]")


def handle_rollback(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    er = EmulatorReplacer(target)

    # 1. Action: Roll back specific backup
    if getattr(args, "backup", None):
        with console.status(f"[bold cyan]Restoring backup {args.backup}..."):
            ok = er.rollback_backup(args.backup)
        if ok:
            console.print(f"[bold green][+] Successfully Restored:[/bold green] Backup '{args.backup}' rolled back to original path.")
        else:
            console.print(f"[bold red]✗ Rollback Failed:[/bold red] Backup '{args.backup}' not found in manifest or file missing.")
            sys.exit(1)
        return

    # 2. Action: Roll back all backups
    if getattr(args, "all", False):
        results = er.rollback_all()
        if not results:
            console.print("[yellow]No backups found in .gamecleaner_backup to restore.[/yellow]")
            return
        restored = 0
        for b_name, ok in results:
            if ok:
                console.print(f"  [green][+] Restored:[/green] {b_name}")
                restored += 1
            else:
                console.print(f"  [red]✗ Failed to restore:[/red] {b_name}")
        console.print(f"\n[bold green]Rollback complete:[/bold green] {restored}/{len(results)} backups restored.")
        return

    # 3. Default: List backups
    backups = er.list_backups()
    if not backups:
        console.print(Panel(
            f"[bold yellow]No Emulator Backups Found[/bold yellow]\n"
            f"Backup Location: [cyan]{er.backup_dir}[/cyan]\n"
            "No original DLL backups exist for this game directory.",
            title=f"Rollback Status: {target.name}",
        ))
        return

    table = Table(title=f"Available Emulator Backups for {target.name} ({len(backups)} items)", show_lines=True)
    table.add_column("Backup File", style="bold cyan", no_wrap=True)
    table.add_column("Original Target Path")
    table.add_column("Arch", justify="center")
    table.add_column("Backup Timestamp", justify="center")

    for b in backups:
        table.add_row(
            b.get("backup_file", ""),
            b.get("original_path", b.get("relative_path", "")),
            b.get("architecture", "N/A"),
            b.get("timestamp", "N/A")[:19],
        )

    console.print(table)
    console.print(f"\n[yellow]Tip:[/yellow] Run [bold]gamecleaner rollback \"{target}\" --backup <FILE>[/bold] or [bold]--all[/bold] to restore original binaries.")


def handle_status(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    with console.status(f"[bold cyan]Auditing game security posture in {target.name}..."):
        exes = [p for p in target.rglob("*.exe") if ".gamecleaner" not in str(p) and ".quarantine" not in str(p)]
        dlls = [p for p in target.rglob("*.dll") if ".gamecleaner" not in str(p) and ".quarantine" not in str(p)]

        er = EmulatorReplacer(target)
        app_id = er.discover_appid(target) or "Not detected"
        drm_targets = er.find_drm_targets()

        has_appid_file = (target / "steam_appid.txt").exists() or (target / "steam_settings" / "steam_appid.txt").exists()
        has_settings_dir = (target / "steam_settings").is_dir()
        has_dlc = (target / "steam_settings" / "DLC.txt").exists()
        has_interfaces = (target / "steam_interfaces.txt").exists() or (target / "steam_settings" / "steam_interfaces.txt").exists()

        qm = QuarantineManager(target)
        quarantined_files = qm.list_quarantined()

        backups = er.list_backups()

        fm = FirewallManager(target)
        has_firewall_script = (target / "block_game_network.ps1").exists()
        rules_applied = False
        try:
            import subprocess
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Get-NetFirewallRule -DisplayName '{fm.rule_prefix}*' | Select-Object -First 1"],
                capture_output=True, text=True, timeout=5,
            )
            rules_applied = proc.returncode == 0 and bool(proc.stdout.strip())
        except Exception:
            pass

        sg = SandboxGenerator(target)
        wsb_file = target / f"Sandbox_{sg.game_name}.wsb"
        has_wsb = wsb_file.exists()
        has_isolated_bat = (target / "Launch_Game_Isolated.bat").exists()
        sandbox_supported = sg.is_supported

        has_report_md = (target / "gamecleaner_report.md").exists()
        has_report_json = (target / "gamecleaner_report.json").exists()

    console.print(Panel(
        f"[bold cyan]Game Directory:[/bold cyan] {target}\n"
        f"[bold cyan]Detected Steam AppID:[/bold cyan] [bold yellow]{app_id}[/bold yellow]\n"
        f"[bold cyan]Binaries:[/bold cyan] {len(exes)} Executables (.exe), {len(dlls)} Dynamic Libraries (.dll)",
        title=f"GameCleaner Security Status: {target.name}",
    ))

    table = Table(title="Containment & Protection Posture", show_lines=True)
    table.add_column("Security Component", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details")

    if drm_targets:
        targets_str = ", ".join(f"{t.dll_name} ({t.platform} {t.architecture})" for t in drm_targets)
        emu_badge = "[green]Configured[/green]" if has_appid_file else "[yellow]Detected (Needs Setup)[/yellow]"
        table.add_row("DRM Wrapper DLLs", emu_badge, targets_str)
    else:
        table.add_row("DRM Wrapper DLLs", "[dim]None Found[/dim]", "No Steam/Epic/Ubisoft wrapper DLLs detected")

    goldberg_items = []
    if has_appid_file: goldberg_items.append("steam_appid.txt")
    if has_settings_dir: goldberg_items.append("steam_settings/")
    if has_interfaces: goldberg_items.append("steam_interfaces.txt")
    if has_dlc: goldberg_items.append("DLC.txt")
    g_status = "[green]Active[/green]" if goldberg_items else "[yellow]Not Configured[/yellow]"
    table.add_row("Goldberg Integration", g_status, ", ".join(goldberg_items) if goldberg_items else "Run 'clean-all' or 'replace-emu'")

    q_badge = f"[red bold]{len(quarantined_files)} Files Isolated[/red bold]" if quarantined_files else "[green]Clean (0 Files)[/green]"
    table.add_row("Quarantine Vault", q_badge, f"Vault: {qm.quarantine_dir.name} (Run 'quarantine' to inspect/restore)")

    b_badge = f"[cyan]{len(backups)} Backups[/cyan]" if backups else "[dim]0 Backups[/dim]"
    table.add_row("Rollback Backups", b_badge, f"Backups in {er.backup_dir.name} (Run 'rollback' to restore original DLLs)")

    if rules_applied:
        fw_badge = "[bold green]Active (Rules Applied)[/bold green]"
        fw_det = f"Rules active with prefix {fm.rule_prefix}"
    elif has_firewall_script:
        fw_badge = "[yellow]Script Ready (Not Applied)[/yellow]"
        fw_det = "Run block_game_network.ps1 as Admin or 'gamecleaner firewall --elevate'"
    else:
        fw_badge = "[dim]Not Generated[/dim]"
        fw_det = "Run 'gamecleaner firewall' to create network isolation script"
    table.add_row("Firewall Isolation", fw_badge, fw_det)

    sb_det = []
    if has_wsb: sb_det.append(wsb_file.name)
    if has_isolated_bat: sb_det.append("Launch_Game_Isolated.bat")
    host_sb_str = "Host Sandbox Supported" if sandbox_supported else "Host Sandbox Unsupported (Home Edition)"
    sb_badge = "[green]Ready[/green]" if has_wsb else "[dim]Not Generated[/dim]"
    table.add_row("Air-Gapped Sandbox", sb_badge, f"{', '.join(sb_det) or 'None'} ({host_sb_str})")

    rep_badge = "[green]Generated[/green]" if (has_report_md or has_report_json) else "[dim]None[/dim]"
    table.add_row("Audit Dossiers", rep_badge, "gamecleaner_report.md / json" if (has_report_md or has_report_json) else "Run 'clean-all' to generate full audit")

    console.print(table)


def handle_verify(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    verifier = IntegrityVerifier(target)
    if getattr(args, "create", False):
        with console.status("[bold cyan]Generating cryptographic SHA-256 integrity manifest..."):
            manifest_p = verifier.create_manifest()
        console.print(f"[bold green][+][/bold green] Cryptographic manifest generated: [bold]{manifest_p}[/bold]")
        return

    with console.status("[bold cyan]Verifying file integrity against manifest..."):
        report = verifier.verify()

    if not report.manifest_path or not Path(report.manifest_path).exists():
        console.print(f"[bold yellow]Warning:[/bold yellow] No manifest found. Run [bold]gamecleaner verify \"{target}\" --create[/bold] to generate one.")
        return

    if report.is_valid:
        console.print(Panel(
            f"[bold green][+] 100% Game Integrity Verified![/bold green]\n"
            f"All {report.total_verified} binaries and configuration files match their cryptographic SHA-256 hashes.\n"
            f"No file corruption, tampering, or newly injected unknown binaries detected.",
            title=f"Integrity Check: {target.name}",
        ))
    else:
        console.print(Panel(
            f"[bold red]✗ Integrity Validation Failed![/bold red]\n"
            f"Verified Files: {report.total_verified}\n"
            f"Missing Files: {len(report.missing_files)}\n"
            f"Modified/Corrupt Files: {len(report.modified_files)}\n"
            f"Untracked/New Injected Binaries: {len(report.untracked_binaries)}",
            title=f"Integrity Alert: {target.name}",
        ))
        if report.tamper_alerts:
            for alert in report.tamper_alerts:
                console.print(f"  [bold red]•[/bold red] {alert}")


def handle_deps(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    auditor = RuntimeAuditor(target)
    with console.status("[bold cyan]Scanning PE imports and verifying required runtimes..."):
        report = auditor.audit()

    table = Table(title=f"Dependency & Runtime Audit: {target.name}", show_lines=True)
    table.add_column("Required DLL", style="bold")
    table.add_column("Runtime Package")
    table.add_column("Status", justify="center")
    table.add_column("Bundled Repack Installer")

    missing_map = {m.dll_name: m for m in report.missing_dependencies}
    for dll in report.required_dlls:
        if dll in missing_map:
            m = missing_map[dll]
            status = "[bold red]Missing on Host[/bold red]"
            inst = m.installer_path or "Not bundled (Download required)"
        else:
            status = "[bold green]Installed / Present[/bold green]"
            inst = "[dim]N/A[/dim]"
        table.add_row(dll, DEPENDENCY_PACKAGES.get(dll, {}).get("package", "Unknown"), status, inst)

    console.print(table)

    if report.discovered_redists:
        console.print(f"\n[bold cyan]Discovered Repack Redists ({len(report.discovered_redists)}):[/bold cyan]")
        for dr in report.discovered_redists:
            console.print(f"  • [bold]{dr.name}[/bold]: `{dr.file_path}`")

    if getattr(args, "install", False) and report.discovered_redists:
        import subprocess
        for dr in report.discovered_redists:
            console.print(f"[cyan]Installing {dr.name}...[/cyan]")
            try:
                cmd = f'"{dr.file_path}" {dr.recommended_silent_args}'
                subprocess.run(cmd, shell=True, timeout=120)
                console.print(f"[green][+][/green] Installed {dr.name}")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to install {dr.name}: {e}")


def handle_sideload(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    auditor = SideloadAuditor(target)
    with console.status("[bold cyan]Scanning for DLL Search-Order Hijacking and Proxy DLLs..."):
        findings = auditor.audit()

    if not findings:
        console.print(f"[bold green][+][/bold green] No sideloaded system DLLs detected in {target.name}.")
        return

    table = Table(title=f"DLL Sideloading & Proxy Audit: {target.name}", show_lines=True)
    table.add_column("DLL Name", style="bold", no_wrap=True)
    table.add_column("Classification", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Target Executable")
    table.add_column("Description")

    for f in findings:
        if f.is_legitimate_mod:
            cls_badge = f"[green]Mod ({f.mod_framework})[/green]"
            sev_badge = "[dim]INFO[/dim]"
        elif f.severity == ThreatSeverity.HIGH:
            cls_badge = "[bold red]Hostile Proxy[/bold red]"
            sev_badge = "[bold red]HIGH[/bold red]"
        else:
            cls_badge = "[yellow]Potential Proxy[/yellow]"
            sev_badge = "[yellow]MEDIUM[/yellow]"

        table.add_row(f.dll_name, cls_badge, sev_badge, f.target_exe or "Unknown", f.description)

    console.print(table)


def handle_run(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory or game file does not exist: {target}")
        sys.exit(1)

    game_dir = target if target.is_dir() else target.parent
    console.print(Panel(
        f"[bold cyan]Smart Isolated Game Launcher: {game_dir.name}[/bold cyan]\n"
        "Verifying firewall socket isolation, repairing accidental blocks, checking runtimes, and launching...",
        title="GameCleaner Smart Runner",
    ))

    # 1. Remediate Windows Firewall Cancel Trap
    fm = FirewallManager(game_dir)
    fix_script = game_dir / "Fix_Firewall_And_Run.bat"
    if not fix_script.exists():
        fm.generate_fix_and_run_script()

    # 2. Check for game executable
    game_exe = None
    if target.is_file() and target.suffix.lower() == ".exe":
        game_exe = target
    else:
        for p in game_dir.glob("*.exe"):
            if not p.name.lower().startswith("unins") and "crash" not in p.name.lower() and "dxsetup" not in p.name.lower():
                game_exe = p
                break
        if not game_exe:
            for sub in ("bin/x64", "bin", "Binaries/Win64", "Binaries/Win32", "x64"):
                sub_p = game_dir / sub
                if sub_p.exists():
                    for p in sub_p.glob("*.exe"):
                        if not p.name.lower().startswith("unins") and "crash" not in p.name.lower():
                            game_exe = p
                            break
                    if game_exe:
                        break

    if not game_exe:
        console.print("[bold red]Error:[/bold red] Could not locate primary game executable.")
        sys.exit(1)

    # 3. Automated Point-in-Time Save Snapshot before launch
    try:
        er = EmulatorReplacer(game_dir)
        appid = er.discover_appid(game_dir) or "UnknownAppID"
        SaveSyncManager().create_snapshot(game_dir, appid=appid, note="Pre-launch automatic snapshot")
        console.print("[dim][+] Automated save snapshot captured.[/dim]")
    except Exception:
        pass

    console.print(f"[green][+][/green] Found game executable: [bold]{game_exe}[/bold]")
    console.print(f"[cyan]Starting game in working directory:[/cyan] `{game_exe.parent}`")

    import subprocess
    try:
        subprocess.Popen([str(game_exe)], cwd=str(game_exe.parent))
        console.print("[bold green][+] Game process launched successfully![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to launch game executable:[/bold red] {e}")


def handle_shield(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    shield = ProcessShield(target)
    shield.generate_shield_script()
    shield.generate_unshield_script()

    if getattr(args, "apply", False):
        with console.status("[bold cyan]Applying Exploit Protection mitigations..."):
            results = shield.apply_mitigations()
        console.print(f"[bold green][+][/bold green] Applied mitigations to {len(results)} executables.")
    elif getattr(args, "remove", False):
        with console.status("[bold cyan]Removing Exploit Protection mitigations..."):
            results = shield.remove_mitigations()
        console.print(f"[bold green][+][/bold green] Removed mitigations from {len(results)} executables.")

    status_list = shield.audit()
    table = Table(title=f"Exploit Protection Status: {target.name}", show_lines=True)
    table.add_column("Executable", style="bold")
    table.add_column("DisallowChildProcess", justify="center")
    table.add_column("StrictHandleCheck", justify="center")
    table.add_column("Status", justify="center")

    for s in status_list:
        stat_badge = "[green]Shielded[/green]" if s.is_shielded else "[yellow]Unshielded[/yellow]"
        d_badge = "[green]Enabled[/green]" if s.disallow_child_processes else "[dim]Disabled[/dim]"
        h_badge = "[green]Enabled[/green]" if s.strict_handle_checks else "[dim]Disabled[/dim]"
        table.add_row(s.executable_name, d_badge, h_badge, stat_badge)

    console.print(table)
    console.print("\nGenerated Exploit Protection Scripts:")
    console.print(f"  • Apply Script:  [bold]{target / 'Apply_Process_Shield.ps1'}[/bold]")
    console.print(f"  • Remove Script: [bold]{target / 'Remove_Process_Shield.ps1'}[/bold]")


def handle_drivers(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    auditor = DriverAuditor(target)
    with console.status("[bold cyan]Auditing kernel drivers (.sys) and driver services..."):
        findings = auditor.audit()

    if not findings:
        console.print(f"[green][+] Clean![/green] No kernel drivers or driver install scripts found in [bold]{target.name}[/bold].")
        return

    table = Table(title=f"Kernel Driver & BYOVD Audit: {target.name}", show_lines=True)
    table.add_column("File Name", style="bold")
    table.add_column("Category", justify="center")
    table.add_column("Threat Severity", justify="center")
    table.add_column("Known Vulnerable (BYOVD)", justify="center")
    table.add_column("Description")

    for f in findings:
        sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_badge = f"[bold red]{sev_str}[/bold red]" if "HIGH" in sev_str or "CRITICAL" in sev_str else f"[yellow]{sev_str}[/yellow]"
        byovd_badge = "[bold red]YES (CRITICAL)[/bold red]" if f.is_known_vulnerable_byovd else "[green]NO[/green]"
        cat_str = "BYOVD Vulnerable Driver" if f.is_known_vulnerable_byovd else ("Microsoft Driver" if f.is_microsoft else "Kernel Driver")
        table.add_row(
            f.driver_name,
            cat_str,
            sev_badge,
            byovd_badge,
            f.description,
        )

    console.print(table)


def handle_proton(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    helper = ProtonHelper(target)
    with console.status("[bold cyan]Generating Linux Proton and Steam Deck runner scripts..."):
        res = helper.generate_all()

    console.print(Panel(
        f"[bold green][+] Steam Deck & Linux Proton Compatibility Prepared![/bold green]\n"
        f"Executable: [bold]{res.executable_name}[/bold]\n"
        f"Wine DLL Overrides: [cyan]{res.overrides}[/cyan]\n"
        f"Network Air-Gap: {'[green]Supported (unshare/firejail)[/green]' if res.network_isolation_supported else '[yellow]Disabled[/yellow]'}\n\n"
        f"Generated Scripts:\n"
        f"  • Proton Runner: [bold]{res.script_path}[/bold]\n"
        f"  • Steam Deck Setup: [bold]{res.setup_script_path}[/bold]",
        title=f"Proton / Steam Deck: {target.name}",
    ))


def handle_monitor(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        sys.exit(1)

    duration = getattr(args, "duration", 10) or 10
    console.print(Panel(
        f"[bold cyan]Real-Time Network Socket & C2 Monitor[/bold cyan]\n"
        f"Target: {target.name}\n"
        f"Sampling active connections for {duration} seconds to detect telemetry, mining pools, and C2 beacons...",
        title="Network Monitor",
    ))

    monitor = NetworkMonitor(target=target)
    report = monitor.monitor(duration=float(duration), interval=1.0)

    table = Table(title=f"Network Socket Audit: {target.name}", show_lines=True)
    table.add_column("Timestamp", justify="center")
    table.add_column("Protocol / Status")
    table.add_column("Local Endpoint")
    table.add_column("Remote Endpoint")
    table.add_column("Classification", justify="center")
    table.add_column("Threat Alert")

    for conn in report.records:
        cat = conn.category
        if cat == "COINMINER_POOL":
            cat_badge = "[bold red]MINING POOL[/bold red]"
        elif cat == "PUBLIC_INTERNET":
            cat_badge = "[bold yellow]PUBLIC INTERNET[/bold yellow]"
        elif cat == "PRIVATE_LAN":
            cat_badge = "[green]PRIVATE LAN[/green]"
        else:
            cat_badge = "[dim]LOOPBACK[/dim]"

        alert_badge = f"[bold red]{conn.details}[/bold red]" if conn.details else "[green]OK[/green]"
        table.add_row(
            conn.timestamp[:19],
            f"{conn.protocol.upper()} ({conn.status})",
            conn.laddr or "0.0.0.0",
            conn.raddr or "N/A",
            cat_badge,
            alert_badge,
        )

    console.print(table)
    out_json = target if target.is_dir() else target.parent
    report_file = out_json / f"net_audit_{target.stem}.json"
    report.save_json(report_file)
    console.print(f"\n[green][+][/green] Network audit report saved to: [bold]{report_file}[/bold]")


def handle_steamless(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        sys.exit(1)

    unpacker = SteamlessUnpacker()
    if not unpacker.is_available():
        console.print("[bold red]Steamless CLI is not found.[/bold red]\nPlace 'Steamless.CLI.exe' in 'tools/steamless/' or run 'gamecleaner setup --steamless'.")
        sys.exit(1)

    binaries = [target] if target.is_file() else [p for p in target.glob("*.exe") if not p.name.lower().startswith("unins")]
    if not binaries:
        console.print("[yellow]No executables found to unpack.[/yellow]")
        return

    for b in binaries:
        console.print(f"[cyan]Unpacking SteamStub DRM for {b.name}...[/cyan]")
        res = unpacker.unpack_binary(b, backup=True)
        if res.success:
            console.print(f"[bold green][+] Unpacked successfully![/bold green] Original backed up to: {res.backup_created}")
        else:
            console.print(f"[bold red]✗ Unpack failed or not SteamStub:[/bold red] {res.error_message}")


def handle_save_sync(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    sync_mgr = SaveSyncManager()
    er = EmulatorReplacer(target)
    appid = getattr(args, "app_id", None) or er.discover_appid(target) or "DefaultAppID"

    if getattr(args, "restore", None):
        snapshot_file = args.restore
        with console.status(f"[bold cyan]Restoring save snapshot '{snapshot_file}'..."):
            ok = sync_mgr.restore_snapshot(target, snapshot_file, appid=appid)
        if ok:
            console.print(f"[bold green][+][/bold green] Save snapshot restored successfully!")
        else:
            console.print(f"[bold red]✗[/bold red] Failed to restore save snapshot.")
        return

    if getattr(args, "list", False):
        snapshots = sync_mgr.list_snapshots(target)
        if not snapshots:
            console.print(f"[yellow]No save snapshots found in {target.name}.[/yellow]")
            return

        table = Table(title=f"Save Snapshots for {target.name}", show_lines=True)
        table.add_column("Filename", style="bold cyan")
        table.add_column("AppID", justify="center")
        table.add_column("Created", justify="center")
        table.add_column("Files", justify="center")
        table.add_column("Size", justify="center")
        table.add_column("Note")

        for s in snapshots:
            size_kb = f"{s.size_bytes / 1024:.1f} KB"
            table.add_row(s.snapshot_filename, s.appid, s.created_at[:19], str(s.file_count), size_kb, s.note)

        console.print(table)
        return

    # Default action or --snapshot: create snapshot
    note = getattr(args, "note", None) or "Manual save backup via CLI"
    with console.status("[bold cyan]Creating versioned save snapshot..."):
        res = sync_mgr.create_snapshot(target, appid=appid, note=note)

    if res.success:
        console.print(f"[bold green][+] Save snapshot created:[/bold green] [bold]{res.snapshot_path}[/bold] ({res.files_archived} files)")
    else:
        console.print(f"[yellow]Save snapshot notice:[/yellow] {res.error_message}")


def handle_web(args):
    host = getattr(args, "host", "127.0.0.1") or "127.0.0.1"
    port = getattr(args, "port", 8765) or 8765
    open_browser = getattr(args, "open", False)

    console.print(Panel(
        f"[bold cyan]GameCleaner Local Cyber Defense WebUI[/bold cyan]\n"
        f"Host: [bold]{host}[/bold] | Port: [bold]{port}[/bold]\n"
        f"Zero-dependency military-grade web dashboard & REST API.",
        title="GameCleaner WebUI",
    ))
    try:
        server = start_server(host=host, port=port, open_browser=open_browser, background=False)
    except KeyboardInterrupt:
        console.print("\n[green]WebUI stopped.[/green]")


def handle_crash_log(args):
    target = Path(args.path).resolve()
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target path does not exist: {target}")
        sys.exit(1)

    forensics = CrashForensics(target if target.is_dir() else target.parent)
    game_exe = target if target.is_file() else None

    with console.status("[bold cyan]Analyzing Windows Event Log & WER crash dumps..."):
        crashes = forensics.diagnose_crash(game_exe=game_exe)

    if not crashes:
        console.print(Panel(
            f"No crash events or WER dumps found for {target.name}.\n"
            "If the game crashed silently without generating an event, check runtime dependencies ('deps') or launch with 'run'.",
            title=f"Crash Forensics: {target.name}",
        ))
        return

    table = Table(title=f"Crash Incidents: {target.name}", show_lines=True)
    table.add_column("Timestamp", justify="center")
    table.add_column("Faulting Module", style="bold")
    table.add_column("Exception Code", justify="center")
    table.add_column("Root Cause Category", justify="center")
    table.add_column("Description")

    for c in crashes:
        table.add_row(
            c.timestamp[:19] if c.timestamp else "Unknown",
            c.faulting_module.name,
            c.exception_code,
            c.root_cause_category,
            c.root_cause_description,
        )
    console.print(table)


def handle_anticheat(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    detector = AntiCheatDetector(target)
    with console.status("[bold cyan]Scanning for Anti-Cheat solutions and binary packers..."):
        report = detector.scan()

    if not report.findings:
        console.print(f"[green][+] Clean![/green] No third-party Anti-Cheat solutions or binary packers detected in [bold]{target.name}[/bold].")
        return

    table = Table(title=f"Anti-Cheat & Packer Audit: {target.name}", show_lines=True)
    table.add_column("Protection", style="bold cyan")
    table.add_column("Status", justify="center")
    table.add_column("BYOVD Driver Risk", justify="center")
    table.add_column("Blocks Offline Play", justify="center")
    table.add_column("Description")

    for f in report.findings:
        byovd_badge = "[bold red]HIGH RISK[/bold red]" if f.byovd_risk else "[green]None[/green]"
        offline_badge = "[yellow]YES[/yellow]" if f.blocks_offline_play else "[green]NO[/green]"
        stat_val = f.status.value if hasattr(f.status, "value") else str(f.status)
        table.add_row(
            f.name,
            stat_val,
            byovd_badge,
            offline_badge,
            f.description,
        )

    console.print(table)


def handle_mods(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    auditor = ModCompatibilityAuditor(target)
    with console.status("[bold cyan]Auditing game mod frameworks and proxy chains..."):
        report = auditor.audit()

    if not report.detected_mods:
        console.print(f"[yellow]No game mod frameworks (ReShade, Special K, BepInEx, ASI) detected in {target.name}.[/yellow]")
        return

    table = Table(title=f"Mod Frameworks & Hooks: {target.name}", show_lines=True)
    table.add_column("Framework", style="bold cyan")
    table.add_column("DLL Name", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Architecture", justify="center")
    table.add_column("Description")

    for m in report.detected_mods:
        if m.is_malware_impersonation:
            integ_badge = "[bold red]Malware Impersonator[/bold red]"
        elif m.is_genuine:
            integ_badge = "[green]Genuine Mod[/green]"
        else:
            integ_badge = "[yellow]Potential Proxy[/yellow]"
        desc = f"Confidence: {m.confidence:.0%}"
        if m.hostile_indicators:
            desc += f" (Hostile: {', '.join(m.hostile_indicators)})"
        table.add_row(
            m.framework.value if hasattr(m.framework, "value") else str(m.framework),
            m.name,
            integ_badge,
            m.architecture,
            desc,
        )

    console.print(table)

    if report.conflicts:
        console.print("\n[bold yellow]Mod Conflicts / Broken Chains:[/bold yellow]")
        for c in report.conflicts:
            c_type = c.conflict_type.value if hasattr(c.conflict_type, "value") else str(c.conflict_type)
            console.print(f"  • [bold red]{c_type}:[/bold red] {c.description}")


def handle_eos(args):
    target = Path(args.path).resolve()
    if target.is_file():
        target = target.parent
    if not target.exists():
        console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
        sys.exit(1)

    replacer = EOSReplacer(target)
    targets = replacer.find_eos_targets()

    if not targets:
        console.print(f"[yellow]No Epic Online Services (EOS) SDK DLLs found in {target.name}.[/yellow]")
        return

    table = Table(title=f"Epic Online Services (EOS) Audit: {target.name}", show_lines=True)
    table.add_column("DLL Name", style="bold cyan")
    table.add_column("Architecture", justify="center")
    table.add_column("Classification", justify="center")
    table.add_column("Location")

    for t in targets:
        cls_badge = "[green]Clean Emulator[/green]" if t.is_emulator else "[yellow]Original/Wrapped SDK[/yellow]"
        rel = str(t.full_path.relative_to(target)) if target in t.full_path.parents else t.full_path.name
        table.add_row(
            t.dll_name,
            t.architecture,
            cls_badge,
            rel,
        )

    console.print(table)

    if getattr(args, "clean", False):
        with console.status("[bold cyan]Sanitizing EOS configuration and emulator stubs..."):
            res = replacer.replace_all()
        console.print(f"[bold green][+][/bold green] Sanitized {len(res)} EOS libraries.")


def handle_mem_audit(args):
    scanner = MemoryScanner()
    pid = getattr(args, "pid", None)
    proc_name = getattr(args, "name", None)

    if not pid and proc_name:
        import psutil
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.info["name"] and p.info["name"].lower() == proc_name.lower():
                    pid = p.info["pid"]
                    break
            except Exception:
                pass

    if not pid:
        console.print("[bold red]Error:[/bold red] Must specify a running process (--pid <PID> or --name <ExecutableName>).")
        sys.exit(1)

    with console.status("[bold cyan]Scanning running process loaded modules and memory space..."):
        report = scanner.scan_process(pid=pid)

    if not report:
        console.print(f"[bold red]Error:[/bold red] Process not found or access denied.")
        sys.exit(1)

    table = Table(title=f"Memory & Loaded Module Audit: PID {report.pid} ({report.process_name})", show_lines=True)
    table.add_column("Module Name", style="bold")
    table.add_column("Signed (Authenticode)", justify="center")
    table.add_column("Threat Severity", justify="center")
    table.add_column("Threat Reason")

    for mod in report.suspicious_modules:
        signed_badge = "[green]YES[/green]" if mod.signature_status == "Valid" else "[yellow]NO[/yellow]"
        sev_str = mod.severity.value if hasattr(mod.severity, "value") else str(mod.severity)
        reason_str = ", ".join(mod.reasons) if mod.reasons else "Suspicious module"
        table.add_row(
            mod.name,
            signed_badge,
            f"[bold red]{sev_str}[/bold red]",
            reason_str,
        )

    console.print(table)


def handle_cloud_save(args):
    sync = CloudSaveSync()
    target = Path(args.path).resolve() if getattr(args, "path", None) else Path.cwd()
    app_id = getattr(args, "app_id", None)

    if getattr(args, "export_deck", False):
        with console.status("[bold cyan]Exporting portable save archive for Steam Deck & Ludusavi..."):
            res = sync.export_game(target, appid=app_id)
        if res.success:
            console.print(f"[bold green][+] Exported portable save package:[/bold green] [bold]{res.archive_path}[/bold] ({res.file_count} files)")
        else:
            console.print(f"[bold red]✗ Export failed:[/bold red] {res.error_message}")
    elif getattr(args, "import_steam", None):
        steam_user_dir = Path(args.import_steam).resolve()
        with console.status("[bold cyan]Importing official Steam save data into Goldberg format..."):
            res = sync.import_steam_save(steam_user_dir, appid=app_id)
        if res.success:
            console.print(f"[bold green][+][/bold green] Imported {res.files_imported} saves to: {res.destination_path}")
        else:
            console.print(f"[bold red]✗ Import failed:[/bold red] {res.error_message}")
    else:
        console.print("[yellow]Specify --export-deck or --import-steam <path> to sync saves.[/yellow]")


def handle_interactive():
    console.print(Panel(
        "[bold cyan]GameCleaner Interactive Security Console[/bold cyan]\n"
        "Defensive security triage, malware isolation, clean emulator containment,\n"
        "save game migration, and air-gapped sandboxing for Windows games.",
        title="GameCleaner",
    ))

    while True:
        console.print("\n[bold yellow]Available Actions:[/bold yellow]")
        console.print("  [bold cyan]1.[/bold cyan] Full Clean & Contain Pipeline ([bold]clean-all[/bold])")
        console.print("  [bold cyan]2.[/bold cyan] Scan & Threat Triage Only ([bold]scan[/bold])")
        console.print("  [bold cyan]3.[/bold cyan] Pre-Install Repack Extractor ([bold]unpack[/bold])")
        console.print("  [bold cyan]4.[/bold cyan] Game Security Posture Dashboard ([bold]status[/bold])")
        console.print("  [bold cyan]5.[/bold cyan] Quarantine Vault Manager ([bold]quarantine[/bold])")
        console.print("  [bold cyan]6.[/bold cyan] Rollback Original DLLs ([bold]rollback[/bold])")
        console.print("  [bold cyan]7.[/bold cyan] Save Game & SteamID Migration ([bold]migrate-saves[/bold])")
        console.print("  [bold cyan]8.[/bold cyan] Firewall Network Isolation ([bold]firewall[/bold])")
        console.print("  [bold cyan]9.[/bold cyan] Air-Gapped Windows Sandbox Profile ([bold]sandbox[/bold])")
        console.print("  [bold cyan]10.[/bold cyan] Replace DRM with Clean Emulator ([bold]replace-emu[/bold])")
        console.print("  [bold cyan]11.[/bold cyan] Deep REA Reverse-Engineering Dossier ([bold]inspect[/bold])")
        console.print("  [bold cyan]12.[/bold cyan] Environment Setup & Diagnostics ([bold]setup[/bold])")
        console.print("  [bold cyan]13.[/bold cyan] Cryptographic Game Integrity Verifier ([bold]verify[/bold])")
        console.print("  [bold cyan]14.[/bold cyan] Audit Runtime Dependencies & Redists ([bold]deps[/bold])")
        console.print("  [bold cyan]15.[/bold cyan] Audit DLL Search-Order Hijacking ([bold]sideload[/bold])")
        console.print("  [bold cyan]16.[/bold cyan] Smart Game Launcher & Firewall Fix ([bold]run[/bold])")
        console.print("  [bold cyan]17.[/bold cyan] Exploit Protection Shield ([bold]shield[/bold])")
        console.print("  [bold cyan]18.[/bold cyan] Kernel Driver & Rootkit Auditor ([bold]drivers[/bold])")
        console.print("  [bold cyan]19.[/bold cyan] Steam Deck & Linux Proton Launcher ([bold]proton[/bold])")
        console.print("  [bold cyan]20.[/bold cyan] Real-Time Socket & C2 Monitor ([bold]monitor[/bold])")
        console.print("  [bold cyan]21.[/bold cyan] Steamless SteamStub DRM Unpacker ([bold]steamless[/bold])")
        console.print("  [bold cyan]22.[/bold cyan] Save Game Snapshots & Versioned Rollback ([bold]save-sync[/bold])")
        console.print("  [bold cyan]23.[/bold cyan] Exit")

        try:
            choice = Prompt.ask("\nSelect an action", choices=[str(i) for i in range(1, 24)], default="4")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[green]Exiting GameCleaner.[/green]")
            break

        if choice == "23":
            console.print("[green]Goodbye![/green]")
            break

        class DummyArgs:
            pass

        d_args = DummyArgs()

        if choice == "1":
            p = Prompt.ask("Enter path to game folder or archive (.zip, .7z, setup.exe)")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.output = None
            d_args.no_quarantine = False
            d_args.no_replace_emu = False
            d_args.no_migrate_saves = False
            d_args.no_firewall = False
            d_args.no_sandbox = False
            try:
                handle_clean_all(d_args)
            except SystemExit:
                pass

        elif choice == "2":
            p = Prompt.ask("Enter path to game folder or binary to scan")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_scan(d_args)
            except SystemExit:
                pass

        elif choice == "3":
            p = Prompt.ask("Enter path to installer (setup.exe or archive)")
            if not p.strip(): continue
            d_args.installer = p.strip().strip('"')
            out = Prompt.ask("Enter destination folder (leave empty for default)", default="")
            d_args.output = out.strip().strip('"') if out.strip() else None
            d_args.no_clean = not Confirm.ask("Auto-clean directory after unpacking?", default=True)
            try:
                handle_unpack(d_args)
            except SystemExit:
                pass

        elif choice == "4":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_status(d_args)
            except SystemExit:
                pass

        elif choice == "5":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            action = Prompt.ask("Quarantine action: [L]ist, [R]estore file, Restore [A]ll, [M]anually add", choices=["l", "r", "a", "m"], default="l").lower()
            d_args.restore = None
            d_args.restore_all = False
            d_args.add = None
            if action == "r":
                d_args.restore = Prompt.ask("Enter quarantined filename to restore")
            elif action == "a":
                d_args.restore_all = True
            elif action == "m":
                d_args.add = Prompt.ask("Enter path of file to quarantine")
                d_args.reason = Prompt.ask("Enter reason", default="Manual quarantine")
            try:
                handle_quarantine(d_args)
            except SystemExit:
                pass

        elif choice == "6":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            action = Prompt.ask("Rollback action: [L]ist backups, [R]estore specific, Restore [A]ll", choices=["l", "r", "a"], default="l").lower()
            d_args.backup = None
            d_args.all = False
            if action == "r":
                d_args.backup = Prompt.ask("Enter backup filename to restore")
            elif action == "a":
                d_args.all = True
            try:
                handle_rollback(d_args)
            except SystemExit:
                pass

        elif choice == "7":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            app_id = Prompt.ask("Enter Steam AppID (leave empty to auto-detect)", default="")
            d_args.app_id = app_id.strip() if app_id.strip() else None
            try:
                handle_migrate_saves(d_args)
            except SystemExit:
                pass

        elif choice == "8":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.elevate = Confirm.ask("Launch UAC prompt to apply rules immediately with Admin rights?", default=False)
            try:
                handle_firewall(d_args)
            except SystemExit:
                pass

        elif choice == "9":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.read_write = Confirm.ask("Mount game directory as read-write? (Default is read-only)", default=False)
            try:
                handle_sandbox(d_args)
            except SystemExit:
                pass

        elif choice == "10":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.custom_dll = None
            try:
                handle_replace_emu(d_args)
            except SystemExit:
                pass

        elif choice == "11":
            p = Prompt.ask("Enter path to binary (.exe / .dll) to reverse-engineer")
            if not p.strip(): continue
            d_args.binary_path = p.strip().strip('"')
            try:
                handle_inspect(d_args)
            except SystemExit:
                pass

        elif choice == "12":
            d_args.all = False
            d_args.check = True
            d_args.context_menu = False
            d_args.remove_context_menu = False
            d_args.unpacker = False
            d_args.ghidra = False
            try:
                handle_setup(d_args)
            except SystemExit:
                pass

        elif choice == "13":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            action = Prompt.ask("Integrity action: [V]erify against manifest, [C]reate new manifest", choices=["v", "c"], default="v").lower()
            d_args.create = (action == "c")
            try:
                handle_verify(d_args)
            except SystemExit:
                pass

        elif choice == "14":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.install = Confirm.ask("Silently install any discovered repack runtimes?", default=False)
            try:
                handle_deps(d_args)
            except SystemExit:
                pass

        elif choice == "15":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_sideload(d_args)
            except SystemExit:
                pass

        elif choice == "16":
            p = Prompt.ask("Enter path to game folder or game .exe")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_run(d_args)
            except SystemExit:
                pass

        elif choice == "17":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.apply = Confirm.ask("Apply mitigations immediately if elevated?", default=False)
            d_args.remove = False
            d_args.elevate = False
            try:
                handle_shield(d_args)
            except SystemExit:
                pass

        elif choice == "18":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_drivers(d_args)
            except SystemExit:
                pass

        elif choice == "19":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_proton(d_args)
            except SystemExit:
                pass

        elif choice == "20":
            p = Prompt.ask("Enter path to game executable or running process")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            d_args.duration = 10
            try:
                handle_monitor(d_args)
            except SystemExit:
                pass

        elif choice == "21":
            p = Prompt.ask("Enter path to game executable or folder to unpack SteamStub")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            try:
                handle_steamless(d_args)
            except SystemExit:
                pass

        elif choice == "22":
            p = Prompt.ask("Enter path to game folder")
            if not p.strip(): continue
            d_args.path = p.strip().strip('"')
            action = Prompt.ask("Save sync action: [S]napshot backup, [L]ist snapshots, [R]estore snapshot", choices=["s", "l", "r"], default="s").lower()
            d_args.list = (action == "l")
            d_args.restore = Prompt.ask("Enter snapshot filename to restore") if action == "r" else None
            d_args.snapshot = (action == "s")
            d_args.note = "Interactive snapshot via CLI"
            d_args.app_id = None
            try:
                handle_save_sync(d_args)
            except SystemExit:
                pass


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
            console.print(f"[bold green][+][/bold green] {msg}")
        else:
            console.print(f"[bold red]✗[/bold red] {msg}")

    if getattr(args, "remove_context_menu", False):
        ok, msg = shell_mgr.uninstall()
        if ok:
            console.print(f"[bold green][+][/bold green] {msg}")
        else:
            console.print(f"[bold red]✗[/bold red] {msg}")

    if getattr(args, "unpacker", False):
        with console.status("[bold cyan]Ensuring innoextract portable binary is installed..."):
            bin_path = unpacker.ensure_innoextract()
        if bin_path:
            console.print(f"[bold green][+][/bold green] innoextract configured at: {bin_path}")
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
            console.print(f"[green][+][/green] {msg}")
        else:
            console.print(f"[red]✗[/red] {msg}")

    # Auto-download Ghidra if requested
    if getattr(args, "ghidra", False):
        if status.ghidra_installed:
            console.print(f"[green][+][/green] Ghidra is already installed at: {status.ghidra_path}")
        else:
            with console.status("[bold cyan]Downloading and extracting official portable Ghidra archive (this may take a few minutes)..."):
                ok, msg, path = manager.install_ghidra_portable()
            if ok:
                console.print(f"[bold green][+][/bold green] {msg}")
            else:
                console.print(f"[bold red]✗[/bold red] {msg}")


def main():
    parser = argparse.ArgumentParser(
        prog="gamecleaner",
        description="GameCleaner: Security Triage, Malware Isolation, and Safe Containment for Games.",
    )
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive menu mode")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan and audit PE binaries in a folder or single file")
    scan_p.add_argument("path", help="Path to game directory or binary")

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

    # status
    status_p = subparsers.add_parser("status", help="Inspect security posture, emulators, quarantine, and containment of a game")
    status_p.add_argument("path", help="Path to game directory")

    # quarantine
    quar_p = subparsers.add_parser("quarantine", help="Audit, list, and restore files from the quarantine vault")
    quar_p.add_argument("path", help="Path to game directory")
    quar_p.add_argument("--list", action="store_true", help="List all quarantined files in vault (Default)")
    quar_p.add_argument("--restore", metavar="FILENAME", help="Restore a specific file from quarantine by its filename")
    quar_p.add_argument("--restore-all", action="store_true", help="Restore all quarantined files in vault")
    quar_p.add_argument("--add", metavar="FILE", help="Manually isolate a suspicious file into quarantine")
    quar_p.add_argument("--reason", default="Manual quarantine via CLI", help="Reason for manual quarantine")

    # rollback
    roll_p = subparsers.add_parser("rollback", help="List or restore original DRM wrapper DLLs from .gamecleaner_backup")
    roll_p.add_argument("path", help="Path to game directory")
    roll_p.add_argument("--list", action="store_true", help="List all available backups (Default)")
    roll_p.add_argument("--backup", metavar="FILENAME", help="Restore a specific backup DLL by its backup filename")
    roll_p.add_argument("--all", action="store_true", help="Restore all backups to their original locations")

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

    # verify (Cryptographic Game Integrity)
    ver_p = subparsers.add_parser("verify", help="Cryptographic SHA-256 integrity check and manifest creation")
    ver_p.add_argument("path", help="Path to game directory")
    ver_p.add_argument("--create", action="store_true", help="Generate or update .gamecleaner_manifest.json")
    ver_p.add_argument("--check", action="store_true", help="Verify game folder integrity against manifest (Default)")

    # deps (Dependency & Runtime Auditor)
    deps_p = subparsers.add_parser("deps", help="Audit DirectX, Visual C++, and OpenAL runtimes and repack installers")
    deps_p.add_argument("path", help="Path to game directory")
    deps_p.add_argument("--install", action="store_true", help="Silently install any discovered repack runtimes")

    # sideload (DLL Search-Order Hijacking Auditor)
    side_p = subparsers.add_parser("sideload", help="Audit DLL search-order hijacking and proxy DLLs")
    side_p.add_argument("path", help="Path to game directory")

    # run (Smart Isolated Game Launcher)
    run_p = subparsers.add_parser("run", help="Smart isolated game launcher with firewall unblock and runtime validation")
    run_p.add_argument("path", help="Path to game directory or game executable")

    # shield (Windows Exploit Protection Child-Process Blocker)
    shield_p = subparsers.add_parser("shield", help="Configure Windows Exploit Protection to block child processes (droppers/miners)")
    shield_p.add_argument("path", help="Path to game directory")
    shield_p.add_argument("--apply", action="store_true", help="Apply exploit mitigations immediately")
    shield_p.add_argument("--remove", action="store_true", help="Remove exploit mitigations")
    shield_p.add_argument("--elevate", action="store_true", help="Relaunch with UAC elevation if not already Admin")

    # drivers (Kernel Driver & BYOVD Rootkit Auditor)
    drv_p = subparsers.add_parser("drivers", help="Audit kernel driver (.sys) binaries and BYOVD exploit threats")
    drv_p.add_argument("path", help="Path to game directory")

    # proton (Steam Deck & Linux Proton Compatibility)
    proton_p = subparsers.add_parser("proton", help="Generate Steam Deck and Linux Proton launch scripts with Wine DLL overrides")
    proton_p.add_argument("path", help="Path to game directory")

    # monitor (Real-Time Socket & C2 Monitor)
    monitor_p = subparsers.add_parser("monitor", help="Real-time socket connection monitor tracking telemetry and C2 beacons")
    monitor_p.add_argument("path", help="Path to game directory or game executable")
    monitor_p.add_argument("--duration", type=int, default=10, help="Monitoring duration in seconds (default: 10)")

    # steamless (SteamStub DRM Unpacker)
    steam_p = subparsers.add_parser("steamless", help="Unpack SteamStub DRM (.bind sections) using Steamless CLI")
    steam_p.add_argument("path", help="Path to game executable or folder")

    # save-sync (Goldberg Save Snapshot & Sync Manager)
    sync_p = subparsers.add_parser("save-sync", help="Goldberg save snapshot manager: backup, list, and restore progress snapshots")
    sync_p.add_argument("path", help="Path to game directory")
    sync_p.add_argument("--snapshot", action="store_true", help="Create a versioned save snapshot")
    sync_p.add_argument("--list", action="store_true", help="List all save snapshots for this game")
    sync_p.add_argument("--restore", metavar="FILENAME", help="Restore save state from a snapshot archive")
    sync_p.add_argument("--note", default="Manual save snapshot via CLI", help="Optional label/note for the snapshot")
    sync_p.add_argument("--app-id", help="Explicit Steam AppID")

    # web (Zero-Dependency Cyber Defense Web Dashboard)
    web_p = subparsers.add_parser("web", help="Launch zero-dependency local cyber defense WebUI dashboard and REST API")
    web_p.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    web_p.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    web_p.add_argument("--open", action="store_true", help="Automatically open dashboard in web browser")

    # crash-log (Windows Event Log & WER Crash Forensics)
    crash_p = subparsers.add_parser("crash-log", help="Triage game crashes and diagnose missing runtimes from Windows Event Log and WER dumps")
    crash_p.add_argument("path", help="Path to game directory or executable")

    # anticheat (Anti-Cheat & Binary Protector Triage)
    ac_p = subparsers.add_parser("anticheat", help="Audit third-party Anti-Cheat solutions (EAC, BattlEye, Vanguard) and protectors (Denuvo, VMProtect)")
    ac_p.add_argument("path", help="Path to game directory")

    # mods (Game Mod & Hook Compatibility Auditor)
    mods_p = subparsers.add_parser("mods", help="Audit game mods (ReShade, Special K, BepInEx, ASI) and verify proxy chains")
    mods_p.add_argument("path", help="Path to game directory")

    # eos (Epic Online Services SDK Triage & Cleaner)
    eos_p = subparsers.add_parser("eos", help="Triage Epic Online Services (EOS) SDK DLLs, clean configs, and emulator stubs")
    eos_p.add_argument("path", help="Path to game directory")
    eos_p.add_argument("--clean", action="store_true", help="Sanitize EOS configuration and install clean emulator stubs")

    # mem-audit (Live Process Memory & Loaded Module Auditor)
    mem_p = subparsers.add_parser("mem-audit", help="Inspect loaded modules and memory hooks of a running game process")
    mem_p.add_argument("--pid", type=int, help="Target process ID (PID)")
    mem_p.add_argument("--name", help="Target process executable name (e.g. Game.exe)")

    # cloud-save (Universal Save Exporter & Importer)
    cloud_p = subparsers.add_parser("cloud-save", help="Export portable save packages for Steam Deck or import official Steam userdata")
    cloud_p.add_argument("path", nargs="?", default=".", help="Path to game directory")
    cloud_p.add_argument("--export-deck", action="store_true", help="Export portable save package for Steam Deck / Ludusavi")
    cloud_p.add_argument("--import-steam", metavar="STEAM_USER_DIR", help="Path to official Steam userdata/<AccountID>/<AppID> folder to import")
    cloud_p.add_argument("--app-id", help="Explicit Steam AppID")

    # interactive mode
    subparsers.add_parser("interactive", help="Launch interactive menu mode")

    args = parser.parse_args()

    if getattr(args, "interactive", False) or args.command == "interactive":
        handle_interactive()
        return

    if not args.command:
        if sys.stdin.isatty():
            handle_interactive()
        else:
            parser.print_help()
            sys.exit(0)
        return

    if args.command == "scan":
        handle_scan(args)
    elif args.command == "clean-all":
        handle_clean_all(args)
    elif args.command == "unpack":
        handle_unpack(args)
    elif args.command == "status":
        handle_status(args)
    elif args.command == "quarantine":
        handle_quarantine(args)
    elif args.command == "rollback":
        handle_rollback(args)
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
    elif args.command == "verify":
        handle_verify(args)
    elif args.command == "deps":
        handle_deps(args)
    elif args.command == "sideload":
        handle_sideload(args)
    elif args.command == "run":
        handle_run(args)
    elif args.command == "shield":
        handle_shield(args)
    elif args.command == "drivers":
        handle_drivers(args)
    elif args.command == "proton":
        handle_proton(args)
    elif args.command == "monitor":
        handle_monitor(args)
    elif args.command == "steamless":
        handle_steamless(args)
    elif args.command == "save-sync":
        handle_save_sync(args)
    elif args.command == "web":
        handle_web(args)
    elif args.command == "crash-log":
        handle_crash_log(args)
    elif args.command == "anticheat":
        handle_anticheat(args)
    elif args.command == "mods":
        handle_mods(args)
    elif args.command == "eos":
        handle_eos(args)
    elif args.command == "mem-audit":
        handle_mem_audit(args)
    elif args.command == "cloud-save":
        handle_cloud_save(args)


if __name__ == "__main__":
    main()
