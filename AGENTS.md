# AGENTS.md — Autonomous AI Agent Operating Guide for GameCleaner

This document guides AI agents (such as **Google Antigravity**, **Claude Code**, **Cursor**, and **Windsurf**) on how to autonomously install, configure, verify, and operate **GameCleaner**.

---

## 1. Project Overview
**GameCleaner** is an automated defensive security framework for PC games and repacks on Windows. It triages malware, isolates hostiles into quarantine, replaces closed-source crack DLLs with clean open-source emulators (Goldberg Steam Emulator / Epic EOS), migrates save games, isolates outbound network access via Windows Firewall, and creates air-gapped Windows Sandbox (`.wsb`) profiles.

---

## 2. Autonomous Setup ("Set This Up")
When a user asks you to **"set this up"**, execute these three steps in sequence:

```powershell
# Step 1: Install Python package in editable mode
pip install -e .

# Step 2: One-command hands-free environment setup
# (Auto-configures innoextract unpacker, registers Windows Explorer context menu, and verifies Java/Node/Goldberg)
python -m gamecleaner.cli setup --all

# Step 3: Run the automated test suite to confirm 100% operational readiness
python -m unittest discover tests
```

Expected result: All 301 unit and integration tests must pass (`OK`).

---

## 3. Standard Operating Workflows

### Scenario A: User Has a `.zip`, `.rar`, or `.7z` in Downloads and Wants it on another drive (e.g., `D:\Games\`)
Execute:
```powershell
python -m gamecleaner.cli clean-all "C:\Users\<Username>\Downloads\<GameArchive>.zip" -o "D:\Games\<GameName>"
```
*What GameCleaner does automatically:*
1. Unpacks the archive safely into `D:\Games\<GameName>` without executing any code.
2. Runs static PE analysis, entropy analysis, and Authenticode signature verification.
3. Replaces untrusted `steam_api64.dll` with pre-bundled clean Goldberg emulator.
4. Auto-generates `steam_appid.txt`, `steam_interfaces.txt`, and queries Steam store API for `steam_settings/DLC.txt`.
5. Migrates existing scene saves from `%APPDATA%` so player progress is retained.
6. Moves identified malicious droppers/miners into `.gamecleaner_quarantine/`.
7. Generates outbound firewall isolation script (`block_game_network.ps1`) and air-gapped Windows Sandbox profile (`.wsb`).
*(Reference verified implementation: `docs/CASE_STUDY_SNIPER_ELITE.md`)*

---

### Scenario B: User Already Installed a Game to a Folder and Wants it Sanitized
Execute:
```powershell
python -m gamecleaner.cli clean-all "D:\Games\<GameFolder>"
```
*Tip:* To apply firewall rules immediately with Admin elevation:
```powershell
python -m gamecleaner.cli firewall "D:\Games\<GameFolder>" --elevate
```

---

### Scenario C: User Downloaded an Inno Setup / Repack `setup.exe`
**Never execute untrusted `setup.exe` directly.** Instead, unpack it directly to disk:
```powershell
# Extracts files safely without running setup.exe AND sanitizes them during install
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "D:\Games\<GameFolder>"
```

---

### Scenario D: Reverse-Engineer or Deep-Inspect a Suspicious Binary
When a user asks to inspect a specific file or verify whether a hook is safe:
```powershell
python -m gamecleaner.cli inspect "D:\Games\<GameFolder>\<binary.dll>"
```
This generates a detailed Capstone disassembly dossier and string cross-reference analysis in `REA_EVIDENCE_<binary>.md`.

---

### Scenario E: Cryptographic Game Integrity & Tamper Verification
Audit whether any game binaries were corrupted, modified after sanitization, or if newly injected droppers appeared:
```powershell
python -m gamecleaner.cli verify "D:\Games\<GameFolder>"
```

---

### Scenario F: Dependency & Runtime Troubleshooting (DirectX / Visual C++ / OpenAL)
Detect missing runtime DLLs and automatically run silent redist installers from `_CommonRedist/` or `redist/`:
```powershell
python -m gamecleaner.cli deps "D:\Games\<GameFolder>" --install
```

---

### Scenario G: Audit DLL Search-Order Hijacking (Sideloaded System DLLs)
Identify untrusted system DLLs (`version.dll`, `winhttp.dll`, `dxgi.dll`) and differentiate mod loaders (ReShade, BepInEx) from hostile proxies:
```powershell
python -m gamecleaner.cli sideload "D:\Games\<GameFolder>"
```

---

### Scenario H: Smart Isolated Game Launcher (Firewall Trap Remediation)
Remediates any Windows Firewall inbound socket blocks, captures a save snapshot, verifies dependencies, and cleanly launches the game:
```powershell
python -m gamecleaner.cli run "D:\Games\<GameFolder>"
```

---

### Scenario I: Windows Exploit Protection Child-Process Blocker
Hard-block game binaries from spawning hidden background miners or scripts:
```powershell
python -m gamecleaner.cli shield "D:\Games\<GameFolder>" --elevate
```

---

### Scenario J: Kernel Driver & BYOVD Rootkit Inspection
Audit all `.sys` driver binaries and driver service scripts against the LOLDrivers/BYOVD database:
```powershell
python -m gamecleaner.cli drivers "D:\Games\<GameFolder>"
```

---

### Scenario K: Steam Deck & Linux Proton Setup
Generate POSIX Proton launch scripts with Wine DLL overrides and Linux network isolation:
```powershell
python -m gamecleaner.cli proton "D:\Games\<GameFolder>"
```

---

### Scenario L: Versioned Save Snapshots & Rollback
Capture or restore point-in-time Goldberg save game archives:
```powershell
# Create snapshot
python -m gamecleaner.cli save-sync "D:\Games\<GameFolder>" --snapshot

# List and restore
python -m gamecleaner.cli save-sync "D:\Games\<GameFolder>" --list
python -m gamecleaner.cli save-sync "D:\Games\<GameFolder>" --restore "<snapshot_name>.zip"
```

---

### Scenario M: Interactive Local Cyber Defense WebUI Dashboard
Launch the zero-dependency local web dashboard and REST API with live telemetry dials, drag-and-drop triage, and one-click actions:
```powershell
python -m gamecleaner.cli web --open
```

---

### Scenario N: Windows Event Log & WER Crash Forensics
Diagnose why a cracked game crashed on startup or silently closed by parsing Windows Application Log (Event ID 1000/1001) and WER dumps:
```powershell
python -m gamecleaner.cli crash-log "D:\Games\<GameFolder>"
```

---

### Scenario O: Anti-Cheat & Binary Protector Triage
Audit third-party anti-cheat suites (Easy Anti-Cheat, BattlEye, Vanguard) and binary protectors (Denuvo, VMProtect, Themida) for BYOVD kernel driver risks:
```powershell
python -m gamecleaner.cli anticheat "D:\Games\<GameFolder>"
```

---

### Scenario P: Game Mod & Hook Compatibility Audit
Audit game mod frameworks (ReShade, Special K, BepInEx, Script Extenders, ASI loaders), detect proxy chains, and prevent malware from masquerading as mod loaders:
```powershell
python -m gamecleaner.cli mods "D:\Games\<GameFolder>"
```

---

### Scenario Q: Epic Online Services (EOS) Emulation & Triage
Triage Epic Online Services SDK binaries (`EOSSDK-Win64-Shipping.dll`), preserve catalog configs, and sanitize with clean emulator stubs:
```powershell
# Audit EOS targets
python -m gamecleaner.cli eos "D:\Games\<GameFolder>"

# Sanitize and replace with clean stubs
python -m gamecleaner.cli eos "D:\Games\<GameFolder>" --clean
```

---

### Scenario R: Live Process Memory & Injection Hook Audit
Inspect loaded modules and detect unauthorized DLL injections from `%TEMP%`/`%APPDATA%`, detour hooks, or crypto miners in a running game process:
```powershell
python -m gamecleaner.cli mem-audit --name "Game.exe"
```

---

### Scenario S: Universal Cloud Save Exporter & Importer
Export portable save packages for Steam Deck / Ludusavi or import official Steam saves into Goldberg format:
```powershell
# Export for Steam Deck
python -m gamecleaner.cli cloud-save "D:\Games\<GameFolder>" --export-deck

# Import official Steam userdata
python -m gamecleaner.cli cloud-save "D:\Games\<GameFolder>" --import-steam "C:\Program Files (x86)\Steam\userdata\<AccountID>\<AppID>"
```

---

## 4. Key Architectural Guarantees for AI Agents
- **Pre-Bundled Emulators:** Clean, verified Goldberg Steam emulators (`steam_api.dll` and `steam_api64.dll`) are permanently bundled in `emulators/goldberg/`. No external download is required for Steam games.
- **NTFS Locked File Evasion:** If a game DLL is locked or loaded in memory, GameCleaner uses NTFS rename-first evasion (`.gc_old`) to swap it with clean emulators without rebooting.
- **Subdirectory DLL Mirroring:** In repacks where executables reside in `bin/` or `bin/x64/`, GameCleaner automatically mirrors clean emulators and `steam_appid.txt` into those subdirectories to avoid DLL loader search failures.
- **Zero Admin Shell Menu:** Explorer context menu writes exclusively to `HKCU\Software\Classes\`, requiring zero UAC prompts or Administrator privileges.
- **Safe Quarantine:** Quarantined files are stripped of execution permissions and stored in `.gamecleaner_quarantine/` with an audit manifest.

---

## 5. Troubleshooting & Real-World Playability Guidance (For AI Agents)
- **The Windows Firewall "Cancel" Trap:**
  When a game first launches, Windows Security may ask: *"Do you want to allow public and private networks to access this app?"*
  - **Instruct the user:** Allow on **Private networks** (Home Wi-Fi).
  - **If the user clicked Cancel:** Windows creates an Inbound Block rule that causes games with co-op/LAN sockets (like Sniper Elite) to fail on `bind()` and silently close.
  - **How the AI fixes it:** Instruct the user to run `Fix_Firewall_And_Run.bat` as Administrator, or run:
    `powershell -Command "Remove-NetFirewallRule -DisplayName '<game_name>'"`
- **AppID Verification:**
  Always verify that `steam_appid.txt` and `steam_settings/steam_appid.txt` contain the game's actual Steam AppID (e.g. `227100` for Sniper Elite Nazi Zombie Army) rather than a generic fallback like `480`, as games check their own AppID during initialization.
