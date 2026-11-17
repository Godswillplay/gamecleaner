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

Expected result: All 29 unit and integration tests must pass (`OK`).

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
