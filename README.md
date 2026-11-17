# GameCleaner 🛡️🎮

[![GameCleaner CI](https://github.com/OWNER/gamecleaner/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/gamecleaner/actions)
![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)
![Tests](https://img.shields.io/badge/tests-29%2F29%20passing-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)
![AI Agent Ready](https://img.shields.io/badge/AI%20Agent-Antigravity%20%7C%20Claude%20%7C%20Cursor-purple.svg)

**GameCleaner** is an automated security triage, malware isolation, clean emulator replacement, and containment framework for untrusted or cracked PC games and software.

It functions as **both a standalone Windows CLI/Shell security tool and an Autonomous Agent Skill (`SKILL.md`)** for Antigravity, Claude Code, and local AI workflows.

---

## The Problem GameCleaner Solves
When gamers install repacks or third-party game releases, they face two critical issues:
1. **Silent Malware Payloads:** Shady repacks bundle infostealers (Lumma, Redline, Vidar), XMRig cryptominers, malicious scheduled tasks, and obfuscated `.lnk` shortcuts.
2. **False Positives vs. Real Threats:** Antivirus heuristics flag all crack hooks (`steam_api64.dll`, memory loaders) as generic `HackTool`, making it difficult to separate harmless offline DRM bypasses from hostile trojans.

---

## 5-Pillar Security Architecture

```
                      ┌──────────────────────────────────────┐
                      │    Untrusted Game Directory / Repack │
                      └──────────────────┬───────────────────┘
                                         │
                   ┌─────────────────────▼─────────────────────┐
                   │ Pillar 1: Static PE, Script & LNK Triage  │
                   │ • Shannon Entropy (Crypter Detection)     │
                   │ • Native Win32 WinVerifyTrust Signatures  │
                   │ • Sensitive API Imports (Stealers/Miners) │
                   │ • MS-SHLLINK & LOLBin Parser (-enc/-w)    │
                   │ • System Persistence Audit (Run/Tasks)    │
                   └─────────────────────┬─────────────────────┘
                                         │
         ┌───────────────────────────────┼──────────────────────────────┐
         ▼                               ▼                              ▼
┌──────────────────┐           ┌────────────────────┐         ┌────────────────────┐
│ Clean Binaries   │           │ Untrusted DRM Hook │         │ Hostile Payload    │
│ (Retain & Verify)│           │ (Steam / Epic / Ubi│         │ (Stealer / Miner)  │
└────────┬─────────┘           └─────────┬──────────┘         └─────────┬──────────┘
         │                               │                              │
         │                     ┌─────────▼──────────┐         ┌─────────▼──────────┐
         │                     │ Pillar 2: Clean    │         │ Quarantine Vault   │
         │                     │ Emulator Replace   │         │ (.gamecleaner_     │
         │                     │ & Save Migration   │         │  quarantine/)      │
         │                     └─────────┬──────────┘         └────────────────────┘
         │                               │
         └───────────────────────────────┴──────────────────────────────┐
                                                                        ▼
                                                   ┌────────────────────────────────────────┐
                                                   │ Pillar 3: Network Isolation & Sandbox  │
                                                   │ • Windows Firewall Outbound Blocks     │
                                                   │ • Air-Gapped Windows Sandbox (.wsb)    │
                                                   └────────────────────────────────────────┘
```

---

## Key Features

1. **Pre-Install Repack Extraction (`unpack`):**
   - Unpacks Inno Setup (`setup.exe`), NSIS installers, and archives directly to disk without executing untrusted installer binaries.
   - **Option during installation:** Automatically runs `clean-all` on the extracted files (`--clean`, enabled by default).
2. **One-Click Windows Explorer Shell Integration (`setup --context-menu`):**
   - Adds right-click **"Clean & Contain with GameCleaner"** to folders in Windows Explorer (writes to `HKCU`, requires zero administrator privileges).
3. **Clean-Room Emulator Replacement (Multi-DRM):**
   - Replaces untrusted Steam, Epic, and Ubisoft wrappers with verified clean open-source emulators (pre-bundled Goldberg Steam Emulator).
   - Auto-queries Steam store API to reconstruct missing `DLC.txt` manifests.
4. **Save Game & SteamID Identity Preservation:**
   - Detects scene INI files (`steam_emu.ini`, `codex.ini`, `rune.ini`) and migrates existing save files so user game progress is never lost.
5. **AI-Assisted Decompiler Triage:**
   - Disassembles entry points and formats structured reverse-engineering prompts for Antigravity / Claude Code to evaluate benign crack logic vs. hostile payload injection.
6. **Air-Gapped Containment:**
   - Generates Windows Sandbox profiles (`.wsb`) with 3D vGPU acceleration and disables network connectivity.

---

## CLI Usage Reference

### 1. Full Security & Remediation Pipeline (`clean-all`)
Runs the complete scan, AI triage, save migration, emulator replacement, quarantine, firewall scripts, and sandbox generation:

```powershell
python -m gamecleaner.cli clean-all "C:\Games\TargetGame"
```

### 2. Pre-Install Repack Unpacker (`unpack`)
Extracts a repack or `setup.exe` safely without running untrusted code:

```powershell
# Unpack and immediately auto-clean the extracted game during installation (Default)
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "C:\Games\TargetGame"

# Unpack only without immediate cleaning
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "C:\Games\TargetGame" --no-clean
```

### 3. Save Game & SteamID Migrator (`migrate-saves`)
Detects scene crack configurations and configures Goldberg identity and saves:

```powershell
python -m gamecleaner.cli migrate-saves "C:\Games\TargetGame"
```

### 4. Windows Explorer Shell Integration (`setup`)
Registers the right-click context menu in Windows Explorer:

```powershell
# Check environment readiness
python -m gamecleaner.cli setup --check

# Register right-click "Clean with GameCleaner" menu
python -m gamecleaner.cli setup --context-menu

# Remove right-click context menu
python -m gamecleaner.cli setup --remove-context-menu
```

### 5. Deep Reverse-Engineering Inspection (`inspect`)
Compiles a full REA evidence dossier (Capstone disassembly, string cross-references, Steamworks interfaces):

```powershell
python -m gamecleaner.cli inspect "C:\Games\TargetGame\game.exe"
```

---

## Proven Real-World Case Study: Sniper Elite Nazi Zombie Army (3.32 GB Repack)

GameCleaner was evaluated on a live 3.32 GB repack archive (`Sniper.Elite.Nazi.Zombie.Army.zip`):
1. **Zero-Execution Unpack:** Unpacked 287 assets from Downloads directly to `D:\Games\` without running untrusted scripts.
2. **Crack Neutralization:** Replaced an untrusted 87 KB closed-source `steam_api.dll` with an audited 9.19 MB Goldberg Steam emulator.
3. **Playability Preservation:** Disambiguated `NZA.exe` keyboard/clipboard UI calls from actual malware; retained game executables while generating kernel-level firewall blocking scripts (`block_game_network.ps1`).
4. **Air-Gapped Sandbox:** Created `Sandbox_Sniper_Elite_Nazi_Zombie_Army.wsb` for 1-click ephemeral execution.

*Detailed technical dossier and beginner cheat sheet:* [docs/CASE_STUDY_SNIPER_ELITE.md](docs/CASE_STUDY_SNIPER_ELITE.md)

---

## Running the Automated Test Suite

```powershell
python -m unittest discover tests
```

All 29 tests pass across PE scanning, Authenticode verification, LNK analysis, save migration, repack unpacking, and firewall generation.

---

## Security & Ethics Notice
GameCleaner is a defensive security triage and quarantine tool designed to protect personal systems from malware, trojans, and surveillance payloads frequently bundled in third-party downloads. It does not generate malware or crack games.
