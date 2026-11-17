# GameCleaner

[![GameCleaner CI](https://github.com/Godswillplay/gamecleaner/actions/workflows/ci.yml/badge.svg)](https://github.com/Godswillplay/gamecleaner/actions)
![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)
![Tests](https://img.shields.io/badge/tests-29%2F29%20passing-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

GameCleaner is an automated defensive security framework for PC games and repacks on Windows. It triages binary payloads, quarantines malicious droppers, replaces closed-source crack DLLs with clean open-source emulators, migrates player saves, and isolates game network access via Windows Firewall and air-gapped Windows Sandbox profiles.

---

## The Problem

Third-party game repacks and scene releases present significant security risks:
1. **Bundled Hostiles:** Shady releases frequently pack infostealers (Lumma, Redline, Vidar), XMRig cryptominers, malicious scheduled tasks, and obfuscated shortcut droppers (`.lnk`).
2. **False Positives vs. Real Threats:** Commercial antivirus engines flag all crack hooks (`steam_api64.dll`, memory loaders) as generic `HackTool`, making it difficult to distinguish harmless offline DRM bypasses from credential-harvesting trojans.
3. **Execution-Time Installer Exploits:** Running untrusted `setup.exe` installers grants full ring-3 user privileges before any files can be examined.

---

## How It Works

```
                       [ Untrusted Game / Repack Archive ]
                                        |
                 +----------------------+----------------------+
                 | Safe Unpack: Inno Setup / NSIS / ZIP / 7z   |
                 | (Extracts assets without executing setup)   |
                 +----------------------+----------------------+
                                        |
                 +----------------------v----------------------+
                 | Static Binary, Script & Shortcut Triage     |
                 | - Shannon entropy analysis (crypters)       |
                 | - WinVerifyTrust Authenticode verification  |
                 | - Sensitive API import scoring              |
                 | - Obfuscated LNK & LOLBin command audit     |
                 | - Scheduled task & registry run inspection  |
                 +----------------------+----------------------+
                                        |
           +----------------------------+----------------------------+
           |                            |                            |
           v                            v                            v
   [ Clean Binaries ]         [ Untrusted Crack DLLs ]     [ Hostile Payloads ]
   - Retain & verify          - steam_api.dll / steam_api64 - Infostealers / miners
                              - EOS / Uplay hooks           - Droppers / bad LNKs
                                        |                            |
                                        v                            v
                              [ Open-Source Emulator ]      [ Quarantine Vault ]
                              - Goldberg Steam Emulator     - Stripped permissions
                              - Interface symbol extraction - Audit manifest (.json)
                              - Save game & ID migration
                                        |
           +----------------------------+
           |
           v
   [ Network Isolation & Containment ]
   - Windows Firewall outbound block scripts
   - Private LAN loopback preservation (avoids socket bind crashes)
   - Air-gapped Windows Sandbox profile (.wsb)
```

---

## Documented Real-World Case: Sniper Elite: Nazi Zombie Army (3.32 GB)

GameCleaner was evaluated end-to-end on a live 3.32 GB archive (`Sniper.Elite.Nazi.Zombie.Army.zip`).

### Target Specifications
- **Archive Path:** `C:\Users\JAI\Downloads\Sniper.Elite.Nazi.Zombie.Army.zip` (3.32 GB)
- **Extracted Destination:** `D:\Games\Sniper.Elite.Nazi.Zombie.Army`
- **Total Files Extracted:** 287 assets (14 PE binaries)

### Execution Command
```powershell
python -m gamecleaner.cli clean-all "C:\Users\JAI\Downloads\Sniper.Elite.Nazi.Zombie.Army.zip" -o "D:\Games\Sniper.Elite.Nazi.Zombie.Army"
```

### Technical Audit & Pipeline Results
1. **Safe Decompression:** Extracted the entire 3.32 GB archive directly to `D:\Games\` without invoking untrusted installer scripts or executables.
2. **Authenticode Verification:**
   - DirectX and Visual C++ redistributable packages: Confirmed valid Microsoft digital signatures.
   - Game executables (`NZA.exe`, `steam_api.dll`): Unsigned (typical of scene releases).
3. **Crack Replacement (Closed-Source Hook -> Clean Goldberg):**
   - Untrusted `steam_api.dll` (87,040 bytes, closed-source hook) was backed up to `.gamecleaner_backup/`.
   - Substituted with pre-bundled, audited **Goldberg Steam Emulator** (`steam_api.dll`, 9,192,360 bytes).
   - Extracted 15 Steamworks interface versions (`SteamClient012`, `SteamUser016`, `SteamFriends011`, `SteamApps005`, `SteamHTTP001`, `SteamNetworking005`, etc.) into `steam_interfaces.txt`.
   - Identified and configured the correct Steam AppID (`227100`) in `steam_appid.txt` and `steam_settings/steam_appid.txt`.
   - Automatically mirrored `steam_api.dll` and `steam_appid.txt` into `bin/` subdirectories to prevent dynamic linker path failures.
4. **Binary Heuristic Disambiguation (`NZA.exe`):**
   - Scanned imports: `user32.dll!GetAsyncKeyState` (keyboard polling in game loop) and `user32.dll!GetClipboardData` (chat paste).
   - Verified zero process injection calls (`WriteProcessMemory`, `CreateRemoteThread` absent).
   - Verified zero credential access calls (`CryptUnprotectData`, `VaultGetItem` absent).
   - Assigned to `FIREWALL_BLOCK`: Executable preserved for playability while isolating network traffic.

### Edge Case Discovered & Resolved: The Windows Firewall "Cancel" Trap
- **The Issue:** On first launch, the game's multiplayer subsystem calls `WSOCK32!bind()` and `WSOCK32!listen()` on local port `0.0.0.0` to detect LAN sessions. Windows Network Location Awareness displayed a prompt: *"Allow NZA.exe to access networks?"*. Clicking **Cancel** caused Windows Defender Firewall to create permanent inbound block rules. On subsequent launches, `NZA.exe` threw a socket exception on `bind()` and silently closed with exit code `-1` (`0xFFFFFFFF`).
- **The Fix:** Hardened GameCleaner's firewall generation (`firewall.py`) to block **Outbound on Any Profile** (preventing telemetry/data exfiltration) while permitting local loopback/Private LAN sockets. GameCleaner generated `Fix_Firewall_And_Run.bat` to purge conflicting Windows block rules and launch with correct permissions.
- **Verification:** Game launched directly to the main menu with functional audio, graphics, offline entitlements, and save progression intact.

---

## Installation

### Prerequisites
- Windows 10 or Windows 11 (64-bit)
- Python 3.10, 3.11, or 3.12

### Setup
```powershell
# Clone the repository
git clone https://github.com/Godswillplay/gamecleaner.git
cd gamecleaner

# Install dependencies and editable package
pip install -r requirements.txt
pip install -e .

# Run one-time environment setup (context menu, unpacker verification)
python -m gamecleaner.cli setup --all

# Confirm test suite
python -m unittest discover tests
```

---

## CLI Reference

### 1. Full Sanitization Pipeline (`clean-all`)
Runs the complete workflow: unpack, static scan, save migration, crack replacement, quarantine, firewall generation, and sandbox creation.

```powershell
# Clean an extracted folder
python -m gamecleaner.cli clean-all "D:\Games\TargetGame"

# Unpack an archive or installer from Downloads directly into another drive and sanitize
python -m gamecleaner.cli clean-all "C:\Downloads\GameArchive.zip" -o "D:\Games\TargetGame"
```

### 2. Pre-Install Repack Extraction (`unpack`)
Extracts Inno Setup installers (`setup.exe`), NSIS packages, or archives (`.zip`, `.7z`, `.rar`) without executing any code.

```powershell
# Unpack and automatically sanitize during installation (Default)
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "D:\Games\TargetGame"

# Unpack only without running sanitization
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "D:\Games\TargetGame" --no-clean
```

### 3. Save Game & SteamID Migrator (`migrate-saves`)
Reads scene configuration files (`steam_emu.ini`, `codex.ini`, `rune.ini`) and maps player saves and account IDs to Goldberg storage.

```powershell
python -m gamecleaner.cli migrate-saves "D:\Games\TargetGame"
```

### 4. Windows Explorer Context Menu (`setup`)
Integrates GameCleaner into Windows Explorer right-click menus (writes strictly to `HKCU`, requires zero administrator privileges).

```powershell
# Register right-click menu
python -m gamecleaner.cli setup --context-menu

# Remove right-click menu
python -m gamecleaner.cli setup --remove-context-menu
```

### 5. Binary Inspection & Reverse Engineering (`inspect`)
Disassembles PE entry points and extracts string cross-references into an evidence dossier (`REA_EVIDENCE_<binary>.md`).

```powershell
python -m gamecleaner.cli inspect "D:\Games\TargetGame\game.exe"
```

---

## AI Agent Integration

GameCleaner is structured for autonomous operation by AI coding assistants:
- **`AGENTS.md`**: Complete execution instructions for Antigravity, Claude Code, Cursor, and Windsurf.
- **`SKILL.md`**: Agent skill specification for tool invocation.
- **`CLAUDE.md`**: Concise architecture and workflow cheatsheet.

---

## Automated Test Suite

GameCleaner includes an automated test suite verifying static analysis, Authenticode signature checks, LNK parsing, save migration, repack extraction, and firewall scripts.

```powershell
python -m unittest discover tests
```

Output:
```text
Ran 29 tests in 9.886s

OK
```

---

## Security Model

- **Zero-Execution Extraction:** Archives and installers are parsed and decompressed via native format streaming, never executed in host user space.
- **Pre-Bundled Goldberg Emulators:** Verified clean emulators (`steam_api.dll` and `steam_api64.dll`) are permanently bundled in `emulators/goldberg/`. No external runtime downloads are required.
- **Non-Destructive Backups:** Replaced files are backed up to `.gamecleaner_backup/` with original timestamps.
- **Strict Quarantine:** Malicious binaries are stripped of execute permissions (`icacls /deny Everyone:(X)`) and moved to `.gamecleaner_quarantine/`.
- **Defensive Scope:** GameCleaner is designed strictly to protect personal machines against malware, trojans, and surveillance payloads frequently bundled in third-party downloads. It does not generate malware or crack games.
