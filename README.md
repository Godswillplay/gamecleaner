# GameCleaner

[![GameCleaner CI](https://github.com/Godswillplay/gamecleaner/actions/workflows/ci.yml/badge.svg)](https://github.com/Godswillplay/gamecleaner/actions)
![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)
![Tests](https://img.shields.io/badge/tests-179%2F179%20passing-brightgreen.svg)
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

### 5. Security & Containment Status (`status`)
Inspects the overall security posture, emulator status, quarantine vault, and firewall state of any game directory.

```powershell
python -m gamecleaner.cli status "D:\Games\TargetGame"
```

### 6. Interactive Terminal Wizard (`interactive` or `-i`)
Launches the hands-free interactive menu for guided triage, unpacking, quarantine management, and containment.

```powershell
python -m gamecleaner.cli interactive
# Or simply run without arguments in an interactive terminal
python -m gamecleaner
```

### 7. Quarantine Vault Management (`quarantine`)
Inspect and restore files isolated during automated sanitization.

```powershell
# List quarantined files
python -m gamecleaner.cli quarantine "D:\Games\TargetGame" --list

# Restore a specific file
python -m gamecleaner.cli quarantine "D:\Games\TargetGame" --restore "suspicious.dll_20261120_100000.quarantined"

# Restore all quarantined files
python -m gamecleaner.cli quarantine "D:\Games\TargetGame" --restore-all
```

### 8. DLL Rollback (`rollback`)
View and restore original DRM DLLs from `.gamecleaner_backup/`.

```powershell
# List available backups
python -m gamecleaner.cli rollback "D:\Games\TargetGame" --list

# Restore all original DLLs
python -m gamecleaner.cli rollback "D:\Games\TargetGame" --all
```

### 9. Binary Inspection & Reverse Engineering (`inspect`)
Disassembles PE entry points and extracts string cross-references into an evidence dossier (`REA_EVIDENCE_<binary>.md`).

```powershell
python -m gamecleaner.cli inspect "D:\Games\TargetGame\game.exe"
```

### 10. Cryptographic Game Integrity Verifier (`verify`)
Generates and audits SHA-256 cryptographic manifests (`.gamecleaner_manifest.json`) to detect post-cleaning corruption, modified binaries, or newly injected unknown files.

```powershell
# Create cryptographic manifest of clean game directory
python -m gamecleaner.cli verify "D:\Games\TargetGame" --create

# Verify game directory integrity against existing manifest
python -m gamecleaner.cli verify "D:\Games\TargetGame"
```

### 11. Dependency & Runtime Auditor (`deps`)
Audits all imported DLLs for required Visual C++, DirectX End-User, and OpenAL runtimes. Verifies host system presence and locates bundled installers in `_CommonRedist/` or `redist/`.

```powershell
# Audit dependencies and check host system presence
python -m gamecleaner.cli deps "D:\Games\TargetGame"

# Silently install any discovered repack redistributables
python -m gamecleaner.cli deps "D:\Games\TargetGame" --install
```

### 12. DLL Sideloading & Proxy Auditor (`sideload`)
Detects DLL Search-Order Hijacking (e.g. `version.dll`, `winhttp.dll`, `dxgi.dll` placed next to the game executable). Distinguishes legitimate game enhancements (ReShade, BepInEx, SpecialK) from malicious proxy droppers.

```powershell
python -m gamecleaner.cli sideload "D:\Games\TargetGame"
```

### 13. Smart Isolated Game Launcher (`run`)
Automatically remediates the Windows Firewall "Cancel" trap, captures a pre-launch save game snapshot, verifies required runtimes, and launches the sanitized game executable.

```powershell
python -m gamecleaner.cli run "D:\Games\TargetGame"
```

### 14. Windows Exploit Protection Shield (`shield`)
Enforces native Windows Exploit Protection (`DisallowChildProcessCreation` and `StrictHandleCheck`) to prevent malicious game wrappers from spawning background miners (`xmrig.exe`), `powershell.exe`, or dropped scripts.

```powershell
# Inspect mitigation status and generate PowerShell scripts
python -m gamecleaner.cli shield "D:\Games\TargetGame"

# Apply mitigations immediately with Admin elevation
python -m gamecleaner.cli shield "D:\Games\TargetGame" --elevate
```

### 15. Kernel Driver & BYOVD Auditor (`drivers`)
Audits kernel-mode drivers (`.sys`) and driver installation scripts against known vulnerable driver families (LOLDrivers / BYOVD database: `gdrv`, `mhyprot2`, `procexp`, `rtcore64`, `iqvw64e`, `asiodrv`, `dbutil_2_3`) and validates Authenticode EV/WHQL code-signing.

```powershell
python -m gamecleaner.cli drivers "D:\Games\TargetGame"
```

### 16. Steam Deck & Linux Proton Compatibility (`proton`)
Generates POSIX `run_proton.sh` with Wine DLL overrides (`WINEDLLOVERRIDES="steam_api=n,b;steam_api64=n,b"`) and Linux network namespace isolation (`unshare -n` / `firejail`) for seamless, air-gapped gaming on Steam Deck.

```powershell
python -m gamecleaner.cli proton "D:\Games\TargetGame"
```

### 17. Real-Time Socket & C2 Monitor (`monitor`)
Monitors process network sockets in real-time to detect outbound telemetry, remote C2 communication, or mining pool connections.

```powershell
python -m gamecleaner.cli monitor "D:\Games\TargetGame" --duration 15
```

### 18. Automated Steamless DRM Unpacker (`steamless`)
Unpacks Valve's encrypted SteamStub DRM (`.bind` sections) via headless Steamless CLI, backs up originals, and swaps clean unpacked binaries.

```powershell
python -m gamecleaner.cli steamless "D:\Games\TargetGame"
```

### 19. Goldberg Save Game Snapshots & Versioned Rollback (`save-sync`)
Creates timestamped `.zip` save snapshots before/after gaming sessions with instant point-in-time progress restoration and Zip-Slip traversal protection.

```powershell
# Create a versioned save snapshot
python -m gamecleaner.cli save-sync "D:\Games\TargetGame" --snapshot

# List all progress snapshots
python -m gamecleaner.cli save-sync "D:\Games\TargetGame" --list

# Restore from a snapshot
python -m gamecleaner.cli save-sync "D:\Games\TargetGame" --restore "save_snapshot_227100_20261120_120000.zip"
```

---

## AI Agent Integration

GameCleaner is structured for autonomous operation by AI coding assistants:
- **`AGENTS.md`**: Complete execution instructions for Antigravity, Claude Code, Cursor, and Windsurf.
- **`SKILL.md`**: Agent skill specification for tool invocation.
- **`CLAUDE.md`**: Concise architecture and workflow cheatsheet.

---

## Automated Test Suite

GameCleaner includes an automated test suite verifying static analysis, Authenticode signature checks, LNK parsing, save migration, repack extraction, firewall scripts, sideloading auditing, runtime checking, cryptographic integrity verification, Exploit Protection, kernel driver BYOVD inspection, Proton compatibility, network socket monitoring, Steamless unpacking, and save synchronization.

```powershell
python -m unittest discover tests
```

Output:
```text
Ran 179 tests in 23.023s

OK
```

---

## Security Model

- **Zero-Execution Extraction:** Archives and installers are parsed and decompressed via native format streaming, never executed in host user space.
- **Pre-Bundled Goldberg Emulators:** Verified clean emulators (`steam_api.dll` and `steam_api64.dll`) are permanently bundled in `emulators/goldberg/`. No external runtime downloads are required.
- **Non-Destructive Backups:** Replaced files are backed up to `.gamecleaner_backup/` with original timestamps.
- **Strict Quarantine:** Malicious binaries are stripped of execute permissions (`icacls /deny Everyone:(X)`) and moved to `.gamecleaner_quarantine/`.
- **Defensive Scope:** GameCleaner is designed strictly to protect personal machines against malware, trojans, and surveillance payloads frequently bundled in third-party downloads. It does not generate malware or crack games.
