---
name: gamecleaner
description: Security triage, malware isolation, clean emulator replacement, and air-gapped containment for cracked PC games. Use when a user wants to scan a downloaded/cracked game for viruses, remove malicious repacker payloads, replace untrusted crack DLLs with clean open-source emulators (Goldberg/EOS), migrate save games, isolate network access with Windows Firewall, or run games safely in Windows Sandbox.
---

# GameCleaner Agent Skill

GameCleaner provides automated defensive security, malware triage, and playability preservation for downloaded and cracked PC games on Windows.

## Capabilities

1. **Pre-Install Repack Extraction (`unpack`):**
   - Unpacks Inno Setup (`setup.exe`), NSIS installers, and archives directly to disk without executing untrusted installer binaries.
   - Option during installation to immediately sanitize and configure the game (`--clean`).

2. **Full Pipeline Remediation (`clean-all`):**
   - **Static PE & Script Triage:** Analyzes PE headers, sections, entropy, sensitive Win32 API imports, Authenticode signatures, and LNK shortcut exploits.
   - **AI-Assisted Decompiler Triage:** Formats reverse-engineering disassembly snippets and string xrefs to classify benign crack hooks vs. hostile droppers/injectors.
   - **Clean Emulator Replacement:** Replaces untrusted Steamworks (`steam_api.dll`, `steam_api64.dll`), Epic Online Services (`EOSSDK*.dll`), and Ubisoft (`uplay_r1_loader*.dll`) wrappers with verified clean emulators (Goldberg Steam Emulator).
   - **Save Game & Identity Preservation:** Extracts AppID and user persona from scene configs (`steam_emu.ini`, `codex.ini`, `rune.ini`) and migrates existing save files so user game progress is never lost.
   - **Quarantine Isolation:** Isolates malicious droppers, cryptominers, and persistent backdoors into `.gamecleaner_quarantine/`.
   - **Persistence Neutralization:** Audits and removes registry autoruns (`HKCU`/`HKLM` `Run`/`RunOnce`) and malicious Windows Scheduled Tasks.
   - **Firewall & Sandbox Containment:** Generates PowerShell outbound firewall blocking scripts and air-gapped `.wsb` Windows Sandbox profiles.

3. **One-Click Windows Explorer Integration (`setup --context-menu`):**
   - Enables right-click "Clean & Contain with GameCleaner" on any folder or desktop shortcut.

---

## Command Reference

### Verified Case Study
- **Sniper Elite: Nazi Zombie Army (3.32 GB):** Extracted from Downloads to `D:\Games\`, replaced untrusted `steam_api.dll` with clean Goldberg emulator, generated firewall blocking rules, and validated 100% playability. See [docs/CASE_STUDY_SNIPER_ELITE.md](docs/CASE_STUDY_SNIPER_ELITE.md).

### Full Pipeline Clean & Contain
```powershell
# Clean an existing game folder
python -m gamecleaner.cli clean-all "C:\Path\To\Game"

# Unpack a .zip/.7z/.rar directly from Downloads to another drive (e.g. D:) and auto-clean
python -m gamecleaner.cli clean-all "C:\Users\<User>\Downloads\Game.zip" -o "D:\Games\GameName"
```

### Safe Pre-Install Unpack (with Auto-Clean Option)
```powershell
# Unpack and auto-clean extracted files immediately
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "C:\Games\TargetGame"

# Unpack only without immediate cleaning
python -m gamecleaner.cli unpack "C:\Downloads\setup.exe" -o "C:\Games\TargetGame" --no-clean
```

### Save Game & SteamID Migration
```powershell
python -m gamecleaner.cli migrate-saves "C:\Path\To\Game"
```

### Deep Reverse-Engineering Inspection (REA & Ghidra)
```powershell
python -m gamecleaner.cli inspect "C:\Path\To\Game\suspect_binary.dll"
```

### Windows Shell & Environment Setup
```powershell
# One-command hands-free setup (configures context menu, unpackers, and environment)
python -m gamecleaner.cli setup --all

# Check environment readiness
python -m gamecleaner.cli setup --check

# Register Windows Explorer right-click context menu
python -m gamecleaner.cli setup --context-menu

# Configure innoextract unpacker
python -m gamecleaner.cli setup --unpacker
```
