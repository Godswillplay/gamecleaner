# CLAUDE.md — Instructions for Claude Code

## Commands
- **Install & Setup:** `pip install -e . && python -m gamecleaner.cli setup --all`
- **Run All Tests:** `python -m unittest discover tests`
- **Clean Game Folder:** `python -m gamecleaner.cli clean-all "<path-to-game>"`
- **Unpack & Clean Archive to Target Drive:** `python -m gamecleaner.cli clean-all "<path-to-archive.zip>" -o "<path-to-target-drive>"`
- **Safe Pre-Install Repack Extraction:** `python -m gamecleaner.cli unpack "<setup.exe>" -o "<destination>"`
- **Save Migration:** `python -m gamecleaner.cli migrate-saves "<path-to-game>"`
- **Firewall Rules:** `python -m gamecleaner.cli firewall "<path-to-game>" --elevate`
- **Verify Cryptographic Integrity:** `python -m gamecleaner.cli verify "<path-to-game>" [--create]`
- **Audit Dependencies & Runtimes:** `python -m gamecleaner.cli deps "<path-to-game>" [--install]`
- **Audit DLL Sideloading:** `python -m gamecleaner.cli sideload "<path-to-game>"`
- **Smart Game Launcher:** `python -m gamecleaner.cli run "<path-to-game>"`
- **Windows Exploit Protection:** `python -m gamecleaner.cli shield "<path-to-game>" [--apply] [--elevate]`
- **Kernel Driver & BYOVD Audit:** `python -m gamecleaner.cli drivers "<path-to-game>"`
- **Steam Deck & Linux Proton Setup:** `python -m gamecleaner.cli proton "<path-to-game>"`
- **Real-Time Network Socket Monitor:** `python -m gamecleaner.cli monitor "<path-to-game>" [--duration <sec>]`
- **Steamless DRM Unpacker:** `python -m gamecleaner.cli steamless "<path-to-game>"`
- **Goldberg Save Game Snapshots:** `python -m gamecleaner.cli save-sync "<path-to-game>" [--snapshot] [--list] [--restore <file>]`
- **WebUI Cyber Defense Dashboard:** `python -m gamecleaner.cli web [--port 8765] [--open]`
- **Crash Forensics & Event Log:** `python -m gamecleaner.cli crash-log "<path-to-game>"`
- **Anti-Cheat & Binary Protector Triage:** `python -m gamecleaner.cli anticheat "<path-to-game>"`
- **Game Mod & Hook Compatibility Audit:** `python -m gamecleaner.cli mods "<path-to-game>"`
- **Epic Online Services (EOS) Emulation:** `python -m gamecleaner.cli eos "<path-to-game>" [--clean]`
- **Process Memory & Injection Hook Audit:** `python -m gamecleaner.cli mem-audit [--pid <PID>] [--name <ExecutableName>]`
- **Universal Cloud Save Exporter/Importer:** `python -m gamecleaner.cli cloud-save "<path-to-game>" [--export-deck] [--import-steam <path>]`
- **REA Inspection:** `python -m gamecleaner.cli inspect "<path-to-binary>"`

## Architecture
- `gamecleaner/analyzer/`: Static PE analysis (`pe_scanner.py`), LNK analysis (`lnk_scanner.py`), persistence audit (`persistence_auditor.py`), AI triage (`ai_classifier.py`), DLL sideloading audit (`sideload_auditor.py`), Steam Stub DRM detector (`steam_stub.py`), Runtime/dependency auditor (`runtime_auditor.py`), Kernel driver & BYOVD auditor (`driver_auditor.py`), Crash forensics (`crash_forensics.py`), Anti-cheat & protector triage (`anticheat_detector.py`), Mod & hook compatibility (`mod_compat.py`), Memory & injection auditor (`memory_scanner.py`).
- `gamecleaner/cleaner/`: Goldberg emulator replacer (`emu_replacer.py`), safe unpacker (`repack_unpacker.py`), save migrator (`save_migrator.py`), quarantine vault (`quarantine.py`), cryptographic integrity verifier (`integrity_verifier.py`), Steamless DRM unpacker (`steamless_unpacker.py`), Save snapshot manager (`save_sync.py`), Epic Online Services emulator replacer (`eos_replacer.py`), Multi-DRM orchestrator (`multidrm.py`), Universal cloud save sync (`cloud_save_sync.py`).
- `gamecleaner/containment/`: Firewall isolation scripts (`firewall.py`), Windows Sandbox generator & container RAM runner (`sandbox.py`), Explorer context menu manager (`shell_integration.py`), Windows Exploit Protection shield (`process_shield.py`), Linux Proton & Steam Deck helper (`proton_helper.py`), Real-time socket monitor (`net_monitor.py`).
- `gamecleaner/web/`: Zero-dependency local cyber defense dashboard and REST API (`server.py`, `api.py`, `templates.py`).
- `gamecleaner/rea/`: Reverse Engineer Anything engine (Capstone disassembly, string xrefs, interface extraction).
- `emulators/goldberg/`: Pre-bundled clean Goldberg Steam emulators (`steam_api.dll`, `steam_api64.dll`).

## Coding Standards & Rules
- All file operations must handle read-only files (`stat.S_IWRITE`) and NTFS locked files (rename-first evasion).
- Never execute untrusted executables or scripts directly. Always use `RepackUnpacker` or analyze statically.
- Mirror clean emulator DLLs and `steam_appid.txt` to `bin/` or `bin/x64/` subfolders if present.
- If a co-op/LAN game silently closes after a Windows Firewall prompt, check if the user clicked "Cancel" (which creates an Inbound Block rule). Remove it via `Remove-NetFirewallRule -DisplayName '<app>'` or `Fix_Firewall_And_Run.bat`.
- When generating reports, provide clickable markdown links formatted with `file:///` and forward slashes.
- Test suite must always remain 100% passing (`python -m unittest discover tests`).
