# CLAUDE.md — Instructions for Claude Code

## Commands
- **Install & Setup:** `pip install -e . && python -m gamecleaner.cli setup --all`
- **Run All Tests:** `python -m unittest discover tests`
- **Clean Game Folder:** `python -m gamecleaner.cli clean-all "<path-to-game>"`
- **Unpack & Clean Archive to Target Drive:** `python -m gamecleaner.cli clean-all "<path-to-archive.zip>" -o "<path-to-target-drive>"`
- **Safe Pre-Install Repack Extraction:** `python -m gamecleaner.cli unpack "<setup.exe>" -o "<destination>"`
- **Save Migration:** `python -m gamecleaner.cli migrate-saves "<path-to-game>"`
- **Firewall Rules:** `python -m gamecleaner.cli firewall "<path-to-game>" --elevate`
- **REA Inspection:** `python -m gamecleaner.cli inspect "<path-to-binary>"`

## Architecture
- `gamecleaner/analyzer/`: Static PE analysis (`pe_scanner.py`), LNK analysis (`lnk_scanner.py`), persistence audit (`persistence_auditor.py`), AI triage (`ai_classifier.py`).
- `gamecleaner/cleaner/`: Goldberg emulator replacer (`emu_replacer.py`), safe unpacker (`repack_unpacker.py`), save migrator (`save_migrator.py`), quarantine vault (`quarantine.py`).
- `gamecleaner/containment/`: Firewall isolation scripts (`firewall.py`), Windows Sandbox generator (`sandbox.py`), Explorer context menu manager (`shell_integration.py`).
- `gamecleaner/rea/`: Reverse Engineer Anything engine (Capstone disassembly, string xrefs, interface extraction).
- `emulators/goldberg/`: Pre-bundled clean Goldberg Steam emulators (`steam_api.dll`, `steam_api64.dll`).

## Coding Standards & Rules
- All file operations must handle read-only files (`stat.S_IWRITE`) and NTFS locked files (rename-first evasion).
- Never execute untrusted executables or scripts directly. Always use `RepackUnpacker` or analyze statically.
- Mirror clean emulator DLLs and `steam_appid.txt` to `bin/` or `bin/x64/` subfolders if present.
- If a co-op/LAN game silently closes after a Windows Firewall prompt, check if the user clicked "Cancel" (which creates an Inbound Block rule). Remove it via `Remove-NetFirewallRule -DisplayName '<app>'` or `Fix_Firewall_And_Run.bat`.
- When generating reports, provide clickable markdown links formatted with `file:///` and forward slashes.
- Test suite must always remain 100% passing (`python -m unittest discover tests`).
