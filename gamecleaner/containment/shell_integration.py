"""
Windows Explorer Shell Integration for GameCleaner.
Registers/unregisters right-click context menu in Windows Explorer for one-click game triage,
containment, and pre-install unpack/clean for .zip/.7z/.rar archives.
Writes to HKCU (Current User), requiring zero administrative privileges.
"""
import os
from pathlib import Path
import sys
from typing import Tuple
import winreg


class ShellIntegrationManager:
    """Manages Windows Explorer context menu entries for GameCleaner."""

    SHELL_NAME = "GameCleaner"
    FOLDER_MENU_TEXT = "Clean & Contain with GameCleaner"
    ARCHIVE_MENU_TEXT = "Unpack & Clean with GameCleaner"

    def __init__(self):
        self.home_dir = Path.home() / ".gamecleaner"
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self.bat_path = self.home_dir / "clean_game_context.bat"
        self.archive_bat_path = self.home_dir / "unpack_clean_context.bat"

    def _ensure_launcher_scripts(self) -> Tuple[Path, Path]:
        """Creates batch file launchers for folder cleaning and archive unpacking."""
        python_exe = sys.executable
        if python_exe.lower().endswith("pythonw.exe"):
            python_exe = python_exe[:-5] + ".exe"

        # 1. Folder Cleaner Launcher
        folder_content = (
            "@echo off\n"
            "setlocal\n"
            'set "TARGET=%~1"\n'
            'if "%TARGET:~-1%"=="\\" set "TARGET=%TARGET:~0,-1%"\n'
            "title GameCleaner - Game Triage and Security Containment\n"
            f'"{python_exe}" -m gamecleaner.cli clean-all "%TARGET%"\n'
            "echo.\n"
            "echo [Press any key to close this window...]\n"
            "pause >nul\n"
        )
        self.bat_path.write_text(folder_content, encoding="utf-8")

        # 2. Archive Unpack & Clean Launcher
        archive_content = (
            "@echo off\n"
            "setlocal\n"
            'set "TARGET=%~1"\n'
            'if "%TARGET:~-1%"=="\\" set "TARGET=%TARGET:~0,-1%"\n'
            "title GameCleaner - Unpack and Clean Game Archive\n"
            f'"{python_exe}" -m gamecleaner.cli unpack "%TARGET%"\n'
            "echo.\n"
            "echo [Press any key to close this window...]\n"
            "pause >nul\n"
        )
        self.archive_bat_path.write_text(archive_content, encoding="utf-8")

        return self.bat_path, self.archive_bat_path

    def _ensure_launcher_script(self) -> Path:
        """Backwards compatibility alias for folder launcher script."""
        folder_bat, _ = self._ensure_launcher_scripts()
        return folder_bat

    def is_installed(self) -> bool:
        """Checks if the context menu entry exists in HKCU."""
        key_path = r"Software\Classes\Directory\shell\GameCleaner"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path):
                return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def install(self) -> Tuple[bool, str]:
        """Registers the right-click context menu in HKCU for folders, directory backgrounds, and archives."""
        folder_bat, archive_bat = self._ensure_launcher_scripts()
        python_exe = sys.executable
        if python_exe.lower().endswith("pythonw.exe"):
            python_exe = python_exe[:-5] + ".exe"

        # Double-wrapped quotes for cmd.exe /c protect quoted paths and arguments from cmd.exe quote stripping
        folder_cmd = f'cmd.exe /c ""{folder_bat}" "%1""'
        bg_cmd = f'cmd.exe /c ""{folder_bat}" "%V""'
        archive_cmd = f'cmd.exe /c ""{archive_bat}" "%1""'

        folder_targets = [
            (r"Software\Classes\Directory\shell\GameCleaner", folder_cmd, self.FOLDER_MENU_TEXT),
            (r"Software\Classes\Directory\Background\shell\GameCleaner", bg_cmd, self.FOLDER_MENU_TEXT),
        ]

        archive_targets = [
            (r"Software\Classes\SystemFileAssociations\.zip\shell\GameCleaner", archive_cmd, self.ARCHIVE_MENU_TEXT),
            (r"Software\Classes\SystemFileAssociations\.7z\shell\GameCleaner", archive_cmd, self.ARCHIVE_MENU_TEXT),
            (r"Software\Classes\SystemFileAssociations\.rar\shell\GameCleaner", archive_cmd, self.ARCHIVE_MENU_TEXT),
        ]

        try:
            for base_key_path, cmd, text in folder_targets + archive_targets:
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base_key_path) as key:
                    winreg.SetValueEx(key, "", 0, winreg.REG_SZ, text)
                    winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'"{python_exe}"')

                cmd_key_path = f"{base_key_path}\\command"
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cmd_key_path) as cmd_key:
                    winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, cmd)

            return True, "Context menus registered successfully for Folders and Archives (.zip, .7z, .rar)."
        except Exception as e:
            return False, f"Failed to register context menu: {e}"

    def _delete_key_tree(self, root_key, key_path: str):
        """Recursively deletes a registry key and all its subkeys."""
        try:
            with winreg.OpenKey(root_key, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                while True:
                    try:
                        sub = winreg.EnumKey(key, 0)
                        self._delete_key_tree(root_key, f"{key_path}\\{sub}")
                    except OSError:
                        break
            winreg.DeleteKey(root_key, key_path)
        except FileNotFoundError:
            pass
        except Exception:
            try:
                winreg.DeleteKey(root_key, key_path)
            except Exception:
                pass

    def uninstall(self) -> Tuple[bool, str]:
        """Removes all GameCleaner context menu entries from HKCU."""
        targets = [
            r"Software\Classes\Directory\shell\GameCleaner\command",
            r"Software\Classes\Directory\shell\GameCleaner",
            r"Software\Classes\Directory\Background\shell\GameCleaner\command",
            r"Software\Classes\Directory\Background\shell\GameCleaner",
            r"Software\Classes\SystemFileAssociations\.zip\shell\GameCleaner\command",
            r"Software\Classes\SystemFileAssociations\.zip\shell\GameCleaner",
            r"Software\Classes\SystemFileAssociations\.7z\shell\GameCleaner\command",
            r"Software\Classes\SystemFileAssociations\.7z\shell\GameCleaner",
            r"Software\Classes\SystemFileAssociations\.rar\shell\GameCleaner\command",
            r"Software\Classes\SystemFileAssociations\.rar\shell\GameCleaner",
        ]

        errors = []
        for key_path in targets:
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except FileNotFoundError:
                pass
            except Exception as e:
                # Attempt recursive deletion fallback
                try:
                    self._delete_key_tree(winreg.HKEY_CURRENT_USER, key_path)
                except Exception as inner_e:
                    errors.append(f"{key_path}: {inner_e}")

        # Clean up batch scripts
        try:
            if self.bat_path.exists():
                self.bat_path.unlink()
        except Exception:
            pass
        try:
            if self.archive_bat_path.exists():
                self.archive_bat_path.unlink()
        except Exception:
            pass

        if not errors:
            return True, "Context menus unregistered successfully."
        else:
            return False, f"Errors while unregistering: {'; '.join(errors)}"
