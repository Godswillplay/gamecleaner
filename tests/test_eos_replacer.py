"""
Unit tests for Epic Online Services (EOS) Emulator Replacer & Configuration Engine.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from gamecleaner.cleaner.eos_replacer import (
    EOSConfig,
    EOSReplacementResult,
    EOSReplacer,
    EOSTarget,
)


class TestEOSReplacer(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()
        self.replacer = EOSReplacer(self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_mock_pe(self, path: Path, arch: str = "x64", extra_bytes: bytes = b"") -> None:
        """Helper to create a minimal mock PE binary with valid machine header."""
        path.parent.mkdir(parents=True, exist_ok=True)
        # MZ header (0x00 to 0x3C)
        data = bytearray(b"MZ" + b"\x00" * 58)
        # Pointer to PE header at offset 0x3C
        data.extend((0x80).to_bytes(4, "little"))
        data.extend(b"\x00" * (0x80 - len(data)))
        # PE signature "PE\0\0"
        data.extend(b"PE\x00\x00")
        # Machine type
        machine = 0x8664 if arch == "x64" else 0x014C
        data.extend(machine.to_bytes(2, "little"))
        data.extend(b"\x00" * 20)
        data.extend(extra_bytes)
        path.write_bytes(bytes(data))

    def test_eos_config_serialization(self):
        config = EOSConfig(
            app_name="DeadIsland2",
            catalog_item_id="item_12345",
            catalog_namespace="ns_67890",
            account_id="acc_abcdef",
            exchange_code="code_999",
            product_id="prod_111",
            sandbox_id="sand_222",
            deployment_id="dep_333",
            user_name="GamerOne",
            offline_mode=True,
            raw_properties={"CustomOption": "ValueX"},
        )
        ini_text = config.to_ini_string()
        self.assertIn("[Epic]", ini_text)
        self.assertIn("AppName = DeadIsland2", ini_text)
        self.assertIn("CatalogItemId = item_12345", ini_text)
        self.assertIn("CatalogNamespace = ns_67890", ini_text)
        self.assertIn("AccountId = acc_abcdef", ini_text)
        self.assertIn("ExchangeCode = code_999", ini_text)
        self.assertIn("Offline = 1", ini_text)
        self.assertIn("CustomOption = ValueX", ini_text)

        d = config.to_dict()
        self.assertEqual(d["AppName"], "DeadIsland2")
        self.assertEqual(d["CatalogItemId"], "item_12345")
        self.assertTrue(d["Offline"])

    def test_find_eos_targets_root_and_subdirs(self):
        # Create Win64 EOS in root
        eos64 = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos64, "x64", b"EOS_Initialize EOS_Platform_Create 1.15.0")

        # Create Win32 EOS in subfolder
        bin32_dir = self.game_dir / "Binaries" / "Win32"
        eos32 = bin32_dir / "EOSSDK-Win32-Shipping.dll"
        self._create_mock_pe(eos32, "x86", b"Nemirtingas Epic Online Services Emulator")

        targets = self.replacer.find_eos_targets()
        self.assertEqual(len(targets), 2)

        target_map = {t.dll_name: t for t in targets}
        self.assertIn("EOSSDK-Win64-Shipping.dll", target_map)
        self.assertIn("EOSSDK-Win32-Shipping.dll", target_map)

        t64 = target_map["EOSSDK-Win64-Shipping.dll"]
        self.assertEqual(t64.architecture, "x64")
        self.assertIn("EOS_Initialize", t64.exports)
        self.assertIn("EOS_Platform_Create", t64.exports)
        self.assertEqual(t64.version, "1.15.0")

        t32 = target_map["EOSSDK-Win32-Shipping.dll"]
        self.assertEqual(t32.architecture, "x86")
        self.assertTrue(t32.is_emulator)
        self.assertEqual(t32.emulator_flavor, "Nemirtingas")

    def test_discover_config_from_epic_emu_ini(self):
        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos_dll, "x64")

        ini_content = """[Epic]
AppName=SaintsRow
CatalogItemId=cat_item_987
CatalogNamespace=cat_ns_654
AccountId=acc_fake_id_123
ExchangeCode=ex_code_456
ProductId=prod_aaa
SandboxId=sand_bbb
DeploymentId=dep_ccc
UserName=TestSaints
Offline=1
CustomParam=PreservedValue
"""
        (self.game_dir / "epic_emu.ini").write_text(ini_content, encoding="utf-8")

        config, discovered = self.replacer.discover_config(self.game_dir)
        self.assertEqual(config.app_name, "SaintsRow")
        self.assertEqual(config.catalog_item_id, "cat_item_987")
        self.assertEqual(config.catalog_namespace, "cat_ns_654")
        self.assertEqual(config.account_id, "acc_fake_id_123")
        self.assertEqual(config.exchange_code, "ex_code_456")
        self.assertEqual(config.product_id, "prod_aaa")
        self.assertEqual(config.sandbox_id, "sand_bbb")
        self.assertEqual(config.deployment_id, "dep_ccc")
        self.assertEqual(config.user_name, "TestSaints")
        self.assertTrue(config.offline_mode)
        self.assertEqual(config.raw_properties.get("CustomParam"), "PreservedValue")
        self.assertEqual(len(discovered), 1)

    def test_discover_config_from_eos_settings_json(self):
        eos_dir = self.game_dir / "EOS_settings"
        eos_dir.mkdir(parents=True)
        json_file = eos_dir / "EOS_settings.json"
        data = {
            "AppName": "MetroExodus",
            "CatalogItemId": "metro_item",
            "CatalogNamespace": "metro_ns",
            "AccountId": "metro_acc",
            "ExchangeCode": "metro_auth",
            "UserName": "Artyom",
            "Offline": True,
        }
        json_file.write_text(json.dumps(data), encoding="utf-8")

        config, discovered = self.replacer.discover_config(self.game_dir)
        self.assertEqual(config.app_name, "MetroExodus")
        self.assertEqual(config.catalog_item_id, "metro_item")
        self.assertEqual(config.catalog_namespace, "metro_ns")
        self.assertEqual(config.account_id, "metro_acc")
        self.assertEqual(config.exchange_code, "metro_auth")
        self.assertEqual(config.user_name, "Artyom")

    def test_generate_clean_config(self):
        config = EOSConfig(
            app_name="Borderlands3",
            catalog_item_id="bl3_item",
            catalog_namespace="bl3_ns",
            account_id="bl3_acc",
            exchange_code="bl3_code",
            user_name="VaultHunter",
            offline_mode=True,
        )
        written = self.replacer.generate_clean_config(config, self.game_dir)
        self.assertTrue(len(written) >= 2)

        epic_emu = self.game_dir / "epic_emu.ini"
        self.assertTrue(epic_emu.exists())
        content = epic_emu.read_text(encoding="utf-8")
        self.assertIn("AppName = Borderlands3", content)
        self.assertIn("CatalogItemId = bl3_item", content)
        self.assertIn("AccountId = bl3_acc", content)

        json_cfg = self.game_dir / "EOS_settings" / "EOS_settings.json"
        self.assertTrue(json_cfg.exists())
        json_data = json.loads(json_cfg.read_text(encoding="utf-8"))
        self.assertEqual(json_data["AppName"], "Borderlands3")

    def test_replace_with_clean_emulator(self):
        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos_dll, "x64", b"Untrusted closed-source cracked EOS wrapper 0xdeadc0de")

        # Fake executable in bin/x64 to verify mirroring
        bin_dir = self.game_dir / "bin" / "x64"
        bin_dir.mkdir(parents=True)
        (bin_dir / "Game.exe").write_bytes(b"MZ" + b"\x00" * 50)

        # Create clean emulator binary
        clean_emu = self.game_dir / "clean_eos_stub.dll"
        clean_emu.write_bytes(b"MZ" + b"\x00" * 2000 + b"Clean Open Source EOS Emulator")

        targets = self.replacer.find_eos_targets()
        self.assertEqual(len(targets), 1)

        result = self.replacer.replace_or_isolate(targets[0], custom_clean_dll=clean_emu)
        self.assertTrue(result.success)
        self.assertEqual(result.action_taken, "REPLACED_WITH_CLEAN_EMU")
        self.assertTrue(result.backup_path.exists())

        # Verify target was overwritten with clean emulator
        new_content = eos_dll.read_bytes()
        self.assertIn(b"Clean Open Source EOS Emulator", new_content)

        # Verify clean config was written
        self.assertTrue((self.game_dir / "epic_emu.ini").exists())

        # Verify clean emulator and config mirrored to bin/x64
        self.assertTrue((bin_dir / "EOSSDK-Win64-Shipping.dll").exists())
        self.assertTrue((bin_dir / "epic_emu.ini").exists())

    def test_safe_isolation_when_no_clean_emulator_available(self):
        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos_dll, "x64", b"Hostile closed source cracked dll")

        targets = self.replacer.find_eos_targets()
        self.assertEqual(len(targets), 1)

        result = self.replacer.replace_or_isolate(targets[0], custom_clean_dll=None, isolate_if_no_clean=True)
        self.assertTrue(result.success)
        self.assertEqual(result.action_taken, "ISOLATED_AND_STUBBED")

        # Original untrusted DLL is no longer directly runnable under original name
        self.assertFalse(eos_dll.exists())
        # Renamed to .gc_isolated
        isolated_file = self.game_dir / "EOSSDK-Win64-Shipping.dll.gc_isolated"
        self.assertTrue(isolated_file.exists())
        # Clean configuration generated
        self.assertTrue((self.game_dir / "epic_emu.ini").exists())

    def test_safe_backup_and_rollback(self):
        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        original_bytes = b"MZ" + b"\x00" * 100 + b"OriginalPreCleanBytes"
        eos_dll.write_bytes(original_bytes)

        clean_emu = self.game_dir / "clean_stub.dll"
        clean_emu.write_bytes(b"MZ" + b"\x00" * 100 + b"CleanReplacedStub")

        targets = self.replacer.find_eos_targets()
        result = self.replacer.replace_or_isolate(targets[0], custom_clean_dll=clean_emu)
        self.assertTrue(result.success)

        # Check backup exists in .gamecleaner_backup
        backups = self.replacer.list_backups()
        self.assertEqual(len(backups), 1)
        backup_name = backups[0]["backup_file"]

        # Current DLL is clean emulator
        self.assertIn(b"CleanReplacedStub", eos_dll.read_bytes())

        # Rollback
        restored = self.replacer.rollback(backup_name)
        self.assertTrue(restored)

        # Verify original bytes restored
        self.assertEqual(eos_dll.read_bytes(), original_bytes)
        self.assertEqual(len(self.replacer.list_backups()), 0)


if __name__ == "__main__":
    unittest.main()
