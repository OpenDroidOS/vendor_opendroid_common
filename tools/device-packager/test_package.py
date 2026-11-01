# Copyright 2026 OpenDroidOS
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from pathlib import Path
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET

import package


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / "system.img"
        self.image.write_bytes(b"\0" * 4096)
        self.manifest = self.root / "plan.json"
        self.data = {"format_version": 1, "boards": ["example"], "product_id": "example",
            "version": "1.0", "slot": "a", "logical_backend": "existing-mappers",
            "groups": {"os_a": 8192}, "partitions": [{"name": "system", "operation": "write",
            "kind": "logical", "group": "os_a", "capacity_bytes": 8192,
            "block_device": "/dev/block/mapper/system_a", "image": "system.img"}]}

    def validate(self):
        self.manifest.write_text(json.dumps(self.data))
        return package.validate(self.manifest)

    def test_expanded_sparse_size_controls_budget(self):
        self.image.write_bytes(struct.pack("<I4H4I", package.SPARSE_MAGIC, 1, 0, 28, 12, 4096, 3, 1, 0)
                               + struct.pack("<2H2I", 0xCAC3, 0, 3, 12))
        with self.assertRaisesRegex(package.PackageError, "12288 bytes"):
            self.validate()

    def test_truncated_sparse_payload_is_rejected(self):
        self.image.write_bytes(struct.pack("<I4H4I", package.SPARSE_MAGIC, 1, 0, 28, 12, 4096, 1, 1, 0)
                               + struct.pack("<2H2I", 0xCAC1, 0, 1, 4108))
        with self.assertRaisesRegex(package.PackageError, "truncated sparse chunk payload"):
            self.validate()

    def test_preserved_logical_allocation_counts_against_group(self):
        self.data["partitions"].append({"name": "system_ext", "operation": "preserve", "kind": "logical",
            "group": "os_a", "capacity_bytes": 4096, "block_device": "/dev/block/mapper/system_ext_a", "image": None})
        with self.assertRaisesRegex(package.PackageError, "group os_a exceeds"):
            self.validate()

    def test_slot_mismatch(self):
        self.data["partitions"][0]["block_device"] = "/dev/block/mapper/system_b"
        with self.assertRaisesRegex(package.PackageError, "suffix"):
            self.validate()

    def test_empty_partition_requires_a_real_nonempty_image(self):
        self.image.write_bytes(b"")
        with self.assertRaisesRegex(package.PackageError, "zero-length"):
            self.validate()

    def test_firmware_partitions_are_not_os_targets(self):
        self.data["partitions"][0]["name"] = "xbl"
        with self.assertRaisesRegex(package.PackageError, "firmware"):
            self.validate()

    def test_chained_vbmeta_does_not_inherit_top_level_flags(self):
        self.data["partitions"][0]["name"] = "vbmeta_system"
        header = bytearray(4096)
        header[:4] = b"AVB0"
        struct.pack_into(">I", header, 120, 2)
        self.image.write_bytes(header)
        with self.assertRaisesRegex(package.PackageError, "chained vbmeta"):
            self.validate()

    def test_preparation_references_existing_images_without_copying(self):
        self.validate()
        binary = self.root / "updater_binary"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 16, 2)
        struct.pack_into("<H", header, 18, 183)
        binary.write_bytes(header)
        output = self.root / "prepared"
        package.prepare(self.manifest, output, binary)
        self.assertTrue((output / "target/system.img").is_symlink())
        self.assertEqual((output / "target/system.img").resolve(), self.image)
        xml = ET.parse(output / "target/updater_config/updater_specified_config.xml")
        self.assertEqual(xml.find("group/component").attrib["compAddr"], "system")
        self.assertEqual((output / "fstab.updater").read_text(),
                         "/dev/block/mapper/system_a /system none defaults defaults\n")

    def test_oversized_native_component_does_not_emit_partial_target(self):
        with self.image.open("wb") as stream:
            stream.truncate(2 ** 31)
        self.data["partitions"][0]["capacity_bytes"] = 2 ** 31
        self.data["groups"]["os_a"] = 2 ** 31
        self.manifest.write_text(json.dumps(self.data))
        binary = self.root / "updater_binary"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 16, 2)
        struct.pack_into("<H", header, 18, 183)
        binary.write_bytes(header)
        with self.assertRaisesRegex(package.PackageError, "large-component"):
            package.prepare(self.manifest, self.root / "prepared", binary)
        self.assertFalse((self.root / "prepared").exists())

    def test_v3_selection_reaches_native_xml_and_verification_plan(self):
        self.validate()
        binary = self.root / "updater_binary"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", header, 16, 2, 183)
        binary.write_bytes(header)
        output = self.root / "prepared"
        package.prepare(self.manifest, output, binary, 3)
        xml = ET.parse(output / "target/updater_config/updater_specified_config.xml")
        self.assertEqual(xml.find("head/info").attrib["fileVersion"], "3")
        self.assertEqual(json.loads((output / "plan.json").read_text())["package_file_version"], 3)


if __name__ == "__main__":
    unittest.main()
