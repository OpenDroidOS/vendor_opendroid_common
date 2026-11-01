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
from unittest.mock import patch

import avb_bundle as avb


class AvbTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "key.pem").write_bytes(b"key fixture")
        (self.root / "public.key").write_bytes(b"public fixture")
        self.tool = self.root / "avbtool"
        self.tool.write_text("#!/bin/sh\nexit 1\n")
        self.tool.chmod(0o755)
        self.parts = [self.part("vbmeta", "top-level"), self.part("vbmeta_system", "chained")]
        self.parts[0]["chain_partitions"] = [{"name": "vbmeta_system", "rollback_index_location": 1,
                                               "public_key": "public.key"}]
        self.manifest = self.root / "plan.json"

    def part(self, name, role):
        return {"name": name, "role": role, "output": name + ".img", "partition_size": 4096,
                "key": "key.pem", "algorithm": "SHA256_RSA2048", "rollback_index": 0,
                "rollback_index_location": 0, "descriptors_from": [], "chain_partitions": []}

    def load(self):
        self.manifest.write_text(json.dumps({"partitions": self.parts}))
        return avb.load_manifest(self.manifest)

    def test_unreachable_child(self):
        self.parts[0]["chain_partitions"] = []
        with self.assertRaisesRegex(avb.BundleError, "unreachable"):
            self.load()

    def test_parent_rollback_location_cannot_be_reused(self):
        self.parts.append(self.part("vbmeta_vendor", "chained"))
        self.parts[0]["chain_partitions"].append({"name": "vbmeta_vendor", "rollback_index_location": 1,
                                                  "public_key": "public.key"})
        with self.assertRaisesRegex(avb.BundleError, "duplicate chain"):
            self.load()

    def test_chained_header_rollback_location_is_zero(self):
        self.parts[1]["rollback_index_location"] = 1
        with self.assertRaisesRegex(avb.BundleError, "must be zero"):
            self.load()

    def test_chained_key_is_required_even_in_development(self):
        self.parts[1]["key"] = None
        self.parts[1]["algorithm"] = "NONE"
        with self.assertRaisesRegex(avb.BundleError, "signing key"):
            self.load()

    def test_only_one_root(self):
        self.parts[1]["role"] = "top-level"
        with self.assertRaisesRegex(avb.BundleError, "exactly one"):
            self.load()

    def test_top_level_flags_only_and_verify_after_all_children_exist(self):
        self.load()
        flags, verifies = {}, []

        def run(command):
            if command[1] == "extract_public_key":
                Path(command[command.index("--output") + 1]).write_bytes(b"public fixture")
            elif command[1] == "make_vbmeta_image":
                path = Path(command[command.index("--output") + 1])
                value = int(command[command.index("--flags") + 1])
                flags[path.name] = value
                raw = bytearray(4096)
                raw[:4] = b"AVB0"
                struct.pack_into(">I", raw, 120, value)
                path.write_bytes(raw)
            else:
                path = Path(command[command.index("--image") + 1])
                self.assertTrue((path.parent / "vbmeta_system.img").is_file())
                self.assertIn("--follow_chain_partitions", command)
                verifies.append(path.name)
        with patch.object(avb, "_run", side_effect=run):
            avb.build(self.manifest, self.tool, self.root / "out", True)
        self.assertEqual(flags, {"vbmeta.img": 2, "vbmeta_system.img": 0})
        self.assertEqual(set(verifies), set(flags))

    def test_key_mismatch_does_not_publish_partial_images(self):
        self.load()

        def run(command):
            Path(command[command.index("--output") + 1]).write_bytes(b"different public key")
        with patch.object(avb, "_run", side_effect=run):
            with self.assertRaisesRegex(avb.BundleError, "differs"):
                avb.build(self.manifest, self.tool, self.root / "out", True)
        self.assertFalse((self.root / "out").exists())


if __name__ == "__main__":
    unittest.main()
