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

import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from native_build import verify_payloads


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "package.zip"
        self.payloads = [b"1.0\n", b"fixture\n", b"filesystem image"]
        self.binary = b"updater binary fixture"
        self.plan = {"version": "1.0", "boards": ["fixture"],
            "updater_binary_sha256": hashlib.sha256(self.binary).hexdigest(),
            "partitions": [{"name": "system", "operation": "write", "stored_bytes": len(self.payloads[2]),
                            "sha256": hashlib.sha256(self.payloads[2]).hexdigest()}]}

    def write(self, corrupt_data=False, corrupt_table=False, file_version=2, high_size=False,
              corrupt_range=False, corrupt_hash=False, omit_hashes=False):
        header = bytearray(180)
        struct.pack_into("<H", header, 0, 1)
        struct.pack_into("<I", header, 8, file_version)
        struct.pack_into("<HH", header, 176, 5, 261)
        for name, payload in zip(["/version_list", "/board_list", "/system"], self.payloads):
            component = bytearray(87)
            component[:len(name)] = name.encode()
            struct.pack_into("<Q" if file_version == 3 else "<I", component, 47,
                             len(payload) + (1 if corrupt_table else 0) + (2 ** 32 if high_size else 0))
            component[55:87] = hashlib.sha256(payload).digest()
            header += component
        header += bytes(16)
        if not omit_hashes:
            header += struct.pack("<HI3HI", 6, 10, 1, 32, 3, 4 * 1024 * 1024)
            table = bytearray()
            for name, payload in zip(["/version_list", "/board_list", "/system"], self.payloads):
                table += struct.pack("<32sH" + ("Q" if file_version == 3 else "I"), name.encode(), 1, len(payload))
                table += struct.pack("<2Q" if file_version == 3 else "<2I",
                                     1 if corrupt_range else 0, len(payload) - 1)
                table += bytes(32) if corrupt_hash else hashlib.sha256(payload).digest()
            header += struct.pack("<HI", 7, len(table)) + table
        header += struct.pack("<HI", 8, 256) + bytes(256)
        payload = b"".join(self.payloads)
        if corrupt_data:
            payload = payload[:-1] + bytes([payload[-1] ^ 1])
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as tools:
            tools.writestr("updater_binary", self.binary)
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("update.bin", header + payload)
            archive.writestr("build_tools.zip", nested.getvalue())

    def test_header_and_payload_match(self):
        self.write()
        self.assertEqual(verify_payloads(self.path, self.plan), "passed")

    def test_changed_payload_is_rejected_even_with_valid_zip_crc(self):
        self.write(corrupt_data=True)
        with self.assertRaisesRegex(ValueError, "block hash differs"):
            verify_payloads(self.path, self.plan)

    def test_wrong_component_size_is_rejected(self):
        self.write(corrupt_table=True)
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            verify_payloads(self.path, self.plan)

    def test_wrong_updater_is_rejected(self):
        self.binary = b"different updater"
        self.write()
        with self.assertRaisesRegex(ValueError, "updater binary differs"):
            verify_payloads(self.path, self.plan)

    def test_v3_header_and_payload_match(self):
        self.plan["package_file_version"] = 3
        self.write(file_version=3)
        self.assertEqual(verify_payloads(self.path, self.plan), "passed")

    def test_v3_high_size_bits_are_checked(self):
        self.plan["package_file_version"] = 3
        self.write(file_version=3, high_size=True)
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            verify_payloads(self.path, self.plan)

    def test_selected_version_must_match_package(self):
        self.plan["package_file_version"] = 3
        self.write()
        with self.assertRaisesRegex(ValueError, "selected version"):
            verify_payloads(self.path, self.plan)

    def test_missing_recovery_hash_table_is_rejected(self):
        self.write(omit_hashes=True)
        with self.assertRaisesRegex(ValueError, "recovery hash header"):
            verify_payloads(self.path, self.plan)

    def test_incorrect_block_range_is_rejected(self):
        self.write(corrupt_range=True)
        with self.assertRaisesRegex(ValueError, "hash range differs"):
            verify_payloads(self.path, self.plan)

    def test_incorrect_block_digest_is_rejected(self):
        self.write(corrupt_hash=True)
        with self.assertRaisesRegex(ValueError, "block hash differs"):
            verify_payloads(self.path, self.plan)


if __name__ == "__main__":
    unittest.main()
