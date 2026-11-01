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

import gzip
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build
from generate_keys import generate


def ramdisk(entries):
    result = bytearray()
    for name, data in [*entries, ("TRAILER!!!", b"")]:
        name = name.encode() + b"\0"
        fields = [0, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        result += b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name
        result += bytes(-len(result) % 4) + data
        result += bytes(-len(data) % 4)
    return gzip.compress(result)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        generate(self.root / "keys", "Development test")
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "out"
        self.fstab = self.root / "fstab.updater"
        self.fstab.write_text("/dev/block/mapper/system_a /system none defaults defaults\n")
        self.manifest = self.root / "installation.json"
        self.manifest.write_text("{}")
        self.args = SimpleNamespace(source_root=self.source, out_dir=self.output,
            signing_key=self.root / "keys/package-key.pem", certificate=self.root / "keys/package-cert.pem",
            recovery_fstab=self.fstab, manifest=self.manifest, package_version=3)

    def recovery(self, certificate=None):
        path = self.output / "packages/phone/images/updater.img"
        path.parent.mkdir(parents=True)
        path.write_bytes(ramdisk([("etc/certificate/signing_cert.crt", certificate or self.args.certificate.read_bytes()),
                                  ("etc/fstab.updater", self.fstab.read_bytes())]))
        return path

    def test_keys_are_owner_only_and_never_overwritten(self):
        from cryptography import x509
        certificate = x509.load_pem_x509_certificate(self.args.certificate.read_bytes())
        self.assertTrue(certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
        self.assertEqual(stat.S_IMODE(self.args.signing_key.stat().st_mode), 0o600)
        original = self.args.signing_key.read_bytes()
        with self.assertRaises(FileExistsError):
            generate(self.root / "keys", "Another identity")
        self.assertEqual(self.args.signing_key.read_bytes(), original)

    def test_image_failure_does_not_start_packaging(self):
        with patch.object(build.subprocess, "run", side_effect=subprocess.CalledProcessError(7, "build")), \
                patch.object(build.package, "prepare") as prepare:
            with self.assertRaises(subprocess.CalledProcessError):
                build.run(self.args, ["--product-name", "example"])
            prepare.assert_not_called()
        self.assertFalse((self.output / "packages/phone/update").exists())

    def test_wrong_built_recovery_certificate_stops_packaging(self):
        self.recovery(b"wrong certificate")
        with patch.object(build.subprocess, "run"), patch.object(build.package, "prepare") as prepare:
            with self.assertRaisesRegex(ValueError, "built recovery trust"):
                build.run(self.args, ["--product-name", "example"])
            prepare.assert_not_called()

    def test_success_runs_package_after_native_build_and_replaces_one_zip(self):
        self.recovery()
        events = []
        def prepare(manifest, output, binary, version):
            events.append("prepare")
            output.mkdir()
            (output / "fstab.updater").write_bytes(self.fstab.read_bytes())
        def execute(command, **kwargs):
            if command[0] == str(self.source / "build.sh"):
                events.append("native")
            else:
                events.append("package")
                output = Path(command[command.index("--output") + 1])
                output.mkdir()
                (output / "updater_sd.zip").write_bytes(b"verified package")
                (output / "verification.json").write_text("{}")
        with patch.object(build.subprocess, "run", side_effect=execute), \
                patch.object(build.package, "prepare", side_effect=prepare):
            self.assertEqual(build.run(self.args, ["--product-name", "example"]), 0)
        self.assertEqual(events, ["native", "prepare", "package"])
        final = self.output / "packages/phone/update"
        self.assertEqual((final / "updater_sd.zip").read_bytes(), b"verified package")
        self.assertFalse(list(final.glob(".package-*")))

    def test_incomplete_or_dry_builds_are_rejected(self):
        for options in (["--build-target", "system"], ["--build-target", "images", "system"],
                        ["--build-only-gn"], ["--ninja-args=-n"], ["--ninja-args", "-n"]):
            with self.subTest(options=options), self.assertRaises(ValueError):
                build.gn_arguments(options, self.args.certificate, self.fstab)

    def test_existing_gn_options_preserved_without_exposing_private_key(self):
        options = build.gn_arguments(["--gn-args", "feature=true", "--build-target", "images"],
                                     self.args.certificate, self.fstab)
        self.assertIn("feature=true", options[1])
        self.assertIn(str(self.args.certificate), options[1])
        self.assertNotIn(str(self.args.signing_key), " ".join(options))

    def test_truncated_ramdisk_is_rejected(self):
        path = self.root / "broken.img"
        path.write_bytes(ramdisk([("etc/test", b"test")])[:-10])
        with self.assertRaises((ValueError, EOFError)):
            build.recovery_files(path, {"etc/test"})


if __name__ == "__main__":
    unittest.main()
