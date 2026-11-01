#!/usr/bin/env python3
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

"""Build native images, then create a signed recovery package after success."""

import argparse
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools/device-packager"))
import package


def recovery_files(path, wanted):
    """Read selected newc members without unpacking or loading the ramdisk."""
    found = {}
    with path.open("rb") as raw:
        compressed = raw.read(2) == b"\x1f\x8b"
        raw.seek(0)
        stream = gzip.GzipFile(fileobj=raw) if compressed else raw
        while True:
            header = stream.read(110)
            if len(header) != 110 or header[:6] not in (b"070701", b"070702"):
                raise ValueError("recovery must contain a complete newc ramdisk")
            size = int(header[54:62], 16)
            name_size = int(header[94:102], 16)
            if not 1 <= name_size <= 4096:
                raise ValueError("invalid recovery member name")
            name = stream.read(name_size)
            if len(name) != name_size or not name.endswith(b"\0"):
                raise ValueError("truncated recovery member name")
            name = name[:-1].decode().removeprefix("./")
            stream.read(-(110 + name_size) % 4)
            if name == "TRAILER!!!":
                break
            if name in wanted:
                if name in found or size > 1024 * 1024:
                    raise ValueError("duplicate or oversized recovery configuration")
                found[name] = stream.read(size)
                if len(found[name]) != size:
                    raise ValueError("truncated recovery configuration")
            else:
                remaining = size
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("truncated recovery member")
                    remaining -= len(block)
            stream.read(-size % 4)
        if set(found) != set(wanted):
            raise ValueError("recovery is missing the selected certificate or partition map")
    return found


def gn_arguments(arguments, certificate, fstab):
    arguments = list(arguments)
    for index, value in enumerate(arguments):
        if value.startswith(("--build-only-", "--disable-package-image", "--disable-post-build")):
            raise ValueError("recovery packaging requires a complete image build and post-build checks")
        if value == "--ninja-args" or value.startswith("--ninja-args="):
            options = value.split("=", 1)[1:] or arguments[index + 1:index + 2]
            if any("-n" in option.split() or "--dry-run" in option.split() for option in options):
                raise ValueError("recovery packaging does not accept a Ninja dry run")
        if value == "--build-target" or value.startswith("--build-target="):
            stop = index + 1
            while stop < len(arguments) and not arguments[stop].startswith("--"):
                stop += 1
            targets = value.split("=", 1)[1:] or arguments[index + 1:stop]
            if targets not in (["images"], ["make_all"]):
                raise ValueError("select the complete images or make_all target")
    selection = ("opendroid_recovery_certificate=" + json.dumps(str(certificate)) +
                 " opendroid_recovery_fstab=" + json.dumps(str(fstab)))
    for value in arguments:
        if "opendroid_recovery_certificate=" in value or "opendroid_recovery_fstab=" in value:
            raise ValueError("recovery inputs are selected by the vendor build entry")
    positions = [i for i, value in enumerate(arguments) if value == "--gn-args" or value.startswith("--gn-args=")]
    if len(positions) > 1:
        raise ValueError("combine GN arguments into one --gn-args option")
    if positions:
        index = positions[0]
        if arguments[index].startswith("--gn-args="):
            arguments[index] += " " + selection
        else:
            stop = index + 1
            while stop < len(arguments) and not arguments[stop].startswith("--"):
                stop += 1
            arguments[index + 1:stop] = [" ".join(arguments[index + 1:stop] + [selection])]
    else:
        arguments += ["--gn-args", selection]
    return arguments


def run(args, native_args):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    source = args.source_root.resolve()
    output = args.out_dir.resolve()
    key_path = args.signing_key.resolve()
    certificate = args.certificate.resolve()
    fstab = args.recovery_fstab.resolve()
    if not args.manifest.is_file():
        raise ValueError("select a product partition manifest before building")
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(certificate.read_bytes())
    if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048 or
            key.public_key().public_numbers() != cert.public_key().public_numbers()):
        raise ValueError("select a matching RSA-2048 package key and certificate")
    if key_path.is_relative_to(source):
        raise ValueError("keep the private package key outside the source checkout")
    fstab.read_bytes()
    # The native command includes post-build dependency checks. Packaging only
    # starts after its successful exit; a compiler or post-build failure stops here.
    command = [str(source / "build.sh"), *gn_arguments(native_args, certificate, fstab)]
    subprocess.run(command, cwd=source, check=True)
    recovered = recovery_files(output / "packages/phone/images/updater.img",
                               {"etc/certificate/signing_cert.crt", "etc/fstab.updater"})
    if (recovered["etc/certificate/signing_cert.crt"] != certificate.read_bytes() or
            recovered["etc/fstab.updater"] != fstab.read_bytes()):
        raise ValueError("built recovery trust or partition map differs from the selected inputs")
    destination = output / "packages/phone/update"
    destination.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".package-", dir=destination))
    try:
        package.prepare(args.manifest.resolve(), work / "prepared",
                        output / "updater/updater/updater_binary", args.package_version)
        prepared = work / "prepared"
        if (prepared / "fstab.updater").read_bytes() != fstab.read_bytes():
            raise ValueError("package mappings differ from the built recovery partition map")
        subprocess.run([sys.executable, "-B", str(ROOT / "tools/device-packager/native_build.py"),
                        "--packaging-tools", str(source / "base/update/packaging_tools"),
                        "--target", str(prepared / "target"), "--output", str(work / "package"),
                        "--signing-key", str(key_path), "--certificate", str(certificate)], check=True,
                       cwd=work)
        os.replace(work / "package/updater_sd.zip", destination / "updater_sd.zip")
        os.replace(work / "package/verification.json", destination / "verification.json")
    except Exception:
        print("Package inputs and logs retained at " + str(work), file=sys.stderr)
        raise
    else:
        import shutil
        shutil.rmtree(work)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--recovery-fstab", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, default=os.environ.get("OPENDROID_PACKAGE_KEY"))
    parser.add_argument("--certificate", type=Path, default=os.environ.get("OPENDROID_PACKAGE_CERT"))
    parser.add_argument("--package-version", type=int, choices=(2, 3), default=3)
    parser.add_argument("native_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.signing_key is None or args.certificate is None:
        parser.error("select --signing-key and --certificate, or OPENDROID_PACKAGE_KEY/CERT")
    forwarded = args.native_args[1:] if args.native_args[:1] == ["--"] else args.native_args
    if not forwarded:
        parser.error("pass native build arguments after --")
    return run(args, forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
