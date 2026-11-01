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

"""Prepare explicit partition mappings for the native OpenHarmony ZIP packager."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET


TARGETS = {"system", "system_ext", "vendor", "product", "odm", "vendor_dlkm",
           "system_dlkm", "sys_prod", "chip_prod", "eng_system", "eng_chipset",
           "boot", "init_boot", "vendor_boot", "recovery", "dtbo", "updater",
           "vbmeta", "vbmeta_system", "vbmeta_vendor"}
TOKEN = re.compile(r"[A-Za-z0-9_.+-]+\Z")
BLOCK = re.compile(r"/dev/block/(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\Z")
SPARSE_MAGIC = 0xED26FF3A


class PackageError(ValueError):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PackageError(f"{label} requires exactly {sorted(fields)}")


def positive(value, label):
    if type(value) is not int or not 0 < value < 2 ** 63 or value % 4096:
        raise PackageError(f"{label} must be a positive 4096-aligned byte count")
    return value


def file_path(base, value):
    if not isinstance(value, str) or not value:
        raise PackageError("image paths must be nonempty strings")
    path = (base / value).absolute()
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise PackageError("image inputs must be regular files without symlinks")
    return path


def image_size(path):
    """Validate every sparse chunk without expanding or copying its data."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(28)
        if len(head) < 4 or struct.unpack_from("<I", head)[0] != SPARSE_MAGIC:
            if not size:
                raise PackageError("zero-length images are not valid empty filesystems")
            return {"format": "raw", "expanded_bytes": size, "stored_bytes": size}
        if len(head) != 28:
            raise PackageError("truncated sparse image header")
        _, major, minor, file_hdr, chunk_hdr, block, blocks, chunks, checksum = struct.unpack("<I4H4I", head)
        if major != 1 or file_hdr < 28 or chunk_hdr < 12 or not block or block % 4:
            raise PackageError("unsupported sparse image header")
        if file_hdr > size or chunks > (size - file_hdr) // chunk_hdr:
            raise PackageError("sparse chunk table exceeds the file")
        stream.seek(file_hdr)
        expanded_blocks = 0
        for _ in range(chunks):
            chunk = stream.read(chunk_hdr)
            if len(chunk) != chunk_hdr:
                raise PackageError("truncated sparse chunk header")
            kind, reserved, count, total = struct.unpack_from("<2H2I", chunk)
            payload = total - chunk_hdr
            if kind == 0xCAC1:
                expected = count * block
            elif kind == 0xCAC2:
                expected = 4
            elif kind == 0xCAC3:
                expected = 0
            elif kind == 0xCAC4 and count == 0:
                expected = 4
            else:
                raise PackageError("unknown sparse chunk type or invalid CRC chunk")
            if payload != expected or stream.tell() + payload > size:
                raise PackageError("invalid or truncated sparse chunk payload")
            expanded_blocks += count
            stream.seek(payload, 1)
        if expanded_blocks != blocks or stream.tell() != size:
            raise PackageError("sparse image block count or trailing bytes differ")
        return {"format": "android-sparse", "expanded_bytes": blocks * block, "stored_bytes": size}


def validate(manifest):
    data = json.loads(manifest.read_text(), object_pairs_hook=unique)
    exact(data, {"format_version", "boards", "product_id", "version", "slot",
                 "logical_backend", "groups", "partitions"}, "package plan")
    if type(data["format_version"]) is not int or data["format_version"] != 1:
        raise PackageError("unsupported package plan version")
    if (not isinstance(data["boards"], list) or not data["boards"]
            or any(not isinstance(v, str) or not TOKEN.fullmatch(v) for v in data["boards"])
            or len(set(data["boards"])) != len(data["boards"])):
        raise PackageError("boards must be unique nonempty identifiers")
    for key in ("product_id", "version"):
        if not isinstance(data[key], str) or not TOKEN.fullmatch(data[key]) or len(data[key].encode()) > 63:
            raise PackageError(f"{key} must be an identifier of at most 63 bytes")
    if data["slot"] not in ("none", "a", "b"):
        raise PackageError("slot must be none, a or b")
    if data["logical_backend"] not in ("none", "existing-mappers"):
        raise PackageError("logical_backend must be none or existing-mappers; super repartitioning is not implemented")
    if not isinstance(data["groups"], dict) or any(not TOKEN.fullmatch(name) for name in data["groups"]):
        raise PackageError("groups must map identifiers to byte budgets")
    totals = {name: 0 for name in data["groups"]}
    for name, size in data["groups"].items():
        positive(size, f"group {name}")
    if not isinstance(data["partitions"], list) or not data["partitions"]:
        raise PackageError("partitions must be a nonempty list")
    seen, blocks, entries = set(), set(), []
    for part in data["partitions"]:
        exact(part, {"name", "operation", "kind", "group", "capacity_bytes", "block_device", "image"}, "partition")
        name = part["name"]
        if not isinstance(name, str) or name not in TARGETS or name in seen:
            raise PackageError("partition must have a unique OS/boot target name; firmware and userdata are excluded")
        seen.add(name)
        if part["operation"] not in ("write", "preserve"):
            raise PackageError("only write and preserve operations are supported")
        capacity = positive(part["capacity_bytes"], name)
        if part["kind"] not in ("physical", "logical"):
            raise PackageError("kind must be physical or logical")
        if part["kind"] == "logical":
            if data["logical_backend"] != "existing-mappers" or part["group"] not in totals:
                raise PackageError("logical partitions require an explicit group and existing-mappers backend")
            totals[part["group"]] += capacity
        elif part["group"] is not None:
            raise PackageError("physical partitions cannot belong to a logical group")
        block = part["block_device"]
        if not isinstance(block, str) or not BLOCK.fullmatch(block) or any(p in (".", "..") for p in block.split("/")):
            raise PackageError("block_device must be an explicit safe path below /dev/block")
        if block in blocks:
            raise PackageError("two entries target the same block device")
        blocks.add(block)
        if data["slot"] != "none" and not block.endswith("_" + data["slot"]):
            raise PackageError("block-device suffix differs from the selected slot")
        if part["kind"] == "logical" and not block.startswith("/dev/block/mapper/"):
            raise PackageError("existing logical targets must use explicit /dev/block/mapper paths")
        entry = dict(part)
        if part["operation"] == "preserve":
            if part["image"] is not None:
                raise PackageError("preserved partitions cannot specify an image")
        else:
            path = file_path(manifest.parent, part["image"])
            before = path.stat()
            entry.update(image_size(path))
            if entry["expanded_bytes"] > capacity:
                raise PackageError(f"{name} expanded image is {entry['expanded_bytes']} bytes; budget is {capacity}")
            with path.open("rb") as stream:
                entry["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
            after = path.stat()
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise PackageError("image changed during validation")
            entry["source"] = str(path)
            if name in ("boot", "init_boot", "vendor_boot"):
                with path.open("rb") as stream:
                    header = stream.read(44)
                magic = b"VNDRBOOT" if name == "vendor_boot" else b"ANDROID!"
                offset = 8 if name == "vendor_boot" else 40
                if header[:8] != magic or len(header) < offset + 4:
                    raise PackageError(f"{name} lacks its native Android boot header")
                entry["boot_header_version"] = struct.unpack_from("<I", header, offset)[0]
                if entry["boot_header_version"] not in (3, 4):
                    raise PackageError("this packager supports boot headers v3/v4 only")
            if name.startswith("vbmeta"):
                with path.open("rb") as stream:
                    header = stream.read(256)
                if len(header) != 256 or header[:4] != b"AVB0":
                    raise PackageError("vbmeta must contain a complete AVB0 header")
                entry["avb_flags"] = struct.unpack_from(">I", header, 120)[0]
                entry["rollback_index_location"] = struct.unpack_from(">I", header, 124)[0]
                if name != "vbmeta" and (entry["avb_flags"] or entry["rollback_index_location"]):
                    raise PackageError("chained vbmeta flags and header rollback location must be zero")
        entries.append(entry)
    for name, size in totals.items():
        if size > data["groups"][name]:
            raise PackageError(f"logical group {name} exceeds its byte budget")
    return {"format_version": 1, "boards": data["boards"], "product_id": data["product_id"],
            "version": data["version"], "slot": data["slot"], "logical_backend": data["logical_backend"],
            "groups": data["groups"], "group_allocated_bytes": totals, "partitions": entries,
            "validation": {"scope": "Static packaging and declared capacity checks",
                "actual_device_layout_and_group_completeness": "caller must verify against measured metadata",
                "logical_mapping_creation": "not implemented; selected mappings must already exist in recovery",
                "slot_management_and_boot_chain": "requires board recovery integration",
                "image_contents_signature_trust_and_device_boot": "not validated by this plan"}}


def prepare(manifest, output, updater_binary, file_version=2):
    if output.exists() or output.is_symlink():
        raise PackageError("output already exists")
    report = validate(manifest)
    if file_version not in (2, 3):
        raise PackageError("native package file version must be 2 or 3")
    report["package_file_version"] = file_version
    binary = file_path(Path.cwd(), str(updater_binary))
    with binary.open("rb") as stream:
        header = stream.read(64)
    if (header[:6] != b"\x7fELF\x02\x01" or len(header) < 64
            or struct.unpack_from("<H", header, 16)[0] not in (2, 3)
            or struct.unpack_from("<H", header, 18)[0] != 183):
        raise PackageError("updater_binary must be the ARM64 executable built for recovery")
    with binary.open("rb") as stream:
        report["updater_binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    writes = [p for p in report["partitions"] if p["operation"] == "write"]
    if not writes:
        raise PackageError("package has no images to write")
    # Legacy encoders use signed 32-bit sizes. Version 3 requires the matching
    # native 64-bit component and hash-table encoder.
    if file_version == 2 and any(p["stored_bytes"] > 2 ** 31 - 1 for p in writes):
        raise PackageError("native package encoder needs large-component support for images above 2 GiB")
    if any(p["format"] == "android-sparse" for p in writes):
        raise PackageError("native full-image preparation currently requires raw images")
    output.mkdir()
    target = output / "target"
    target.mkdir()
    config = target / "updater_config"
    config.mkdir()
    os.symlink(binary, target / "updater_binary")
    package = ET.Element("package")
    head = ET.SubElement(package, "head")
    now = datetime.now(timezone.utc)
    ET.SubElement(head, "info", {"fileVersion": str(file_version), "prdID": report["product_id"],
        "softVersion": report["version"], "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S")}).text = "head info"
    group = ET.SubElement(package, "group")
    fstab = []
    for index, entry in enumerate(writes, 1):
        name = entry["name"]
        os.symlink(entry["source"], target / (name + ".img"))
        ET.SubElement(group, "component", {"compAddr": name, "compId": str(index),
            "resType": "5", "compType": "0", "compVer": "1"}).text = "./" + name + ".img"
        fstab.append(f"{entry['block_device']} /{name} none defaults defaults")
    ET.indent(package)
    ET.ElementTree(package).write(config / "updater_specified_config.xml", encoding="utf-8", xml_declaration=True)
    (config / "BOARD.list").write_text("\n".join(report["boards"]) + "\n")
    (config / "VERSION.mbn").write_text(report["version"] + "\n")
    (output / "fstab.updater").write_text("\n".join(fstab) + "\n")
    (output / "plan.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("inspect", "prepare", "build"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--updater-binary", type=Path)
    parser.add_argument("--packaging-tools", type=Path)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--package-version", type=int, choices=(2, 3), default=2)
    args = parser.parse_args()
    try:
        if args.command in ("prepare", "build"):
            if args.updater_binary is None:
                raise PackageError("prepare requires --updater-binary")
            if args.command == "build":
                if None in (args.packaging_tools, args.signing_key, args.certificate):
                    raise PackageError("build requires --packaging-tools, --signing-key and --certificate")
            prepare(args.manifest.absolute(), args.output.absolute(), args.updater_binary, args.package_version)
            if args.command == "build":
                output = args.output.absolute()
                (output / "tmp").mkdir()
                environment = dict(os.environ, TMPDIR=str(output / "tmp"), PYTHONDONTWRITEBYTECODE="1")
                command = [args.python, "-B", str(Path(__file__).with_name("native_build.py")),
                           "--packaging-tools", str(args.packaging_tools.absolute()),
                           "--certificate", str(args.certificate.absolute()),
                           "--signing-key", str(args.signing_key.absolute()),
                           "--target", str(output / "target"), "--output", str(output / "package")]
                with (output / "build.log").open("x") as log:
                    result = subprocess.run(command, cwd=output, env=environment,
                                            stdout=log, stderr=subprocess.STDOUT, check=False)
                if result.returncode:
                    raise PackageError("native package build/verification failed; see build.log")
        else:
            report = validate(args.manifest.absolute())
            with args.output.open("x") as stream:
                json.dump(report, stream, indent=2)
                stream.write("\n")
    except (PackageError, OSError, UnicodeError, json.JSONDecodeError, struct.error) as exc:
        parser.exit(2, f"package: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
