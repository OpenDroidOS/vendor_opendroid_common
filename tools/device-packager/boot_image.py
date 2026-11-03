#!/usr/bin/env python3
# Copyright 2026 OpenDroidOS
# SPDX-License-Identifier: Apache-2.0

"""Replace a selected v3/v4 generic ramdisk, producing an unsigned boot container.

The Android boot header format is specified by AOSP bootimg.h. Kernel bytes,
OS version and command line come from the selected template. Signing and the
board's AVB graph remain separate explicit inputs to avb_bundle.py.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from stage_kernel import StageError, _absolute, _directory, _hash_file, _open_regular

PAGE_SIZE = 4096
HEADER_SIZE = {3: 1580, 4: 1584}


def aligned(size):
    return (size + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE


def template_header(path):
    with _open_regular(path) as stream:
        header = stream.read(PAGE_SIZE)
        size = os.fstat(stream.fileno()).st_size
    if len(header) != PAGE_SIZE or header[:8] != b"ANDROID!":
        raise StageError("Expected a complete Android generic boot header")
    kernel, ramdisk, os_version, header_size = struct.unpack_from("<4I", header, 8)
    version = struct.unpack_from("<I", header, 40)[0]
    if version not in HEADER_SIZE or header_size != HEADER_SIZE[version]:
        raise StageError("Only generic boot header versions 3 and 4 are supported")
    if any(header[24:40]):
        raise StageError("Reserved boot header fields must be zero")
    if version == 4 and struct.unpack_from("<I", header, 1580)[0] != 0:
        raise StageError("Template has a v4 boot signature; regenerate it with the developer's signing tool")
    if PAGE_SIZE + aligned(kernel) + aligned(ramdisk) > size:
        raise StageError("Template payload sizes exceed the selected file")
    return bytearray(header[:header_size]), {
        "header_version": version,
        "kernel_bytes": kernel,
        "previous_ramdisk_bytes": ramdisk,
        "os_version_field": os_version,
    }


def copy_region(source, output, offset, size):
    digest = hashlib.sha256()
    with _open_regular(source) as stream:
        stream.seek(offset)
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                raise StageError("Input became shorter while copying its payload")
            output.write(block)
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def build(template, template_sha256, ramdisk, ramdisk_sha256, partition_size, output):
    if type(partition_size) is not int or partition_size <= 0 or partition_size % PAGE_SIZE:
        raise StageError("Select a positive, page-aligned partition capacity in bytes")
    template, ramdisk, output = map(_absolute, (template, ramdisk, output))
    if output in (template, ramdisk):
        raise StageError("Output must not replace an input")
    for path, expected in ((template, template_sha256), (ramdisk, ramdisk_sha256)):
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise StageError("Each selected input requires a lowercase SHA256 digest")
        if _hash_file(path)[0] != expected:
            raise StageError(f"SHA256 mismatch for {path.name}")
    header, info = template_header(template)
    ramdisk_size = _hash_file(ramdisk)[1]
    if not 0 < ramdisk_size <= 0xffffffff:
        raise StageError("Ramdisk must be nonempty and fit the header's 32-bit size field")
    size = PAGE_SIZE + aligned(info["kernel_bytes"]) + aligned(ramdisk_size)
    if size > partition_size:
        raise StageError("New container exceeds the selected partition capacity")
    struct.pack_into("<I", header, 12, ramdisk_size)
    _directory(output.parent, create=True)
    fd, temporary = tempfile.mkstemp(prefix=".boot-image-", dir=output.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(header)
            stream.write(bytes(PAGE_SIZE - len(header)))
            kernel_hash = copy_region(template, stream, PAGE_SIZE, info["kernel_bytes"])
            stream.write(bytes(aligned(info["kernel_bytes"]) - info["kernel_bytes"]))
            copied_hash = copy_region(ramdisk, stream, 0, ramdisk_size)
            if copied_hash != ramdisk_sha256:
                raise StageError("Selected ramdisk changed while constructing the image")
            stream.write(bytes(aligned(ramdisk_size) - ramdisk_size))
            stream.flush()
            os.fsync(stream.fileno())
        if _hash_file(template)[0] != template_sha256 or _hash_file(ramdisk)[0] != ramdisk_sha256:
            raise StageError("A selected input changed during construction")
        digest, actual_size = _hash_file(temporary)
        if actual_size != size:
            raise StageError("Constructed container has an unexpected size")
        os.link(temporary, output, follow_symlinks=False)
    finally:
        temporary.unlink()
    return dict(info, format_version=1, template_sha256=template_sha256,
                ramdisk_sha256=ramdisk_sha256, kernel_sha256=kernel_hash,
                ramdisk_bytes=ramdisk_size, partition_capacity_bytes=partition_size,
                image_bytes=size, image_sha256=digest, signed=False,
                limits=["The template's kernel and header fields were preserved; bootloader/DT compatibility is not established.",
                        "No old v4 signature or AVB footer was reused. Apply the selected developer keys and AVB graph separately.",
                        "No image was flashed, loaded or booted."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--template-sha256", required=True)
    parser.add_argument("--ramdisk", required=True, type=Path)
    parser.add_argument("--ramdisk-sha256", required=True)
    parser.add_argument("--partition-size", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = build(args.template, args.template_sha256, args.ramdisk,
                       args.ramdisk_sha256, args.partition_size, args.output)
    except (StageError, OSError) as error:
        print(f"boot_image: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
