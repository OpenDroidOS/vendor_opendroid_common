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

"""Build and validate explicitly selected Android AVB vbmeta images."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


ALGORITHMS = {"NONE", "SHA256_RSA2048", "SHA256_RSA4096", "SHA256_RSA8192",
              "SHA512_RSA2048", "SHA512_RSA4096", "SHA512_RSA8192"}
AVB_FLAGS_OFFSET = 120
VERIFICATION_DISABLED = 2
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]*\Z")


class BundleError(ValueError):
    pass


def _int(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise BundleError(f"{label} must be an integer >= {minimum}")
    return value


def load_manifest(path):
    path = Path(path).resolve(strict=True)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"cannot read manifest: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"partitions"}:
        raise BundleError("manifest must contain only a partitions array")
    parts = doc["partitions"]
    if not isinstance(parts, list) or not parts:
        raise BundleError("partitions must be a non-empty array")
    seen_names, seen_outputs = set(), set()
    base = path.parent
    normalized = []
    for index, item in enumerate(parts):
        label = f"partitions[{index}]"
        required = {"name", "role", "output", "partition_size", "key", "algorithm",
                    "rollback_index", "rollback_index_location",
                    "descriptors_from", "chain_partitions"}
        if not isinstance(item, dict) or set(item) != required:
            raise BundleError(f"{label} must contain exactly {sorted(required)}")
        name, output = item["name"], item["output"]
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise BundleError(f"{label}.name must be a simple partition name")
        if name in seen_names:
            raise BundleError(f"duplicate partition name: {name}")
        seen_names.add(name)
        if output != name + ".img":
            raise BundleError(f"{label}.output must be name.img for chain verification")
        if item["role"] not in ("top-level", "chained"):
            raise BundleError(f"{label}.role must be top-level or chained")
        if output in seen_outputs:
            raise BundleError(f"duplicate output filename: {output}")
        seen_outputs.add(output)
        size = _int(item["partition_size"], f"{label}.partition_size", 1)
        rollback = _int(item["rollback_index"], f"{label}.rollback_index")
        location = _int(item["rollback_index_location"], f"{label}.rollback_index_location")
        if location > 31:
            raise BundleError(f"{label}.rollback_index_location must be <= 31")
        if item["role"] == "chained" and location != 0:
            raise BundleError("chained header rollback_index_location must be zero")
        algorithm = item["algorithm"]
        if algorithm not in ALGORITHMS:
            raise BundleError(f"{label}.algorithm must be one of {sorted(ALGORITHMS)}")

        def input_file(value, field):
            if not isinstance(value, str) or not value:
                raise BundleError(f"{label}.{field} paths must be non-empty strings")
            candidate = (base / value).resolve(strict=True)
            if not candidate.is_file():
                raise BundleError(f"{label}.{field} is not a file")
            return candidate

        if algorithm == "NONE":
            if item["key"] is not None:
                raise BundleError(f"{label}.key must be null when algorithm is NONE")
            key = None
        else:
            key = input_file(item["key"], "key")
        descriptors = item["descriptors_from"]
        chains = item["chain_partitions"]
        if not isinstance(descriptors, list) or not isinstance(chains, list):
            raise BundleError(f"{label} descriptors_from and chain_partitions must be arrays")
        descriptor_files = []
        descriptor_names = set()
        for descriptor_index, descriptor in enumerate(descriptors):
            dlabel = f"{label}.descriptors_from[{descriptor_index}]"
            if not isinstance(descriptor, dict) or set(descriptor) != {"image", "partition_name"}:
                raise BundleError(f"{dlabel} must contain image and partition_name")
            dname = descriptor["partition_name"]
            if not isinstance(dname, str) or not NAME.fullmatch(dname):
                raise BundleError(f"{dlabel}.partition_name must be a simple name")
            if dname in descriptor_names or dname in seen_names:
                raise BundleError(f"duplicate descriptor partition name: {dname}")
            descriptor_names.add(dname)
            descriptor_files.append((input_file(descriptor["image"], "descriptors_from"), dname))
        chain_args = []
        chain_names = set()
        for chain_index, chain in enumerate(chains):
            clabel = f"{label}.chain_partitions[{chain_index}]"
            if not isinstance(chain, dict) or set(chain) != {"name", "rollback_index_location", "public_key"}:
                raise BundleError(f"{clabel} must contain name, rollback_index_location, public_key")
            cname = chain["name"]
            if not isinstance(cname, str) or not NAME.fullmatch(cname):
                raise BundleError(f"{clabel}.name must be a simple partition name")
            if cname in chain_names:
                raise BundleError(f"duplicate chain partition: {cname}")
            chain_names.add(cname)
            cloc = _int(chain["rollback_index_location"], f"{clabel}.rollback_index_location", 1)
            if cloc > 31:
                raise BundleError(f"{clabel}.rollback_index_location must be <= 31")
            chain_args.append((cname, cloc, input_file(chain["public_key"], "chain public_key")))
        normalized.append({"name": name, "role": item["role"], "output": output, "size": size,
                           "key": key, "algorithm": algorithm, "rollback": rollback,
                           "location": location, "descriptors": descriptor_files,
                           "chains": chain_args})
    validate_graph(normalized)
    return normalized


def validate_graph(parts):
    by_name = {part["name"]: part for part in parts}
    roots = [part for part in parts if part["role"] == "top-level"]
    if len(roots) != 1:
        raise BundleError("exactly one top-level vbmeta image is required")
    parents, locations = {}, {roots[0]["location"]}
    for part in parts:
        for name, location, key in part["chains"]:
            if name not in by_name or by_name[name]["role"] != "chained":
                raise BundleError("chain must reference a selected chained image")
            if name in parents or location in locations:
                raise BundleError("duplicate chain parent or rollback-index location")
            if by_name[name]["key"] is None:
                raise BundleError("chained images require a signing key")
            parents[name] = part["name"]
            locations.add(location)
        for _, name in part["descriptors"]:
            if name in by_name:
                raise BundleError("payload descriptor collides with a vbmeta partition")
    reachable, visiting = set(), set()

    def visit(name):
        if name in visiting:
            raise BundleError("AVB chain cycle")
        if name in reachable:
            return
        visiting.add(name)
        for child, _, _ in by_name[name]["chains"]:
            visit(child)
        visiting.remove(name)
        reachable.add(name)
    visit(roots[0]["name"])
    if reachable != set(by_name):
        raise BundleError("unreachable chained vbmeta image")


def _header_flags(path):
    with open(path, "rb") as image:
        header = image.read(AVB_FLAGS_OFFSET + 4)
    if len(header) != AVB_FLAGS_OFFSET + 4 or header[:4] != b"AVB0":
        raise BundleError(f"{path.name} does not contain an AVB0 header")
    return struct.unpack_from(">I", header, AVB_FLAGS_OFFSET)[0]


def _run(argv):
    try:
        subprocess.run(argv, check=True, shell=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as exc:
        # Avoid echoing argv: it contains caller paths, including signing-key paths.
        raise BundleError(f"AVB tool command failed ({argv[1]})") from exc


def build(manifest, avbtool, output_dir, disable_verification=False):
    partitions = load_manifest(manifest)
    if any(part["algorithm"] == "NONE" for part in partitions) and not disable_verification:
        raise BundleError("algorithm NONE is allowed only with --disable-verification")
    tool = Path(avbtool).resolve(strict=True)
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise BundleError("avbtool must name an executable file")
    destination = Path(output_dir).absolute()
    if destination.exists() or destination.is_symlink():
        raise BundleError("output directory already exists; refusing to overwrite it")
    parent = destination.parent
    if not parent.is_dir():
        raise BundleError("output parent directory must already exist")
    staging = Path(tempfile.mkdtemp(prefix=".avb-stage-", dir=parent))
    try:
        by_name = {part["name"]: part for part in partitions}
        # Verify each parent's selected public key against the actual child's
        # signing key before creating any vbmeta output.
        for part in partitions:
            for name, _, public_key in part["chains"]:
                extracted = staging / "child.avbpubkey"
                _run([str(tool), "extract_public_key", "--key", str(by_name[name]["key"]),
                      "--output", str(extracted)])
                if extracted.read_bytes() != public_key.read_bytes():
                    raise BundleError("chain public key differs from the child's signing key")
                extracted.unlink()
        for part in partitions:
            expected_flags = VERIFICATION_DISABLED if disable_verification and part["role"] == "top-level" else 0
            output = staging / part["output"]
            command = [str(tool), "make_vbmeta_image", "--output", str(output),
                       "--algorithm", part["algorithm"],
                       "--rollback_index", str(part["rollback"]),
                       "--rollback_index_location", str(part["location"]),
                       "--flags", str(expected_flags), "--padding_size", str(part["size"])]
            if part["key"] is not None:
                command.extend(["--key", str(part["key"])])
            for descriptor, partition_name in part["descriptors"]:
                command.extend(["--include_descriptors_from_image", str(descriptor)])
                staged_image = staging / f"{partition_name}{descriptor.suffix}"
                if staged_image.exists():
                    raise BundleError(f"descriptor validation image collision: {partition_name}")
                os.symlink(descriptor, staged_image)
            for name, location, public_key in part["chains"]:
                command.extend(["--chain_partition", f"{name}:{location}:{public_key}"])
            _run(command)
            if not output.is_file() or output.stat().st_size != part["size"]:
                raise BundleError(f"{part['name']} output does not match its partition_size budget")
            if _header_flags(output) != expected_flags:
                raise BundleError(f"{part['name']} header flags differ from the requested mode")
            for descriptor, partition_name in part["descriptors"]:
                (staging / f"{partition_name}{descriptor.suffix}").unlink()
        # Every child image must exist before following the complete graph.
        # Keep descriptor inputs available for avbtool's payload verification.
        descriptor_links = set()
        for part in partitions:
            for descriptor, name in part["descriptors"]:
                link = staging / (name + ".img")
                if link.exists() and (not link.is_symlink() or link.resolve() != descriptor):
                    raise BundleError("conflicting descriptor validation image")
                if not link.exists():
                    os.symlink(descriptor, link)
                descriptor_links.add(link)
        for part in partitions:
            verify = [str(tool), "verify_image", "--image", str(staging / part["output"])]
            if part["key"] is not None:
                verify += ["--key", str(part["key"])]
            for name, location, public_key in part["chains"]:
                verify += ["--expected_chain_partition", f"{name}:{location}:{public_key}"]
            verify += ["--follow_chain_partitions"]
            _run(verify)
        for link in descriptor_links:
            link.unlink()
        os.rename(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--avbtool", required=True, help="explicit executable path to Android avbtool")
    parser.add_argument("--output-dir", required=True, help="new directory; existing directories are rejected")
    parser.add_argument("--disable-verification", action="store_true",
                        help="development-only: set AVB_VERIFICATION_DISABLED (flags=2)")
    args = parser.parse_args()
    try:
        result = build(args.manifest, args.avbtool, args.output_dir, args.disable_verification)
    except BundleError as exc:
        parser.error(str(exc))
    print(result)


if __name__ == "__main__":
    main()
