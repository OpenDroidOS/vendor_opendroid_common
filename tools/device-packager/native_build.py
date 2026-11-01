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

"""Run the native packager with an explicit signing identity and verify its ZIP."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile


def verify_zip(path, certificate):
    from asn1crypto import cms
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(-6, 2)
        start, marker, comment = struct.unpack("<3H", stream.read(6))
        if marker != 65535 or start != comment or comment < 6 or size < comment + 22:
            raise ValueError("invalid native ZIP signature footer")
        stream.seek(size - comment - 22)
        eocd = stream.read(22)
        if eocd[:4] != b"PK\x05\x06" or struct.unpack_from("<H", eocd, 20)[0] != comment:
            raise ValueError("signature is not in the ZIP end record")
        der = stream.read(comment - 6)
        data = cms.ContentInfo.load(der)["content"]
        if len(data["signer_infos"]) != 1 or len(data["certificates"]) != 1:
            raise ValueError("expected one native package signer")
        signer = data["signer_infos"][0]
        if (len(data["digest_algorithms"]) != 1
                or data["digest_algorithms"][0]["algorithm"].native != "sha256"
                or signer["digest_algorithm"]["algorithm"].native != "sha256"
                or signer["signature_algorithm"]["algorithm"].native != "sha256_rsa"):
            raise ValueError("unsupported native package signature algorithm")
        expected = x509.load_pem_x509_certificate(certificate.read_bytes())
        if data["certificates"][0].chosen.dump() != expected.public_bytes(serialization.Encoding.DER):
            raise ValueError("package certificate differs from the supplied certificate")
        stream.seek(0)
        digest = hashlib.sha256()
        remaining = size - comment - 22
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("truncated signed ZIP")
            digest.update(block)
            remaining -= len(block)
        payload_hash = digest.digest()
        if data["encap_content_info"]["content"].native != struct.pack("<2H32s", 672, 32, payload_hash):
            raise ValueError("signed content digest differs from ZIP bytes")
        expected.public_key().verify(data["signer_infos"][0]["signature"].native,
                                     payload_hash, padding.PKCS1v15(), hashes.SHA256())
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError("ZIP data CRC failed")
        names = archive.namelist()
        if len(names) != len(set(names)) or not {"update.bin", "build_tools.zip", "board_list", "version_list"} <= set(names):
            raise ValueError("native ZIP entry contract differs")
        member = archive.getinfo("build_tools.zip")
        if member.file_size > 32 * 1024 * 1024:
            raise ValueError("build_tools.zip exceeds verification limit")
        with zipfile.ZipFile(io.BytesIO(archive.read(member))) as tools:
            tool_names = tools.namelist()
            if (tools.testzip() is not None or len(tool_names) != len(set(tool_names))
                    or not {"updater_binary", "loadScript.us"} <= set(tool_names)):
                raise ValueError("native build tools contract differs")
    return {"package": path.name, "bytes": size,
            "certificate_sha256": expected.fingerprint(hashes.SHA256()).hex(),
            "zip_crc_and_native_members": "passed", "outer_signature": "passed",
            "native_recovery_installation": "not-tested"}


def verify_payloads(path, plan, certificate=None):
    """Match native component headers and streamed payloads to prepared inputs."""
    product_version = (plan["version"] + "\n").encode()
    boards = ("\n".join(plan["boards"]) + "\n").encode()
    entries = [("/version_list", len(product_version), hashlib.sha256(product_version).digest()),
               ("/board_list", len(boards), hashlib.sha256(boards).digest())]
    entries += [("/" + item["name"], item["stored_bytes"], bytes.fromhex(item["sha256"]))
                for item in plan["partitions"] if item["operation"] == "write"]
    with zipfile.ZipFile(path) as archive:
        with archive.open("build_tools.zip") as member:
            with zipfile.ZipFile(io.BytesIO(member.read())) as tools:
                with tools.open("updater_binary") as binary:
                    if hashlib.file_digest(binary, "sha256").hexdigest() != plan["updater_binary_sha256"]:
                        raise ValueError("packaged updater binary differs from prepared input")
        member = archive.getinfo("update.bin")
        with archive.open(member) as stream:
            header = stream.read(180)
            signed = hashlib.sha256(header)
            version = plan.get("package_file_version", 2)
            if (version not in (2, 3) or len(header) != 180 or struct.unpack_from("<H", header)[0] != 1
                    or struct.unpack_from("<I", header, 8)[0] != version
                    or struct.unpack_from("<HH", header, 176) != (5, len(entries) * 87)):
                raise ValueError("native component-table header differs from selected version")
            for name, size, digest in entries:
                component = stream.read(87)
                signed.update(component)
                if (len(component) != 87 or component[:32].split(b"\0")[0].decode() != name
                        or struct.unpack_from("<Q" if version >= 3 else "<I", component, 47)[0] != size
                        or component[55:87] != digest):
                    raise ValueError("packaged component metadata differs from prepared input")
            reserve = stream.read(16)
            signed.update(reserve)
            hash_header = stream.read(16)
            signed.update(hash_header)
            block_size = 4 * 1024 * 1024
            if (len(reserve) != 16 or len(hash_header) != 16
                    or struct.unpack("<HI3HI", hash_header) != (6, 10, 1, 32, len(entries), block_size)):
                raise ValueError("missing or invalid native recovery hash header")
            data_header = stream.read(6)
            signed.update(data_header)
            word_size = 8 if version >= 3 else 4
            header_size = 34 + word_size
            expected_length = sum(header_size + ((size + block_size - 1) // block_size) *
                                  (2 * word_size + 32) for _, size, _ in entries)
            if len(data_header) != 6 or struct.unpack("<HI", data_header) != (7, expected_length):
                raise ValueError("native recovery hash table length differs")
            block_hashes = []
            for name, size, _ in entries:
                raw = stream.read(header_size)
                signed.update(raw)
                count = (size + block_size - 1) // block_size
                if (len(raw) != header_size or struct.unpack("<32sH" + ("Q" if version >= 3 else "I"), raw)
                        != (name.encode().ljust(32, b"\0"), count, size)):
                    raise ValueError("native recovery hash component differs")
                digests = []
                for start in range(0, size, block_size):
                    raw = stream.read(2 * word_size + 32)
                    signed.update(raw)
                    if (len(raw) != 2 * word_size + 32
                            or struct.unpack_from("<2Q" if version >= 3 else "<2I", raw)
                            != (start, min(size, start + block_size) - 1)):
                        raise ValueError("native recovery hash range differs")
                    digests.append(raw[-32:])
                block_hashes.append(digests)
            sign_header = stream.read(6)
            if len(sign_header) != 6 or struct.unpack("<HI", sign_header) != (8, 256):
                raise ValueError("invalid native header signature record")
            signature = stream.read(256)
            if len(signature) != 256:
                raise ValueError("truncated native header signature")
            if certificate is not None:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                x509.load_pem_x509_certificate(certificate.read_bytes()).public_key().verify(
                    signature, signed.digest(), padding.PKCS1v15(), hashes.SHA256())
            if stream.tell() + sum(size for _, size, _ in entries) != member.file_size:
                raise ValueError("native component data offsets differ")
            for (name, size, expected), digests in zip(entries, block_hashes):
                digest = hashlib.sha256()
                for start, block_digest in zip(range(0, size, block_size), digests):
                    block = hashlib.sha256()
                    remaining = min(block_size, size - start)
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError("truncated component payload")
                        block.update(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if block.digest() != block_digest:
                        raise ValueError("native recovery block hash differs: " + name)
                if digest.digest() != expected:
                    raise ValueError("packaged payload differs from prepared input: " + name)
    return "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packaging-tools", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(args.certificate.read_bytes())
    if (not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048
            or key.public_key().public_numbers() != cert.public_key().public_numbers()):
        raise ValueError("native full-package signing needs a matching RSA-2048 key/certificate")
    sys.path.insert(0, str(args.packaging_tools))
    import build_pkcs7
    # The upstream signing module otherwise reads a fixed certificate beside
    # its source. Keep caller identities outside that source tree.
    build_pkcs7.CERT_PATH = str(args.certificate)
    import build_update
    sys.argv = [str(args.packaging_tools / "build_update.py"), str(args.target),
                str(args.output), "-pk", str(args.signing_key), "-sc"]
    build_update.main()
    output = args.output / "updater_sd.zip"
    if not output.is_file():
        raise ValueError("native packager did not create updater_sd.zip")
    report = verify_zip(output, args.certificate)
    plan = json.loads((args.target.parent / "plan.json").read_text())
    report["prepared_component_bytes_headers_and_recovery_hashes"] = verify_payloads(output, plan, args.certificate)
    (args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
