#!/usr/bin/env python3
# Copyright 2026 OpenDroidOS
# SPDX-License-Identifier: Apache-2.0

"""Preserve native recovery entrypoints in an appended A/B ramdisk layout."""

from contextlib import contextmanager
import gzip
import hashlib
import posixpath
import stat

from stage_kernel import StageError, _open_regular

MAX_ENTRIES = 200000
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_NAME = 4096


def _exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise StageError("Truncated native recovery archive")
    return data


@contextmanager
def _stream(path):
    with _open_regular(path) as raw:
        magic = raw.read(2)
        raw.seek(0)
        if magic == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=raw) as stream:
                yield stream
        else:
            yield raw


def _name(raw):
    name = raw.decode("utf-8")
    while name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return "."
    if (name.startswith("/") or "\\" in name or
            any(part in ("", ".", "..") for part in name.split("/")) or
            any(ord(character) < 32 or ord(character) == 127 for character in name)):
        raise StageError("Unsafe native recovery member name")
    return name


def _walk(path, consume):
    names = set()
    expanded = 0
    with _stream(path) as stream:
        while True:
            header = _exact(stream, 110)
            if header[:6] not in (b"070701", b"070702"):
                raise StageError("Expected a native newc recovery archive")
            fields = [int(header[index:index + 8], 16) for index in range(6, 110, 8)]
            size, name_size = fields[6], fields[11]
            if not 1 <= name_size <= MAX_NAME:
                raise StageError("Invalid native recovery member name size")
            raw_name = _exact(stream, name_size)
            if raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
                raise StageError("Invalid native recovery member name")
            padding = _exact(stream, -(110 + name_size) % 4)
            name = _name(raw_name[:-1])
            expanded += 110 + name_size + len(padding) + size + (-size % 4)
            if expanded > MAX_EXPANDED:
                raise StageError("Native recovery archive exceeds layout limits")
            if name == "TRAILER!!!":
                if size:
                    raise StageError("Invalid native recovery trailer")
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        return
                    expanded += len(block)
                    if expanded > MAX_EXPANDED or block.strip(b"\0"):
                        raise StageError("Unexpected data after native recovery trailer")
            if name in names:
                raise StageError("Duplicate native recovery member: " + name)
            if len(names) >= MAX_ENTRIES:
                raise StageError("Native recovery archive exceeds layout limits")
            names.add(name)
            entry = {"name": name, "fields": fields, "mode": fields[1],
                     "header": header + raw_name + padding}
            checksum = 0
            remaining = size

            def chunks():
                nonlocal remaining, checksum
                while remaining:
                    block = _exact(stream, min(remaining, 1024 * 1024))
                    remaining -= len(block)
                    if header[:6] == b"070702":
                        checksum = (checksum + sum(block)) & 0xffffffff
                    yield block

            consume(entry, chunks())
            if remaining:
                raise StageError("Incomplete native recovery layout traversal")
            _exact(stream, -size % 4)
            if header[:6] == b"070702" and checksum != fields[12]:
                raise StageError("Native recovery member checksum mismatch")


def _catalog(path):
    records = {}

    def capture(entry, chunks):
        digest = hashlib.sha256()
        prefix = b""
        link = bytearray()
        is_link = stat.S_ISLNK(entry["mode"])
        if is_link and entry["fields"][6] > MAX_NAME:
            raise StageError("Oversized native recovery symlink")
        for block in chunks:
            digest.update(block)
            if len(prefix) < 64:
                prefix += block[:64 - len(prefix)]
            if is_link:
                link.extend(block)
        entry.update(sha256=digest.hexdigest(), prefix=prefix)
        if is_link:
            entry["link"] = bytes(link).decode("utf-8")
        records[entry["name"]] = entry

    _walk(path, capture)
    return records


def _resolved_link(name, target):
    return posixpath.normpath(posixpath.join("/" + posixpath.dirname(name), target))


def _plan(records):
    for name in ("bin", "etc", "system"):
        if name not in records or not stat.S_ISDIR(records[name]["mode"]):
            raise StageError("Native recovery requires a directory at /" + name)
    binaries = [records.get(name) for name in ("bin/init", "bin/updater")]
    for name, entry in zip(("bin/init", "bin/updater"), binaries):
        if (entry is None or not stat.S_ISREG(entry["mode"]) or
                not entry["mode"] & 0o111 or not entry["prefix"].startswith(b"\x7fELF") or
                len(entry["prefix"]) < 20):
            raise StageError("A/B recovery requires the native executable /" + name)
    if binaries[0]["prefix"][4:7] != binaries[1]["prefix"][4:7] or binaries[0]["prefix"][18:20] != binaries[1]["prefix"][18:20]:
        raise StageError("Native init and Updater have different ELF architectures")
    recovery = records.get("bin/recovery")
    if recovery is not None and not (
            (stat.S_ISLNK(recovery["mode"]) and
             _resolved_link("bin/recovery", recovery["link"]) == "/bin/updater") or
            (stat.S_ISREG(recovery["mode"]) and recovery["sha256"] == binaries[1]["sha256"])):
        raise StageError("Native recovery already supplies a different recovery executable")
    replacements = {}
    additions = {}

    def add(name, source, target=None):
        existing = records.get(name)
        directory = target is None
        if existing is not None and name not in replacements:
            if directory and stat.S_ISDIR(existing["mode"]):
                return
            if not directory:
                if (stat.S_ISLNK(existing["mode"]) and
                        _resolved_link(name, existing["link"]) == _resolved_link(name, target)):
                    return
                if (stat.S_ISREG(existing["mode"]) and stat.S_ISREG(source["mode"]) and
                        existing["sha256"] == source["sha256"] and
                        (existing["mode"] & 0o7777) == (source["mode"] & 0o7777)):
                    return
            raise StageError("Conflicting recovery entrypoint: /" + name)
        additions[name] = {"name": name, "source": source, "target": target}

    for source_root in ("bin", "etc"):
        destination = "system/" + source_root
        existing = records.get(destination)
        if existing is not None and stat.S_ISLNK(existing["mode"]):
            if (_resolved_link(destination, existing["link"]) != "/" + source_root or
                    existing["fields"][4] != 1):
                raise StageError("Unexpected native recovery directory alias")
            replacements[destination] = {"name": destination,
                                          "source": records[source_root], "target": None}
        else:
            add(destination, records[source_root])
        for name, entry in records.items():
            if not name.startswith(source_root + "/"):
                continue
            destination = "system/" + name
            if stat.S_ISDIR(entry["mode"]):
                add(destination, entry)
            else:
                target = posixpath.relpath("/" + name, "/" + posixpath.dirname(destination))
                add(destination, entry, target)
    add("system/bin/recovery", binaries[1], "../../bin/updater")
    return replacements, additions


def _write_entry(stream, item, inode):
    name = item["name"].encode("utf-8") + b"\0"
    body = item["target"].encode("utf-8") if item["target"] is not None else b""
    if len(name) > MAX_NAME or len(body) > MAX_NAME or inode > 0xffffffff:
        raise StageError("Generated recovery entry exceeds newc limits")
    fields = item["source"]["fields"].copy()
    fields[0] = inode
    fields[1] = ((stat.S_IFLNK | 0o777) if body else
                 (stat.S_IFDIR | (item["source"]["mode"] & 0o7777)))
    fields[4], fields[6], fields[11], fields[12] = 1, len(body), len(name), 0
    stream.write(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
    stream.write(name)
    stream.write(bytes(-(110 + len(name)) % 4))
    stream.write(body)
    stream.write(bytes(-len(body) % 4))


def prepare_ab_recovery(source, output):
    """Stream an explicitly selected native CPIO into a compatible gzip CPIO.

    No files are extracted and no payload, identity, module or policy is replaced.
    The caller owns the temporary output and publishes only a validated container.
    """
    try:
        records = _catalog(source)
        replacements, additions = _plan(records)
        inode = max(entry["fields"][0] for entry in records.values())
        if inode + len(replacements) + len(additions) > 0xffffffff:
            raise StageError("No newc inode range remains for recovery aliases")
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
            seen = set()
            def emit(entry, chunks):
                nonlocal inode
                if entry["name"] not in records:
                    raise StageError("Native recovery changed during layout preparation")
                seen.add(entry["name"])
                replacement = replacements.get(entry["name"])
                if replacement is not None:
                    inode += 1
                    _write_entry(stream, replacement, inode)
                else:
                    stream.write(entry["header"])
                digest = hashlib.sha256()
                for block in chunks:
                    digest.update(block)
                    if replacement is None:
                        stream.write(block)
                if digest.hexdigest() != records[entry["name"]]["sha256"] or entry["fields"] != records[entry["name"]]["fields"]:
                    raise StageError("Native recovery changed during layout preparation")
                if replacement is None:
                    stream.write(bytes(-entry["fields"][6] % 4))

            _walk(source, emit)
            if seen != set(records):
                raise StageError("Native recovery changed during layout preparation")
            for name in sorted(additions, key=lambda name: (name.count("/"), name)):
                inode += 1
                _write_entry(stream, additions[name], inode)
            trailer = b"TRAILER!!!\0"
            fields = [0] * 13
            fields[4], fields[11] = 1, len(trailer)
            stream.write(b"070701" + b"".join(f"{value:08x}".encode() for value in fields))
            stream.write(trailer)
            stream.write(bytes(-(110 + len(trailer)) % 4))
            stream.write(bytes(-stream.tell() % 512))
        return {"layout": "ab-recovery", "original_members": len(records),
                "directory_aliases_replaced": sorted(replacements),
                "members_added": len(additions), "payloads_preserved": True,
                "second_stage_init": "/system/bin/init",
                "recovery_entrypoint": "/system/bin/recovery",
                "recovery_executable": "/bin/updater",
                "limits": ["This preserves entrypoint layout; OEM ramdisk selection, bootloader trust and actual boot remain unproven."]}
    except (ValueError, UnicodeError, EOFError) as error:
        raise StageError("Cannot prepare native A/B recovery layout: " + str(error)) from error
