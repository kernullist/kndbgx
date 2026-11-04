"""Fetch the matching public PDB for a local PE into a private test cache."""

import argparse
import hashlib
import json
import pathlib
import struct
import urllib.parse
import urllib.request
import uuid


def rsds(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Invalid DOS header")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    machine, sections, timestamp, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    optional = pe + 24
    if optional_size < 112 or optional + optional_size + sections * 40 > len(data) or sections > 96:
        raise ValueError("Invalid optional or section table")
    magic = struct.unpack_from("<H", data, optional)[0]
    directory = optional + (112 if magic == 0x20b else 96 if magic == 0x10b else 0)
    if directory == optional or directory + 56 > optional + optional_size:
        raise ValueError("Debug directory not present")
    debug_rva, debug_size = struct.unpack_from("<II", data, directory + 6 * 8)
    if debug_size > 28 * 1024 or debug_size % 28:
        raise ValueError("Invalid debug directory size")

    def file_offset(rva, size):
        for index in range(sections):
            section = optional + optional_size + index * 40
            _, va, raw_size, raw_offset = struct.unpack_from("<IIII", data, section + 8)
            if va <= rva and rva - va + size <= raw_size:
                offset = raw_offset + rva - va
                if offset + size <= len(data):
                    return offset
        raise ValueError("RVA outside raw image")

    records = file_offset(debug_rva, debug_size)
    for entry in range(records, records + debug_size, 28):
        _, _, _, _, kind, size, _, offset = struct.unpack_from("<IIHHIIII", data, entry)
        if kind != 2 or size < 25 or offset + size > len(data) or data[offset:offset + 4] != b"RSDS":
            continue
        guid = uuid.UUID(bytes_le=data[offset + 4:offset + 20])
        age = struct.unpack_from("<I", data, offset + 20)[0]
        name_data = data[offset + 24:offset + size]
        if b"\0" not in name_data:
            raise ValueError("Unterminated PDB name")
        name = pathlib.PureWindowsPath(name_data.split(b"\0", 1)[0].decode("utf-8")).name
        if not name.lower().endswith(".pdb") or len(name) > 256:
            raise ValueError("Invalid PDB name")
        return {
            "image": str(path.resolve()), "imageSha256": hashlib.sha256(data).hexdigest(),
            "machine": machine, "timestamp": timestamp, "pdbName": name, "pdbGuid": str(guid), "pdbAge": age,
            "symbolKey": guid.hex.upper() + format(age, "X")
        }
    raise ValueError("No RSDS identity")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=pathlib.Path, required=True)
    parser.add_argument("--cache", type=pathlib.Path, required=True)
    args = parser.parse_args()
    identity = rsds(args.image)
    destination = args.cache.resolve() / identity["pdbName"] / identity["symbolKey"] / identity["pdbName"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    url = "https://msdl.microsoft.com/download/symbols/" + "/".join(
        urllib.parse.quote(identity[key], safe="") for key in ("pdbName", "symbolKey", "pdbName"))
    if not destination.exists():
        temporary = destination.with_suffix(".pending-" + uuid.uuid4().hex)
        try:
            with urllib.request.urlopen(url, timeout=45) as response, temporary.open("xb") as output:
                total = 0
                while block := response.read(1024 * 1024):
                    total += len(block)
                    if total > 1024 * 1024 * 1024:
                        raise ValueError("PDB exceeds fixture size budget")
                    if output.write(block) != len(block):
                        raise OSError("Short write")
                expected = response.headers.get("Content-Length")
                if expected is not None and total != int(expected):
                    raise OSError("Truncated download")
                output.flush()
            with temporary.open("rb") as check:
                if not check.read(32).startswith(b"Microsoft C/C++ MSF 7.00"):
                    raise ValueError("Response is not a supported PDB")
            temporary.rename(destination)
        finally:
            temporary.unlink(missing_ok=True)
    with destination.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    identity.update({"pdbPath": str(destination), "pdbSha256": digest,
                     "source": url, "scope": "Local validation only; not a kernel memory fixture"})
    manifest = destination.parent / "identity.json"
    manifest.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(identity, indent=2))


if __name__ == "__main__":
    main()
