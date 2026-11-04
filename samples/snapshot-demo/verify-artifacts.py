"""Check native image flags, matching PDB identities and distinct callback banks."""

import json
import pathlib
import re
import struct
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from release import PE
from privacy import require_pdb_basename, require_public


def pdb_identity(path):
    data = path.read_bytes()
    if data[:32] != b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0":
        raise ValueError("Expected MSF 7 PDB")
    block_size, _, block_count, directory_size, _, block_map = struct.unpack_from("<6I", data, 32)
    if block_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768) or len(data) != block_count * block_size:
        raise ValueError("Invalid PDB block geometry")

    def block(index):
        if index >= block_count:
            raise ValueError("Invalid PDB block")
        return data[index * block_size:(index + 1) * block_size]

    directory_blocks = (directory_size + block_size - 1) // block_size
    if directory_blocks * 4 > block_size:
        raise ValueError("PDB directory exceeds demo verifier bound")
    indices = struct.unpack_from(f"<{directory_blocks}I", block(block_map))
    directory = b"".join(block(index) for index in indices)[:directory_size]
    stream_count, = struct.unpack_from("<I", directory)
    if stream_count < 2 or stream_count > 65536:
        raise ValueError("Invalid PDB stream count")
    sizes = struct.unpack_from(f"<{stream_count}I", directory, 4)
    cursor = 4 + 4 * stream_count
    for index, size in enumerate(sizes):
        count = 0 if size == 0xFFFFFFFF else (size + block_size - 1) // block_size
        indices = struct.unpack_from(f"<{count}I", directory, cursor)
        cursor += 4 * count
        if index == 1:
            stream = b"".join(block(number) for number in indices)[:size]
            if len(stream) < 28:
                raise ValueError("PDB info stream is truncated")
            _, _, age = struct.unpack_from("<3I", stream)
            return {"guid": str(uuid.UUID(bytes_le=stream[12:28])), "age": age}
    raise ValueError("PDB info stream missing")


def verify_image(path):
    image = PE(path)
    require_public(path.name, image.data, ROOT)
    flags, = image.unpack("H", image.optional + 70)
    if image.machine != 0x8664 or flags & 0x140 != 0x140:
        raise ValueError(f"Expected x64 ASLR/NX image: {path.name}")
    if any(section[5] & 0xA0000000 == 0xA0000000 for section in image.sections):
        raise ValueError(f"Writable executable section: {path.name}")
    if path.suffix.lower() == ".sys":
        subsystem, = image.unpack("H", image.optional + 68)
        if subsystem != 1 or not flags & 0x80:
            raise ValueError("Driver requires Native subsystem and FORCE_INTEGRITY")
    debug_rva, debug_size = image.directory(6)
    if debug_size == 0 or debug_size % 28:
        raise ValueError("Invalid image debug directory")
    debug = image.offset(debug_rva, debug_size)
    identities = []
    for entry in range(debug, debug + debug_size, 28):
        kind, length, _, raw = image.unpack("4I", entry + 12)
        if kind == 2 and length >= 24 and raw + length <= len(image.data) and image.data[raw:raw + 4] == b"RSDS":
            require_pdb_basename(image.data[raw + 24:raw + length])
            identities.append({"guid": str(uuid.UUID(bytes_le=image.data[raw + 4:raw + 20])), "age": image.unpack("I", raw + 20)[0]})
    if len(identities) != 1 or identities[0] != pdb_identity(path.with_suffix(".pdb")):
        raise ValueError(f"PDB identity mismatch: {path.name}")
    return {"file": path.name, "pdb": identities[0], "aslr": True, "nx": True, "writableExecutableSections": False}


def main():
    directory = pathlib.Path(sys.argv[1]).resolve()
    records = [verify_image(directory / name) for name in ("KnSnapshotDemo.sys", "KnSnapshotDemoCtl.exe", "KnSnapshotDemoFixtures.exe")]
    symbols = {}
    for line in (directory / "KnSnapshotDemo.map").read_text(encoding="utf-8").splitlines():
        match = re.search(r"(\S*(?:\?Pre@|\?Post@)\S*Callbacks\S*)\s+([0-9a-fA-F]{16})\s+f", line)
        if match:
            symbols[match[1]] = match[2].lower()
    if len(symbols) != 4 or len(set(symbols.values())) != 4:
        raise ValueError(f"Expected four distinct Pre/Post bank routines, found {len(symbols)}")
    result = {"schema": "kndbgx.snapshot-demo.artifacts.v1", "images": records, "callbackSymbols": symbols, "liveDriverTested": False}
    (directory / "artifact-verification.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("PASS x64 image flags, three matching PDBs and four distinct callback bank addresses")


if __name__ == "__main__":
    main()
