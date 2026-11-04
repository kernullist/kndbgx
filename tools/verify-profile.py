"""Verify the shipped extent profile against an owned local kernel image and matching PDB."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from release import PE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=pathlib.Path, required=True)
    parser.add_argument("--pdb", type=pathlib.Path, required=True)
    parser.add_argument("--profile", type=pathlib.Path, default=pathlib.Path("profiles/nt-26100.8655-x64.json"))
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    pe = PE(args.image)
    if hashlib.sha256(pe.data).hexdigest() != profile["imageSha256"] or hashlib.sha256(args.pdb.read_bytes()).hexdigest() != profile["pdbSha256"]:
        raise ValueError("Profile input identity mismatch")
    table = int(profile["tableRva"], 16)
    limit_rva = int(profile["limitRva"], 16)
    count = pe.unpack("I", pe.offset(limit_rva, 4))[0]
    if count != profile["count"] or table + count * 4 != limit_rva:
        raise ValueError("Extent mismatch")
    for name, expected in ((profile["tableSymbol"], table), (profile["limitSymbol"], limit_rva)):
        result = json.loads(subprocess.check_output(["x64/Release/kndbgx-engine-test.exe", "--pdb-type", str(args.pdb),
                          profile["pdbGuid"], str(profile["pdbAge"]), "@" + name], encoding="utf-8"))
        if not (result.get("present") or result.get("publicPresent")) or int(result["rva"], 16) != expected:
            raise ValueError("Public PDB symbol extent mismatch")
    raw = pe.offset(table, count * 4)
    entries = []
    for index in range(count):
        rva = pe.unpack("I", raw + index * 4)[0]
        executable = [name for name, va, size, _, _, flags in pe.sections if va <= rva < va + size and flags & 0x20000000]
        if len(executable) != 1:
            raise ValueError("Disk service RVA is not in one executable section")
        entries.append({"index": index, "rva": hex(rva), "executableSection": executable[0]})
    evidence = {"profile": profile["id"], "imageSha256": profile["imageSha256"], "pdbSha256": profile["pdbSha256"],
                "diskEncoding": "ImageRva32", "runtimeMemoryVerified": False, "executableEntries": count, "entries": entries}
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"profile": profile["id"], "validatedDiskRvas": count, "runtimeMemoryVerified": False}))


if __name__ == "__main__":
    main()
