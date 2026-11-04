"""Create or verify a sanitized source/artifact/assertion manifest for a review map."""

import argparse
import collections
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

import release

ROOT = pathlib.Path(__file__).resolve().parent.parent


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_fingerprint():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode("utf-8").split("\0")
    selected = sorted({name for name in names if name and (
        name.startswith(("src/", "ui/", "tools/", "profiles/", "res/")) or
        name.endswith((".vcxproj", ".sln", ".props", ".targets")) or name == "deps/dependencies.lock.json")})
    digest = hashlib.sha256()
    for name in selected:
        # Text normalization makes the fingerprint independent of core.autocrlf.
        data = (ROOT / name).read_bytes()
        try:
            data.decode("utf-8-sig")
            data = data.replace(b"\r\n", b"\n")
        except UnicodeDecodeError:
            pass
        digest.update(name.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
    return {"algorithm": "SHA256(sorted UTF-8 path + NUL + SHA256(file bytes with CRLF normalized to LF))",
            "scope": "src, ui, tools, profiles, res, projects/solution, MSBuild props/targets, dependency lock; Git-visible files only",
            "files": len(selected), "sha256": digest.hexdigest()}


def read_log(path):
    data = path.read_bytes()
    return data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")


def assertions(log):
    if re.search(r"^\s*(?:\[FAIL\]|FAIL\s)", log, re.M) or re.search(r"engine integration failures: [1-9]", log):
        raise ValueError("Test logs contain failed assertions")
    return collections.Counter(re.findall(r"^\s*(?:\[PASS\]|PASS)\s+([^\r\n]+)", log, re.M))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def engine_artifacts(path):
    records = json.loads(path.read_text(encoding="utf-8-sig"))
    hashes = {record["Path"].replace("\\", "/").rsplit("/", 1)[-1]: record["Hash"].lower() for record in records}
    require(set(hashes) == {"kndbgx.dll", "dbgeng.dll"} and
            all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()), "Invalid engine binary record")
    return hashes


def build_manifest(args):
    subprocess.run([sys.executable, str(ROOT / "tools/check-acceptance.py"), str(args.build_log)], cwd=ROOT, check=True)
    build = read_log(args.build_log)
    debug = read_log(args.debug_log)
    build_assertions, debug_assertions = assertions(build), assertions(debug)
    counts = [int(n) for n in re.findall(r"^([0-9]+) passed, 0 failed\s*$", build, re.M)]
    require(len(counts) == 4 and len(set(counts)) == 1, "Four matching clean native runs required")
    require(build_assertions["release.validation-run-complete"] == 1 and
            "engine integration failures: 0" in build, "Completed clean release gate required")
    require("engine integration failures: 0" in debug, "Completed Debug Windows failure tests required")
    mapping = json.loads(args.mapping.read_text(encoding="utf-8"))
    ids = [entry["id"] for entry in mapping["findings"]]
    require(bool(ids) and len(ids) == len(set(ids)), "Nonempty unique review finding IDs required")
    combined = build_assertions + debug_assertions
    findings = []
    for entry in mapping["findings"]:
        source = "\n".join((ROOT / path).read_text(encoding="utf-8-sig") for path in entry["tests"])
        require(all((ROOT / path).is_file() for path in entry["productPaths"]), "Missing product path")
        require(bool(entry["assertions"]), "Missing assertions")
        for name in entry["assertions"]:
            require(name in source and combined[name] > 0, f"Missing executed source assertion: {entry['id']} {name}")
        findings.append({"id": entry["id"], "expected": "all mapped assertions pass", "actual": "pass",
                         "assertions": [{"id": name, "passes": combined[name]} for name in entry["assertions"]]})
    dll, pdb = ROOT / "x64/Release/kndbgx.dll", ROOT / "x64/Release/kndbgx.pdb"
    dll_hash, pdb_hash = sha(dll), sha(pdb)
    pe = release.PE(dll).inspect()
    debug_hash = sha(ROOT / "x64/Debug/kndbgx.dll")
    release_engine, debug_engine = engine_artifacts(args.release_artifacts), engine_artifacts(args.debug_artifacts)
    require(release_engine["kndbgx.dll"] == dll_hash and debug_engine["kndbgx.dll"] == debug_hash and
            release_engine["dbgeng.dll"] == debug_engine["dbgeng.dll"], "Windows test runs used different binaries")
    rebuilt = json.loads(args.rebuild.read_text(encoding="utf-8-sig"))
    require(rebuilt["dllByteIdentical"] and rebuilt["bothPdbIdentitiesAndEntrypointsVerified"] and
            rebuilt["first"]["dll"] == rebuilt["second"]["dll"] == dll_hash and rebuilt["second"]["pdb"] == pdb_hash and
            rebuilt["pdbIdentity"] == pe["pdb"], "Rebuild results do not match the final DLL/PDB")
    symbols = json.loads(args.symbols.read_text(encoding="utf-8-sig"))
    callbacks = json.loads(args.callbacks.read_text(encoding="utf-8-sig"))
    require(symbols["dllSha256"] == callbacks["dllSha256"] == dll_hash, "Dump tests used a different DLL")
    require(symbols["coldTypeQuery"] == "Success" and symbols["commands"] == 29, "Incomplete symbol dump matrix")
    require(callbacks["coldStartJobSucceeded"] and callbacks["allRoutineAddressesMatch"] and callbacks["allModuleNamesMatch"] and
            callbacks["allListsReachSentinel"] and callbacks["debuggerCallbackExceptions"] == 0, "Callback oracle failed")
    matrix = __import__("test-symbol-dump")
    require(set(symbols["results"]) == set(matrix.SUCCESS + matrix.PARTIAL), "Incomplete symbol command coverage")
    require(symbols["dumpBytes"] == callbacks["dumpBytes"], "Dump sizes differ between validation runs")
    # Whitelist counts and coverage. Never copy raw rows, addresses, output or file paths.
    symbol_results = []
    for command, value in symbols["results"].items():
        expected = "Partial" if command in matrix.PARTIAL else "Success"
        require(value["state"] == expected and value["coverage"]["complete"] == (expected == "Success"), "Unexpected command coverage")
        if expected == "Success":
            require(int(value["coverage"]["unknownEntries"]) == 0 and int(value["coverage"]["unreadableEntries"]) == 0,
                    "Successful command has unknown or unreadable entries")
        symbol_results.append({"command": command, "expectedStatus": expected, "actualStatus": value["state"],
                               "rows": value["rows"], "coverage": value["coverage"]})
    require(re.fullmatch(r"[0-9a-f]{40}", args.baseline) is not None, "Full baseline commit required")
    environment = json.loads(args.environment.read_text(encoding="utf-8-sig"))
    require(set(environment) == {"windows", "msvc", "sdk", "dbgeng", "webview2", "python", "node"} and
            all(isinstance(value, str) and re.fullmatch(r"[0-9A-Za-z. ()_-]{1,100}", value) for value in environment.values()),
            "Environment must contain version strings only")
    profile = json.loads((ROOT / "profiles/nt-26100.8655-callbacks-x64.json").read_text(encoding="utf-8"))
    manifest = {
        "schema": "kndbgx.review-evidence.v1", "createdUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "baselineCommit": args.baseline, "source": source_fingerprint(), "environment": environment,
        "mapping": {"path": args.mapping.resolve().relative_to(ROOT).as_posix(), "sha256": sha(args.mapping)},
        "artifacts": {"releaseDllSha256": dll_hash, "releasePdbSha256": pdb_hash, "pe": pe,
                      "debugDllSha256": debug_hash, "dbgengSha256": release_engine["dbgeng.dll"],
                      "cleanDllByteIdentical": True, "bothPdbIdentitiesAndEntrypointsVerified": True},
        "execution": {"nativePassesPerRun": counts, "javascriptPasses": len(re.findall(r"^PASS\s+T-[^\r\n]+", build, re.M)),
                      "releaseOwnedWindowsPasses": sum(n for name, n in assertions(build[build.index("[PASS] host.load-installed-dbgeng"):]).items() if name.startswith(("host.", "third."))),
                      "debugOwnedWindowsPasses": sum(n for name, n in assertions(debug[debug.index("[PASS] host.load-installed-dbgeng"):]).items() if name.startswith(("host.", "third."))),
                      "rendererUnresponsiveNotificationObserved": "ui.unresponsive-notification=observed" in debug},
        "findings": findings,
        "kernelDump": {"scope": "read-only supplied dump; one exact reviewed NT image/PDB identity",
                       "dumpBytes": symbols["dumpBytes"],
                       "profileIdentity": {name: profile[name] for name in ("machine", "timestamp", "imageSize", "pdbGuid", "pdbAge", "imageSha256", "pdbSha256")},
                       "symbolCommands": symbol_results, "rawComparisons": symbols["rawComparisons"],
                       "callbacks": {name: callbacks[name] for name in ("coldStartJobSucceeded", "routineRowsCompared", "nonNullRoutinesCompared", "families", "coverage",
                                     "allRoutineAddressesMatch", "allModuleNamesMatch", "allListsReachSentinel", "debuggerCallbackExceptions")}},
        "evidenceDigests": {name: sha(path) for name, path in {"cleanBuildLog": args.build_log, "debugWindowsLog": args.debug_log,
                            "rebuild": args.rebuild, "symbols": args.symbols, "callbacks": args.callbacks,
                            "debugEngineArtifacts": args.debug_artifacts, "releaseEngineArtifacts": args.release_artifacts}.items()},
        "limits": ["Assertion counts are traceability, not branch coverage or a defect-free guarantee.",
                   "WebView failure injection uses an owned Debug runtime; Release boot/unload is checked separately.",
                   "No live/remote kernel race, other NT identity or hardware mutation claim.",
                   "PDB byte determinism is not required; each PDB identity and entrypoint was verified."]}
    text = json.dumps(manifest, indent=2, ensure_ascii=True) + "\n"
    require(not re.search(r"[A-Za-z]:[/\\]|0xffff[0-9a-f]{8,}", text, re.I), "Private path or target address in manifest")
    args.output.write_text(text, encoding="utf-8")
    print("PASS rereview.sanitized-source-artifact-manifest-created")


def verify(path, artifacts):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    require(manifest["schema"] == "kndbgx.review-evidence.v1" and manifest["source"] == source_fingerprint(),
            "Manifest source fingerprint differs from the checkout")
    require(bool(manifest["findings"]) and all(entry["actual"] == "pass" for entry in manifest["findings"]), "Incomplete review manifest")
    if "mapping" in manifest:
        mapping = manifest["mapping"]
        require(sha(ROOT / mapping["path"]) == mapping["sha256"], "Review map hash mismatch")
    if artifacts:
        require(manifest["artifacts"]["releaseDllSha256"] == sha(ROOT / "x64/Release/kndbgx.dll") and
                manifest["artifacts"]["releasePdbSha256"] == sha(ROOT / "x64/Release/kndbgx.pdb") and
                manifest["artifacts"]["debugDllSha256"] == sha(ROOT / "x64/Debug/kndbgx.dll"), "Artifact hash mismatch")
    print("PASS rereview.manifest-source-and-requested-artifacts-verified")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    for name in ("build-log", "debug-log", "rebuild", "symbols", "callbacks", "environment", "output", "debug-artifacts", "release-artifacts"):
        create.add_argument("--" + name, type=pathlib.Path, required=True)
    create.add_argument("--baseline", required=True)
    create.add_argument("--mapping", type=pathlib.Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("manifest", type=pathlib.Path)
    check.add_argument("--artifacts", action="store_true")
    args = parser.parse_args()
    if args.command == "create":
        build_manifest(args)
    else:
        verify(args.manifest, args.artifacts)


if __name__ == "__main__":
    main()
