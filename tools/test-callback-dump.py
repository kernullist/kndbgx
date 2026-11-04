"""Compare the reviewed callback profile with raw CDB reads of an operator-owned dump."""

import argparse
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import time


def json_rows(text, prefix):
    rows = []
    for line in text.splitlines():
        start = line.find(prefix)
        if start >= 0:
            try:
                rows.append(json.loads(line[start:]))
            except json.JSONDecodeError:
                pass
    return rows


def oracle_commands():
    commands = []
    for symbol in ("PspCreateProcessNotifyRoutine", "PspCreateThreadNotifyRoutine", "PspLoadImageNotifyRoutine"):
        slot = f"(nt!{symbol} + @$t0 * 8)"
        commands.append(
            f'.for (r @$t0 = 0; @$t0 < 0x40; r @$t0 = @$t0 + 1) {{ .if (poi({slot}) != 0) {{ '
            f'.printf "CALLBACK_ORACLE {symbol} %p %p\\n", {slot}, poi((poi({slot}) & 0xfffffffffffffff0) + 8) }} }}')
    for symbol, family in (("PsProcessType", "Process"), ("PsThreadType", "Thread"), ("ExDesktopObjectType", "Desktop")):
        head = f"(poi(nt!{symbol}) + 0xc8)"
        commands.append(
            f'r @$t0 = poi({head}); r @$t1 = 0; .while (@$t0 != {head}) {{ .if (@$t1 >= 0x100) {{ .break }}; '
            f'.printf "CALLBACK_ORACLE {family}.PreOperation %p %p\\n", @$t0, poi(@$t0 + 0x28); '
            f'.printf "CALLBACK_ORACLE {family}.PostOperation %p %p\\n", @$t0, poi(@$t0 + 0x30); '
            f'r @$t0 = poi(@$t0); r @$t1 = @$t1 + 1 }}; .printf "CALLBACK_LIST_END {family} %p %p\\n", @$t0, {head}')
    commands.append(
        'r @$t0 = poi(nt!CallbackListHead); r @$t1 = 0; .while (@$t0 != nt!CallbackListHead) { '
        '.if (@$t1 >= 0x100) { .break }; .printf "CALLBACK_ORACLE Registry %p %p\\n", @$t0, poi(@$t0 + 0x28); '
        'r @$t0 = poi(@$t0); r @$t1 = @$t1 + 1 }; .printf "CALLBACK_LIST_END Registry %p %p\\n", @$t0, nt!CallbackListHead')
    commands += ["lm", ".echo CALLBACK_ORACLE_DONE"]
    return "\n".join(commands) + "\n"


def routine_rows(rows):
    routines = []
    for row in rows:
        if row.get("kind") == "RoutineObservation":
            routines.append(row)
        elif row.get("kind") == "ObjectCallbackRegistration":
            routines.extend((row["pre"], row["post"]))
    return routines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cdb", type=pathlib.Path, required=True)
    parser.add_argument("--dll", type=pathlib.Path, required=True)
    parser.add_argument("--dump", type=pathlib.Path, required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    args = parser.parse_args()
    for path in (args.cdb, args.dll, args.dump):
        if not path.is_file():
            parser.error(f"File unavailable: {path}")
    args.evidence.mkdir(parents=True, exist_ok=False)
    log = args.evidence.resolve() / "cdb.log"
    oracle = args.evidence.resolve() / "oracle.txt"
    oracle.write_text(oracle_commands(), encoding="ascii")
    command = f'.reload /f nt; .load "{args.dll.resolve().as_posix()}"; !kndbgx !callbacks'
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [str(args.cdb.resolve()), "-z", str(args.dump.resolve()), "-y", args.symbols, "-c", command],
            stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)

        def send(line):
            process.stdin.write(line + "\n")
            process.stdin.flush()

        def read():
            if log.stat().st_size > 16 * 1024 * 1024:
                raise RuntimeError("Debugger output exceeded its evidence budget")
            text = log.read_text(encoding="utf-8", errors="replace")
            return re.sub(r"(?m)^\d+:[ \t]*kd>[ \t]*", "", text)

        def wait_for(predicate, timeout=90):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = predicate(read())
                if value:
                    return value
                if process.poll() is not None:
                    raise RuntimeError("Debugger exited before validation completed")
                time.sleep(0.1)
            raise TimeoutError("Debugger validation timed out")

        try:
            match = wait_for(lambda text: re.search(r"\[job\] ([0-9a-f]+)", text))
            job_id = match.group(1)
            job = None
            for attempt in range(120):
                send("!kndbgx job " + job_id)
                time.sleep(0.25)
                candidates = [row for row in json_rows(read(), '{"jobId":') if row.get("jobId") == job_id and "result" in row]
                if candidates:
                    job = candidates[-1]
                    break
            if job is None or job["state"] != "Success":
                raise RuntimeError(f"Callback collection did not complete: {job}")
            coverage = job["result"]["coverage"]
            if not coverage["complete"] or int(coverage["unknownEntries"]) or int(coverage["unreadableEntries"]):
                raise RuntimeError("Callback coverage is incomplete")
            rows = json_rows(job["output"], '{"kind":')
            routines = routine_rows(rows)
            tables = [row for row in rows if row["kind"] == "CallbackTable"]
            if len(tables) != 3 or any(row.get("verification") != "Verified" for row in tables):
                raise RuntimeError("This raw-memory oracle requires the reviewed callback profile")
            send("$$><" + str(oracle))
            text = wait_for(lambda text: text if re.search(r"^CALLBACK_ORACLE_DONE\s*$", text, re.M) else None)
            expected = {(row["family"], int(row["slot"], 16)): int(row["routine"], 16)
                        for row in routines}
            actual = {(family, int(slot.replace("`", ""), 16)): int(routine.replace("`", ""), 16)
                      for family, slot, routine in re.findall(r"^CALLBACK_ORACLE (\S+) ([0-9a-f`]+) ([0-9a-f`]+)", text, re.M)}
            if len(expected) != len(routines) or not expected or expected != actual:
                raise RuntimeError("Collector addresses differ from raw debugger reads")
            ends = re.findall(r"^CALLBACK_LIST_END (\S+) ([0-9a-f`]+) ([0-9a-f`]+)", text, re.M)
            if len(ends) != 4 or any(current != head for _, current, head in ends):
                raise RuntimeError("A raw callback list did not reach its sentinel")
            modules = [(int(start.replace("`", ""), 16), int(end.replace("`", ""), 16), name)
                       for start, end, name in re.findall(r"^([0-9a-f]{8}`[0-9a-f]{8})\s+([0-9a-f]{8}`[0-9a-f]{8})\s+(\S+)\s", text, re.M)]
            for row in routines:
                if int(row["routine"], 16):
                    owners = [name for start, end, name in modules if start <= int(row["routine"], 16) < end]
                    if owners != [row.get("module")]:
                        raise RuntimeError("Collector ownership differs from the debugger module list")
            if "Exception in debugger client" in text:
                raise RuntimeError("A debugger callback raised an exception")
            evidence = {
                "dump": str(args.dump.resolve()), "dumpBytes": args.dump.stat().st_size,
                "dllSha256": hashlib.sha256(args.dll.read_bytes()).hexdigest(),
                "coldStartJobSucceeded": True, "routineRowsCompared": len(actual),
                "nonNullRoutinesCompared": sum(value != 0 for value in actual.values()),
                "families": dict(collections.Counter(row["family"] for row in routines)),
                "allRoutineAddressesMatch": True, "allModuleNamesMatch": True,
                "allListsReachSentinel": True, "debuggerCallbackExceptions": 0,
                "coverage": job["result"]["coverage"]}
            (args.evidence / "result.json").write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
            (args.evidence / "validation.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(evidence, indent=2))
        finally:
            if process.poll() is None:
                try:
                    send("q")
                    process.wait(timeout=5)
                except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=5)
            process.stdin.close()


if __name__ == "__main__":
    main()
