"""Audit symbol consumers and compare profiled collectors with raw reads of a reviewed NT dump."""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import time


SUCCESS = [
    "dt nt!_EX_FAST_REF", "dt nt!_EPROCESS", "!dml_proc pid:4", "!vad pid:4 /limit 16",
    "!threads pid:4", "!token pid:4", "!callbacks", "!idt", "!dpc", "!nmi", "!etw", "!hive",
    "!alpc", "!fwtable", "!driver", "!minifilter", "!unloaded", "!module", "!drvobj disk",
    "ln nt!KeBugCheckEx", "x nt!Ps*Notify*", "lm",
]
PARTIAL = ["!ssdt", "!timer", "!hal", "!piddb", "!cihash", "!mapper", "stack 4"]


def objects(text, prefix):
    result = []
    for line in text.splitlines():
        start = line.find(prefix)
        if start >= 0:
            try:
                result.append(json.loads(line[start:]))
            except json.JSONDecodeError:
                pass
    return result


def number(text):
    return int(text.replace("`", ""), 16)


class DumpSession:
    def __init__(self, args):
        self.log = args.evidence / "cdb.log"
        self.output = self.log.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            [str(args.cdb.resolve()), "-z", str(args.dump.resolve()), "-y", args.symbols,
             "-c", f'.load "{args.dll.resolve().as_posix()}"; .echo SYMBOL_AUDIT_READY'],
            stdin=subprocess.PIPE, stdout=self.output, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)

    def send(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def read(self):
        if self.log.stat().st_size > 128 * 1024 * 1024:
            raise RuntimeError("Evidence output exceeded its byte budget")
        return re.sub(r"(?m)^(?:\d+:[ \t]*kd>[ \t]*)+", "", self.log.read_text(encoding="utf-8", errors="replace"))

    def wait(self, predicate, timeout=90):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = predicate(self.read())
            if result:
                return result
            if self.process.poll() is not None:
                raise RuntimeError("Debugger exited before the audit completed")
            time.sleep(0.1)
        raise TimeoutError("Debugger operation exceeded its time budget")

    def job(self, command):
        start = len(self.read())
        self.send("!kndbgx submit " + command)

        def submitted(text):
            response = text[start:]
            if "Invalid or recursive job command" in response:
                raise RuntimeError("Command cannot be submitted as a job: " + command)
            return re.search(r"\[job\] ([0-9a-f]{32})", response)

        match = self.wait(submitted)
        job_id = match.group(1)
        end = time.monotonic() + 90
        while time.monotonic() < end:
            self.send("!kndbgx job " + job_id)
            time.sleep(0.2)
            candidates = [item for item in objects(self.read()[start:], '{"jobId":')
                          if item.get("jobId") == job_id and "result" in item]
            if candidates:
                return candidates[-1]
            if self.process.poll() is not None:
                raise RuntimeError("Debugger exited during job execution")
        raise TimeoutError("Job did not complete: " + command)

    def rows(self, job):
        rows = []
        offset = 0
        for _ in range(512):
            start = len(self.read())
            self.send(f'!kndbgx result-read {job["resultId"]} {offset}')
            pages = self.wait(lambda text: objects(text[start:], '{"Schema":'))
            if len(pages) != 1:
                raise RuntimeError("Result paging failed or was truncated")
            page = pages[0]
            if page["ResultId"] != job["resultId"] or int(page["Offset"]) != offset:
                raise RuntimeError("Wrong result page")
            rows.extend(page["Rows"])
            if page["PageComplete"]:
                if len(rows) != int(page["RowCount"]):
                    raise RuntimeError("Result row count mismatch")
                return rows
            next_offset = int(page["Next"])
            if next_offset <= offset:
                raise RuntimeError("Result paging did not advance")
            offset = next_offset
        raise RuntimeError("Result exceeded the page budget")

    def close(self):
        if self.process.poll() is None:
            try:
                self.send("q")
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdin.close()
        self.output.close()


def raw_oracle(session, results, directory):
    profile = "NT-26100.8655-symbols-PDB-11D7FE79-age1"
    for command in ("!nmi", "!fwtable", "!unloaded"):
        if results[command]["result"]["provenance"]["layoutProfile"] != profile:
            raise RuntimeError("The raw oracle requires the exact reviewed NT profile")
    commands = [
        'r @$t0 = poi(nt!KiNmiCallbackListHead); r @$t1 = 0; .while (@$t0 != 0) { '
        '.if (@$t1 >= 0x100) { .break }; .printf "NMI_ORACLE %p %p\\n", @$t0, poi(@$t0+8); '
        'r @$t0 = poi(@$t0); r @$t1 = @$t1 + 1 }; .printf "NMI_END %p\\n", @$t0',
        'r @$t0 = poi(nt!ExpFirmwareTableProviderListHead); r @$t1 = 0; '
        '.while (@$t0 != nt!ExpFirmwareTableProviderListHead) { .if (@$t1 >= 0x100) { .break }; '
        '.printf "FW_ORACLE %p %p %x\\n", @$t0, poi(@$t0-0x10), dwo(@$t0-0x18); '
        'r @$t0 = poi(@$t0); r @$t1 = @$t1+1 }; '
        '.printf "FW_END %p %p\\n", @$t0, nt!ExpFirmwareTableProviderListHead',
        '.for (r @$t1=0; @$t1<0x32; r @$t1=@$t1+1) { r @$t0=poi(nt!MmUnloadedDrivers)+@$t1*0x28; '
        '.if (wo(@$t0) != 0) { .printf "UNLOAD_ORACLE %p %p %p %p\\n", @$t0, poi(@$t0+0x10), '
        'poi(@$t0+0x18), poi(@$t0+0x20) } }',
        'r @$t2=poi(nt!PspHostSiloGlobals+0x340); '
        '.for (r @$t1=0; @$t1<dwo(@$t2+0x10); r @$t1=@$t1+1) { '
        '.if (@$t1>=0x1000) { .break }; r @$t0=poi(poi(@$t2+0x2c8)+@$t1*8); '
        '.if (@$t0!=0) { .if (@$t0!=1) { '
        '.printf "ETW_ORACLE %p %x %p\\n", @$t0, dwo(@$t0), poi(@$t0+0x18) } } }',
    ]
    vad_rows = results["!vad pid:4 /limit 16"]["rows"]
    for row in vad_rows:
        index = int(row["protectionIndex"])
        if not 0 <= index < 32:
            raise RuntimeError("VAD protection index outside reviewed table")
        commands.append(f'.printf "VAD_ORACLE %p %x\\n", {row["object"]}, dwo(nt!MmProtectToValue+{index * 4:#x})')
    port_rows = results["!alpc"]["rows"]
    for row in port_rows:
        address = row["address"]
        commands.append(f'r @$t0=poi({address}+0x10); .if (@$t0 != 0) {{ '
                        f'.printf "ALPC_ORACLE %p %p\\n", {address}, poi(@$t0) }} .else {{ '
                        f'.printf "ALPC_ORACLE %p %p\\n", {address}, 0 }}')
    commands.append(".echo SYMBOL_ORACLE_DONE")
    (directory / "oracle.txt").write_text("\n".join(commands) + "\n", encoding="ascii")
    start = len(session.read())
    # Separate commands preserve progress if an individual debugger expression fails.
    for command in commands:
        session.send(command)
    text = session.wait(lambda text: text[start:] if re.search(r"^SYMBOL_ORACLE_DONE\s*$", text[start:], re.M) else None)
    patterns = {
        "nmi": ("NMI_ORACLE", "!nmi", ("slot", "routine")),
        "firmware": ("FW_ORACLE", "!fwtable", ("slot", "routine", "signature")),
        "unloaded": ("UNLOAD_ORACLE", "!unloaded", ("record", "StartAddress", "EndAddress", "CurrentTime")),
        "etw": ("ETW_ORACLE", "!etw", ("object", "loggerId", "rawClock")),
        "vad": ("VAD_ORACLE", "!vad pid:4 /limit 16", ("object", "pageProtection")),
        "alpc": ("ALPC_ORACLE", "!alpc", ("address", "connectionPort")),
    }
    counts = {}
    for name, (prefix, command, fields) in patterns.items():
        observed = [tuple(number(value) for value in match)
                    for match in re.findall("^" + prefix + " " + " ".join([r"([0-9a-f`]+)"] * len(fields)) + "$", text, re.M)]
        expected = [tuple(int(row[field], 10 if field == "loggerId" else 16) for field in fields)
                    for row in results[command]["rows"]]
        if not expected or len(set(expected)) != len(expected) or sorted(observed) != sorted(expected):
            raise RuntimeError("Raw memory comparison failed: " + name)
        counts[name] = len(expected)
    nmi_end = re.findall(r"^NMI_END ([0-9a-f`]+)$", text, re.M)
    fw_end = re.findall(r"^FW_END ([0-9a-f`]+) ([0-9a-f`]+)$", text, re.M)
    if len(nmi_end) != 1 or number(nmi_end[0]) != 0 or len(fw_end) != 1 or fw_end[0][0] != fw_end[0][1]:
        raise RuntimeError("Raw list traversal did not terminate at its sentinel")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cdb", "dll", "dump", "evidence"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--symbols", required=True)
    args = parser.parse_args()
    for path in (args.cdb, args.dll, args.dump):
        if not path.is_file():
            parser.error("File unavailable: " + str(path))
    args.evidence.mkdir(parents=True, exist_ok=False)
    session = DumpSession(args)
    results = {}
    try:
        session.wait(lambda text: re.search(r"^SYMBOL_AUDIT_READY\s*$", text, re.M))
        for command in SUCCESS + PARTIAL:
            job = session.job(command)
            job["rows"] = session.rows(job)
            results[command] = job
            expected = "Success" if command in SUCCESS else "Partial"
            coverage = job["result"]["coverage"]
            if job["state"] != expected or bool(coverage["complete"]) != (expected == "Success"):
                raise RuntimeError(f"Unexpected coverage for {command}: {job['state']} {coverage}")
            if expected == "Success" and (int(coverage["unknownEntries"]) or int(coverage["unreadableEntries"])):
                raise RuntimeError("Successful result includes unknown or unreadable entries: " + command)
            (args.evidence / f"{len(results):02}-result.json").write_text(json.dumps(job, indent=2) + "\n", encoding="utf-8")
            print(command, job["state"], "rows=" + str(len(job["rows"])), flush=True)
        counts = raw_oracle(session, results, args.evidence)
        if "Exception in debugger client" in session.read():
            raise RuntimeError("Debugger callback exception")
        validation = {"dumpBytes": args.dump.stat().st_size, "dllSha256": hashlib.sha256(args.dll.read_bytes()).hexdigest(),
                      "coldTypeQuery": "Success", "commands": len(results), "rawComparisons": counts,
                      "results": {command: {"state": job["state"], "rows": len(job["rows"]), "coverage": job["result"]["coverage"]}
                                  for command, job in results.items()}}
        (args.evidence / "validation.json").write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"commands": len(results), "rawComparisons": counts}), flush=True)
    finally:
        session.close()


if __name__ == "__main__":
    main()
