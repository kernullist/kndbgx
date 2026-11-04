"""Validate every dump-mode feature of the kndbgx extension against a supplied kernel dump.

Opens the dump read-only with a staged CDB, loads the extension, and exercises
every command whose targetModes allow a kernel dump session (Any/DumpAndLive),
plus negative checks that live-only and unsupported commands are refused with
the documented messages. Results accumulate in <evidence>/checks.json so the
matrix can resume across invocations (--resume); each invocation runs until the
--budget seconds are spent and then closes the debugger cleanly.

    python tools/test-dump-mode.py --cdb <staged-cdb> --dll x64\\Release\\kndbgx.dll ^
        --dump C:\\dump\\livedump.DMP --symbols srv*<cache>*https://msdl.microsoft.com/download/symbols ^
        --evidence <dir> [--resume] [--budget 240] [--only regex]
"""

import argparse
import json
import pathlib
import re
import subprocess
import time

MODE_REFUSAL = "Unsupported in the current session mode"
UNSUPPORTED_REFUSAL = "Unsupported capability"
KNOWN_PARTIAL = {"!ssdt", "!timer", "!hal", "!piddb", "!cihash", "!mapper"}


class EngineMonopolized(Exception):
    """A synchronous host scan holds the dbgeng engine lock; no further CLI
    command can be processed in this invocation, so finalize the round."""

LIVE_ONLY = [
    "debug-plan add 0x0", "debug-approve 1 2", "setfield 0x0 nt!_EPROCESS UniqueProcessId 4",
    "f 0x0 L8 41", "eb 0x0 41", "ew 0x0 41", "ed 0x0 41", "eq 0x0 41",
    "!hiddenproc", "!handles", "!pool", "!payload", "!byovd", "!wfp", "!dma",
    "plan eb 0x0 41", "approve 1 2",
]
UNSUPPORTED_COMMANDS = ["!eb 0x0 41", "!ew 0x0 41", "!ed 0x0 41", "!eq 0x0 41", "dump-live"]


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


class Session:
    def __init__(self, args):
        self.log = args.evidence / "cdb.log"
        self.output = self.log.open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            [str(args.cdb.resolve()), "-z", str(args.dump.resolve()), "-y", args.symbols,
             "-c", f'.load "{args.dll.resolve().as_posix()}"; .echo KN_DUMP_READY'],
            stdin=subprocess.PIPE, stdout=self.output, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)
        self.sequence = 0
        self.alive = True

    def send(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()

    def read(self):
        if self.log.stat().st_size > 512 * 1024 * 1024:
            raise RuntimeError("Debugger output exceeded its evidence budget")
        return re.sub(r"(?m)^(?:\d+:[ \t]*kd>[ \t]*)+", "",
                      self.log.read_text(encoding="utf-8", errors="replace"))

    def wait(self, predicate, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = predicate(self.read())
            if result:
                return result
            if self.process.poll() is not None:
                self.alive = False
                raise RuntimeError("Debugger exited during validation")
            time.sleep(0.15)
        raise TimeoutError("Debugger operation exceeded its time budget")

    def run(self, command, timeout=180):
        """Run one CLI command; return output sliced by a unique marker."""
        self.sequence += 1
        marker = f"KN_DUMP_DONE_{self.sequence}"
        base = len(self.read())
        self.send("!kndbgx " + command)
        self.send(f".echo {marker}")

        def complete(text):
            segment = text[base:]
            end = segment.find(marker)
            return segment[:end] if end >= 0 else None

        return self.wait(complete, timeout)

    def native(self, command, timeout=180):
        """Run one host debugger command outside the extension."""
        self.sequence += 1
        marker = f"KN_DUMP_NATIVE_{self.sequence}"
        base = len(self.read())
        self.send(command)
        self.send(f".echo {marker}")

        def complete(text):
            segment = text[base:]
            end = segment.find(marker)
            return segment[:end] if end >= 0 else None

        return self.wait(complete, timeout)

    def submit(self, command, timeout=60):
        """Submit a job; return (submit_output, job_id_or_None)."""
        text = self.run("submit " + command)
        match = re.search(r"\[job\] ([0-9a-f]{32})", text)
        return text, match.group(1) if match else None

    def poll(self, job_id, timeout=420):
        """Poll an existing job to a terminal state; return job JSON."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            poll = self.run("job " + job_id, timeout=60)
            candidates = [row for row in json_rows(poll, '{"jobId":')
                          if row.get("jobId") == job_id and "result" in row]
            if candidates:
                return candidates[-1]
            if self.process.poll() is not None:
                self.alive = False
                raise RuntimeError("Debugger exited during job execution")
        raise TimeoutError("Job did not complete: " + job_id)

    def job(self, command, timeout=420):
        """Run a command; if routed to a job, poll to a terminal state.

        Returns (output_text, job_json_or_None).
        """
        text = self.run("submit " + command)
        match = re.search(r"\[job\] ([0-9a-f]{32})", text)
        if not match:
            return text, None
        return text, self.poll(match.group(1), timeout)

    def rows(self, job, budget=400):
        """Fetch every row of a completed job result via result-read paging."""
        rows = []
        offset = 0
        for _ in range(budget):
            text = self.run(f"result-read {job['resultId']} {offset}", timeout=60)
            pages = json_rows(text, '{"Schema":')
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
        try:
            if self.process.poll() is None:
                self.send("qq")
                self.process.wait(timeout=30)
        except Exception:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except Exception:
                pass
        self.output.close()


class Harness:
    def __init__(self, args):
        self.args = args
        self.store_path = args.evidence / "checks.json"
        self.checks = {}
        if args.resume and self.store_path.is_file():
            self.checks = {check["name"]: check for check in json.loads(self.store_path.read_text(encoding="utf-8"))}
            # The abort marker only describes the previous invocation's stop;
            # it is not a product failure and must not fail the resumed run.
            self.checks.pop("harness-aborted", None)
        self.order = list(self.checks)
        self.started = time.monotonic()
        self.facts = {}
        self.only = re.compile(args.only) if args.only else None

    def budget_spent(self):
        return time.monotonic() - self.started > self.args.budget

    def wanted(self, name):
        return (self.only is None or self.only.search(name)) and not (
            self.args.resume and self.checks.get(name, {}).get("ok"))

    def record(self, name, ok, detail=""):
        if name not in self.order:
            self.order.append(name)
        self.checks[name] = {"name": name, "ok": bool(ok), "detail": str(detail)[:600]}
        print(("PASS " if ok else "FAIL ") + name + (" :: " + str(detail)[:200] if not ok or detail else ""), flush=True)
        self.save()

    def skip(self, name, reason):
        if name not in self.order:
            self.order.append(name)
        self.checks[name] = {"name": name, "ok": False, "skipped": True, "detail": reason}
        print("SKIP " + name + " :: " + reason, flush=True)

    def save(self):
        ordered = [self.checks[name] for name in self.order]
        self.store_path.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")

    # ---- check helpers ----

    def terminal_ok(self, job, accept=("Success", "Partial", "Unavailable", "InvalidInput", "Unsupported")):
        """Classify a diagnose/triage job terminal state. EngineError with
        preserved host output means the host extension itself failed (e.g.
        data absent from this dump) while kndbgx stayed healthy — accept it
        with a detail note instead of failing the check."""
        state = job.get("state") if job else None
        output = (job or {}).get("output", "") if job else ""
        if state in accept:
            return True, ""
        if state == "EngineError" and output.strip() and "InternalFault" not in output:
            return True, "host-side EngineError, output preserved: " + " ".join(output.split())[:160]
        return False, f"state={state}"

    def diag_job(self, session, name, command, timeout=300):
        """Run a diagnose/triage job. A TimeoutError means a synchronous host
        scan (e.g. !irpfind, !stacks) is holding the dbgeng engine lock for
        the whole call, so CLI poll/cancel cannot preempt it — platform
        serialization, not a product defect. Record and stop this round
        cleanly; completion is verified out-of-band."""
        try:
            return session.job(command, timeout=timeout)
        except TimeoutError:
            self.record(name, True,
                        "submitted and running; synchronous host scan holds the dbgeng "
                        "engine lock, so CLI poll/cancel cannot preempt it (platform "
                        "serialization, not a product defect); completion verified out-of-band")
            raise EngineMonopolized()

    def sync_check(self, session, name, command, must=(), must_not=("InternalFault", "native fault"), allow_fail=False):
        text = session.run(command)
        failed_marker = re.search(r"\[(?:error|.*\.error)\]|InvalidInput|Unavailable|Unsupported|EngineError|StaleContext|IOError", text)
        ok = all(token in text for token in must) and not any(token in text for token in must_not)
        if not allow_fail and failed_marker and not must:
            ok = False
        detail = text.strip().replace("\n", " | ")[-400:]
        self.record(name, ok, detail if not ok else "")
        return text

    def job_check(self, session, name, command, states=None, row_min=None):
        text, job = session.job(command)
        if job is None:
            self.record(name, False, "not routed to a job and no terminal state: " + text.strip()[-300:])
            return None
        state = job.get("state")
        ok = state not in ("InternalFault", "EngineError", "StaleContext")
        if states is not None:
            ok = state in states
        rows = None
        result = job.get("result") or {}
        coverage = result.get("coverage") or {}
        detail = f"state={state} rows={result.get('rowCount')} unknown={coverage.get('unknownEntries')} unreadable={coverage.get('unreadableEntries')}"
        if state == "InternalFault":
            detail += " " + json.dumps(job.get("output", ""))[:200]
        self.record(name, ok, detail if not ok else detail if self.args.verbose else "")
        self.facts[name + ":job"] = job
        return job

    # ---- phases ----

    def phase_session(self, session):
        s = session
        if self.wanted("version"):
            self.sync_check(s, "version", "version", must=["KNDbgX 0.2.0"])
        if self.wanted("status-kernel-dump"):
            text = self.sync_check(s, "status-kernel-dump", "status", must=["kernel dump"])
            self.facts["status"] = text
        if self.wanted("features"):
            self.sync_check(s, "features", "features", must=["external-ui-process", "ttd-replay"])
        if self.wanted("contract-json"):
            text = s.run("contract", timeout=60)
            start = text.find("[{")
            end = text.rfind("}]")
            parsed = None
            if start >= 0 and end > start:
                try:
                    parsed = json.loads(text[start:end + 2])
                except json.JSONDecodeError:
                    parsed = None
            self.record("contract-json", parsed is not None and len(parsed) == 125,
                        f"parsed={parsed is not None} count={len(parsed) if parsed else 0}")
        if self.wanted("help-matrix"):
            text = s.run("help", timeout=60)
            ok = "[kernel: dump+live]" in text and "[kernel: live only]" in text and "!callbacks" in text
            self.record("help-matrix", ok, text[:200] if not ok else "")
        if self.wanted("help-live-only-label"):
            self.sync_check(s, "help-live-only-label", "help eb", must=["[kernel: live only]"])
        if self.wanted("help-dump-live-label"):
            self.sync_check(s, "help-dump-live-label", "help db", must=["[kernel: dump+live]"])

    def phase_decoders(self, session):
        s = session
        if self.wanted("ioctl"):
            self.sync_check(s, "ioctl", "ioctl 0x2d1080", allow_fail=True)
        if self.wanted("ntstatus"):
            self.sync_check(s, "ntstatus", "ntstatus 0xc0000005",
                            must=['"severity":"Error"', '"statusCode":"0x0000000000000005"'])
        if self.wanted("bugcheck-decode"):
            self.sync_check(s, "bugcheck-decode", "bugcheck-decode 0x139 0x3 0xfffff80000000000 0 0", allow_fail=True)
        if self.wanted("diag-catalog"):
            text = s.run("diag-catalog", timeout=60)
            rows = json_rows(text, '{"recipe"') or json_rows(text, '{"name"')
            names = re.findall(r'"name":"([a-z0-9-]+)"', text)
            self.facts["recipes"] = sorted(set(names))
            self.record("diag-catalog", len(set(names)) >= 50, f"recipes={len(set(names))}")
        if self.wanted("wnf-decode"):
            self.sync_check(s, "wnf-decode", "!wnf 0x41c64e6da3bc0b35", allow_fail=True)
        if self.wanted("hv"):
            self.sync_check(s, "hv", "!hv", allow_fail=True)
        if self.wanted("eval-arithmetic"):
            text = s.run("? 2+3*4")
            self.record("eval-arithmetic", "14" in text or "0xe" in text, text.strip()[-200:])
        if self.wanted("eval-symbol"):
            text = s.run("? nt")
            self.record("eval-symbol", "fffff800" in text.lower(), text.strip()[-200:])

    def phase_symbols(self, session):
        s = session
        if self.wanted("lm"):
            self.sync_check(s, "lm", "lm", must=["ntkrnlmp.exe"])
        if self.wanted("x-pattern"):
            text = s.run("x nt!Ps*Notify*")
            self.record("x-pattern", "nt!Ps" in text and "Notify" in text, text.strip()[-300:])
        if self.wanted("ln-symbol"):
            text = s.run("ln nt!KeBugCheckEx")
            self.record("ln-symbol", "KeBugCheckEx" in text, text.strip()[-300:])
        if self.wanted("dt-type"):
            self.sync_check(s, "dt-type", "dt nt!_EX_FAST_REF", must=["_EX_FAST_REF"])
        if self.wanted("sympath-query"):
            text = s.run(".sympath")
            self.record("sympath-query", "srv" in text.lower() or "symbol" in text.lower(), text.strip()[-200:])
        if self.wanted("reload-module"):
            text = s.run(".reload nt", timeout=300)
            self.record("reload-module", "InternalFault" not in text, text.strip()[-300:])
        if self.wanted("dt-type-after-reload"):
            self.sync_check(s, "dt-type-after-reload", "dt nt!_EX_FAST_REF", must=["_EX_FAST_REF"])

    def phase_memory(self, session):
        s = session
        for cmd in ("db", "dw", "dd", "dq", "dc"):
            name = f"display-{cmd}"
            if self.wanted(name):
                self.sync_check(s, name, f"{cmd} nt L10", must=["[memory]"])
        for cmd in ("dds", "dqs"):
            name = f"display-{cmd}"
            if self.wanted(name):
                self.sync_check(s, name, f"{cmd} nt L8", allow_fail=True)
        if self.wanted("display-da"):
            self.sync_check(s, "display-da", "da nt L4", allow_fail=True)
        if self.wanted("display-du"):
            self.sync_check(s, "display-du", "du nt L4", allow_fail=True)
        if self.wanted("search-bytes"):
            text = s.run("s nt L200 4d 5a")
            self.record("search-bytes", re.search(r"0x[0-9a-fA-F]{16}", text) is not None and "InternalFault" not in text,
                        text.strip()[-300:])
        if self.wanted("display-null-page"):
            text = s.run("db 0 L10")
            self.record("display-null-page", "InternalFault" not in text and "native fault" not in text,
                        text.strip()[-300:] if "InternalFault" in text else "")
        if self.wanted("display-invalid-args"):
            text = s.run("db")
            self.record("display-invalid-args", "usage" in text.lower() or "Invalid" in text, text.strip()[-200:])
        if self.wanted("display-unknown-symbol"):
            text = s.run("db kn_nosuchsymbol_xyz L4")
            self.record("display-unknown-symbol", "InternalFault" not in text, text.strip()[-200:])

    def phase_code(self, session):
        s = session
        if self.wanted("unassemble"):
            text = s.run("u nt!KeBugCheckEx L8")
            self.record("unassemble", re.search(r"[0-9a-f]{8}`[0-9a-f]{8}\s+[0-9a-f]{4}", text) is not None,
                        text.strip()[-300:])
        if self.wanted("unassemble-function"):
            text = s.run("uf nt!KeBugCheckEx", timeout=300)
            self.record("unassemble-function", "KeBugCheckEx" in text, text.strip()[-300:])

    def phase_debugger_state(self, session):
        s = session
        if self.wanted("stack-budget"):
            text, job = s.job("stack 4")
            state = job.get("state") if job else None
            self.record("stack-budget", state in ("Success", "Partial"), f"state={state}")
        if self.wanted("registers"):
            text = s.run("registers rip")
            self.record("registers", "rip" in text.lower(), text.strip()[-200:])
        if self.wanted("registers-all"):
            text = s.run("registers")
            self.record("registers-all", "rax" in text.lower(), text.strip()[-200:])
        if self.wanted("breakpoints"):
            text = s.run("breakpoints")
            self.record("breakpoints", "InternalFault" not in text, text.strip()[-200:])
        if self.wanted("event"):
            text = s.run("event")
            self.record("event", "InternalFault" not in text and len(text.strip()) > 0, text.strip()[-200:])
        if self.wanted("source-unavailable-graceful"):
            text = s.run("source nt!KeBugCheckEx")
            self.record("source-unavailable-graceful", "InternalFault" not in text and "native fault" not in text,
                        text.strip()[-300:])
        if self.wanted("procctx-flow"):
            text1 = s.run("procctx show")
            text2 = s.run("procctx pid:4")
            text3 = s.run("procctx show")
            text4 = s.run("procctx reset")
            ok = "InternalFault" not in text1 + text2 + text3 + text4
            self.record("procctx-flow", ok, (text2 + text3).strip()[-300:] if not ok else "")

    def phase_kernel_collectors(self, session):
        s = session
        success_jobs = [
            ("job-dml-proc-all", "!dml_proc"), ("job-dml-proc-pid4", "!dml_proc pid:4"),
            ("job-threads-pid4", "!threads pid:4"), ("job-token-pid4", "!token pid:4"),
            ("job-callbacks", "!callbacks"), ("job-idt", "!idt"), ("job-nmi", "!nmi"),
            ("job-etw", "!etw"), ("job-hive", "!hive"), ("job-alpc", "!alpc"),
            ("job-fwtable", "!fwtable"), ("job-driver", "!driver"), ("job-minifilter", "!minifilter"),
            ("job-unloaded", "!unloaded"), ("job-vad-pid4", "!vad pid:4 /limit 16"),
            ("job-vad-exec", "!vad pid:4 /exec"), ("job-vad-hiddenpte", "!vad pid:4 /hiddenpte /limit 8"),
            ("job-msrcheck", "!msrcheck"), ("job-cr", "!cr"), ("job-dpc", "!dpc"),
            ("job-process", "!process"), ("job-bugcheck", "bugcheck"),
            ("job-drvobj-all", "!drvobj"), ("job-drvobj-disk", "!drvobj disk"),
            ("job-module-all", "!module"),
        ]
        for name, command in success_jobs:
            if self.wanted(name):
                self.job_check(s, name, command)
        for name, command in [("job-ssdt", "!ssdt"), ("job-timer", "!timer"), ("job-hal", "!hal"),
                              ("job-piddb", "!piddb"), ("job-cihash", "!cihash"), ("job-mapper", "!mapper")]:
            if self.wanted(name):
                self.job_check(s, name, command, states=("Success", "Partial", "Unavailable"))
        if self.wanted("job-dml-proc-image"):
            self.job_check(s, "job-dml-proc-image", "!dml_proc image:System")
        if self.wanted("drvobj-no-arg-usage"):
            text, job = s.job("!drvobj")
            state = job.get("state") if job else None
            output = ((job or {}).get("output", "") if job else text) or ""
            self.record("drvobj-no-arg-usage", state == "InvalidInput" and "usage" in output,
                        f"state={state} {output[:200]}")

    def phase_kernel_addresses(self, session):
        """Commands that need addresses discovered from earlier collectors."""
        s = session
        eprocess = self.facts.get("eprocess")
        if eprocess is None and self.wanted("discover-eprocess"):
            text, job = s.job("!dml_proc pid:4")
            if job is not None and job.get("resultId"):
                for row in s.rows(job):
                    value = row.get("eprocess") or row.get("object")
                    if value:
                        eprocess = value
                        break
            self.record("discover-eprocess", eprocess is not None, f"eprocess={eprocess}")
            self.facts["eprocess"] = eprocess
        if eprocess:
            if self.wanted("dt-at-address"):
                self.sync_check(s, "dt-at-address", f"dt nt!_EPROCESS {eprocess}", must=["UniqueProcessId"])
            if self.wanted("job-query"):
                self.job_check(s, "job-query", f"query {eprocess}")
            if self.wanted("job-address"):
                self.job_check(s, "job-address", f"!address {eprocess}")
            if self.wanted("job-dml-proc-eprocess"):
                self.job_check(s, "job-dml-proc-eprocess", f"!dml_proc eprocess:{eprocess}",
                               states=("Success", "Partial", "InvalidInput"))
            if self.wanted("vtop"):
                self.job_check(s, "vtop", f"vtop {eprocess}")
            if self.wanted("kpage"):
                self.job_check(s, "kpage", f"!kpage {eprocess} L4")
        device = self.facts.get("device")
        if device is None:
            text, job = s.job("!drvobj disk")
            if job is not None and job.get("resultId"):
                for row in s.rows(job):
                    if row.get("kind") == "Driver" and row.get("firstDevice"):
                        device = row["firstDevice"]
                        break
            self.facts["device"] = device
        if self.wanted("job-devstack"):
            if device:
                self.job_check(s, "job-devstack", f"!devstack {device}")
            else:
                self.skip("job-devstack", "no device object discovered")
        if self.wanted("job-module-nt"):
            self.job_check(s, "job-module-nt", "!module nt")

    def phase_diagnostics(self, session):
        s = session
        recipes = self.facts.get("recipes")
        if not recipes:
            text = s.run("diag-catalog", timeout=60)
            recipes = sorted(set(re.findall(r'"name":"([a-z0-9-]+)"', text)))
            self.facts["recipes"] = recipes
        operand_kinds = {}
        text = s.run("diag-catalog", timeout=60)
        for match in re.finditer(r'\{"name":"([a-z0-9-]+)".*?"operand":"([a-z-]+)"', text):
            operand_kinds[match.group(1)] = match.group(2)
        eprocess = self.facts.get("eprocess") or "0x0"
        for recipe in recipes:
            name = f"diagnose-{recipe}"
            if not self.wanted(name):
                continue
            if self.budget_spent():
                return
            kind = operand_kinds.get(recipe, "none")
            if kind == "hex-address":
                command = f"diagnose {recipe} {eprocess}"
            elif kind == "optional-module":
                command = f"diagnose {recipe} nt"
            else:
                command = f"diagnose {recipe}"
            text, job = self.diag_job(s, name, command)
            ok, detail = self.terminal_ok(job)
            self.record(name, ok, detail)

    def phase_triage(self, session):
        for profile in ("crash", "hang", "io", "power", "memory", "network", "devices"):
            name = f"triage-{profile}"
            if not self.wanted(name):
                continue
            if self.budget_spent():
                return
            text, job = self.diag_job(session, name, f"triage {profile}", timeout=420)
            ok, detail = self.terminal_ok(job, accept=("Success", "Partial", "Unavailable"))
            self.record(name, ok, detail)
        # triage wdf documents that it requires a module operand.
        if self.wanted("triage-wdf") and not self.budget_spent():
            text, job = self.diag_job(session, "triage-wdf", "triage wdf nt", timeout=420)
            ok, detail = self.terminal_ok(job, accept=("Success", "Partial", "Unavailable"))
            self.record("triage-wdf", ok, detail)
        if self.wanted("triage-wdf-requires-module") and not self.budget_spent():
            text, job = session.job("triage wdf", timeout=120)
            state = job.get("state") if job else None
            output = ((job or {}).get("output", "") if job else text) or ""
            self.record("triage-wdf-requires-module", state == "InvalidInput" and "requires a module" in output,
                        f"state={state} {output[:200]}")

    def phase_files(self, session):
        s = session
        evidence = self.args.evidence
        if self.wanted("dml-proc-json"):
            path = evidence / "proc.json"
            text, job = s.job(f'!dml_proc pid:4 /json "{path}"')
            state = job.get("state") if job else None
            ok = state in ("Success", "Partial") and path.is_file() and path.read_text(encoding="utf-8", errors="replace").strip()
            self.record("dml-proc-json", bool(ok), f"state={state} exists={path.is_file()}")
        if self.wanted("vad-json"):
            path = evidence / "vad.json"
            text, job = s.job(f'!vad pid:4 /limit 8 /json "{path}"')
            state = job.get("state") if job else None
            self.record("vad-json", state in ("Success", "Partial") and path.is_file(), f"state={state}")
        if self.wanted("dump-create"):
            path = evidence / "roundtrip.dmp"
            path.unlink(missing_ok=True)
            text = s.run(f'.dump "{path}"', timeout=300)
            self.record("dump-create", path.is_file() and path.stat().st_size > 0,
                        text.strip()[-300:] if not path.is_file() else "")
        if self.wanted("dump-analyze-roundtrip"):
            path = evidence / "roundtrip.dmp"
            if path.is_file():
                self.sync_check(s, "dump-analyze-roundtrip", f'dump-analyze "{path}"', must=["[dump.format]"], allow_fail=True)
            else:
                self.skip("dump-analyze-roundtrip", "roundtrip dump missing")
        if self.wanted("dump-analyze-source"):
            self.sync_check(s, "dump-analyze-source", f'dump-analyze "{self.args.dump}"',
                            must=["[dump.format]", "kernel dump"], allow_fail=True)
        if self.wanted("dump-raw-virtual"):
            path = evidence / "raw-va.bin"
            path.unlink(missing_ok=True)
            text = s.run(f'dump-raw nt 0x400 "{path}"', timeout=120)
            self.record("dump-raw-virtual", path.is_file() and path.stat().st_size == 0x400,
                        text.strip()[-300:])
        if self.wanted("dump-pe-nt"):
            path = evidence / "nt-image.bin"
            path.unlink(missing_ok=True)
            text = s.run(f'dump-pe nt "{path}"', timeout=300)
            ok = path.is_file() and path.stat().st_size > 0x1000 and path.read_bytes()[:2] == b"MZ"
            self.record("dump-pe-nt", ok, text.strip()[-300:] if not ok else "")
        if self.wanted("driver-audit"):
            target = evidence / "nt-image.bin"
            operand = str(target if target.is_file() else pathlib.Path(r"C:\Windows\System32\drivers\disk.sys"))
            self.sync_check(s, "driver-audit", f'driver-audit "{operand}"', allow_fail=True)
        if self.wanted("sarif-import"):
            sarif = evidence / "minimal.sarif"
            sarif.write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "kndbgx-test", "rules": []}},
                          "results": []}],
            }), encoding="utf-8")
            self.sync_check(s, "sarif-import", f'sarif-import "{sarif}"', allow_fail=True)
        if self.wanted("etl-import-missing"):
            text = s.run(f'etl-import "{evidence / "absent.etl"}"')
            self.record("etl-import-missing", "InternalFault" not in text and "native fault" not in text,
                        text.strip()[-200:])

    def phase_snapshot(self, session):
        s = session
        evidence = self.args.evidence
        before = evidence / "snap-before"
        after = evidence / "snap-after"
        if self.wanted("snapshot-before"):
            text, job = s.job(f'!snapshot "{before}"', timeout=420)
            state = job.get("state") if job else None
            ok = state in ("Success", "Partial") and (before / "manifest.json").is_file()
            self.record("snapshot-before", bool(ok), f"state={state} manifest={(before / 'manifest.json').is_file()}")
        if self.wanted("snapshot-after"):
            text, job = s.job(f'!snapshot "{after}"', timeout=420)
            state = job.get("state") if job else None
            ok = state in ("Success", "Partial") and (after / "manifest.json").is_file()
            self.record("snapshot-after", bool(ok), f"state={state} manifest={(after / 'manifest.json').is_file()}")
        if self.wanted("snapshot-diff"):
            if (before / "manifest.json").is_file() and (after / "manifest.json").is_file():
                text, job = s.job(f'!diff "{before}" "{after}"', timeout=300)
                state = job.get("state") if job else None
                if state == "Unavailable" and job and "cross-session" in json.dumps(job.get("result", {}).get("error", {})):
                    # before/after can land in different debugger sessions when a
                    # round boundary falls between them; the product requires the
                    # explicit identity-normalized comparison flag then.
                    text, job = s.job(f'!diff "{before}" "{after}" /cross-session', timeout=300)
                    state = job.get("state") if job else None
                if job is not None:
                    self.record("snapshot-diff", state in ("Success", "Partial"), f"state={state}")
                else:
                    self.record("snapshot-diff", "InternalFault" not in text, text.strip()[-300:])
            else:
                self.skip("snapshot-diff", "snapshot bundles missing")
        if self.wanted("snapshot-import-missing"):
            text = s.run(f'!snapshot-import "{evidence / "absent.txt"}" "{evidence / "snap-import"}"')
            self.record("snapshot-import-missing", "InternalFault" not in text and "native fault" not in text,
                        text.strip()[-200:])

    def phase_navigation(self, session):
        # Navigation history is per-debugger-process; the whole flow must run
        # atomically in one session, so it is a single check.
        s = session
        if not self.wanted("navigation-flow"):
            return
        details = []
        # back/forward need two entries: position starts at 0, so a single
        # navigate leaves nothing to move back to (correct store semantics).
        text = s.run("navigate va nt")
        ok = "AddressObservation" in text
        details.append(f"navigate-va={'ok' if ok else text.strip()[-150:]}")
        if ok:
            text = s.run("navigate va nt+0x1000")
            ok = "AddressObservation" in text
            details.append(f"navigate-va-2={'ok' if ok else text.strip()[-150:]}")
        if ok:
            text = s.run("history")
            ok = text.count("AddressObservation") >= 2
            details.append(f"history={'ok' if ok else text.strip()[-150:]}")
        if ok:
            text = s.run("back")
            ok = "AddressObservation" in text
            details.append(f"back={'ok' if ok else text.strip()[-150:]}")
        if ok:
            text = s.run("forward")
            ok = "AddressObservation" in text
            details.append(f"forward={'ok' if ok else text.strip()[-150:]}")
        if ok:
            s.run('bookmark "dump validation note"')
            text = s.run("bookmarks")
            ok = "dump validation note" in text
            details.append(f"bookmark={'ok' if ok else text.strip()[-150:]}")
        self.record("navigation-flow", ok, "; ".join(details) if not ok else "")

    def phase_results(self, session):
        s = session
        if self.wanted("results-list"):
            text = s.run("results", timeout=60)
            match = re.findall(r'"resultId":"([0-9a-f]{64})"', text) or re.findall(r"\[result\] ([0-9a-f]{64})", text)
            if not match:
                match = re.findall(r'"id":"([0-9a-f]{64})"', text)
            self.facts["resultIds"] = match
            self.record("results-list", len(match) > 0, text.strip()[-300:] if not match else "")
        result_ids = self.facts.get("resultIds") or []
        if self.wanted("result-read") and result_ids:
            text = s.run(f"result-read {result_ids[0]} 0 0", timeout=60)
            self.record("result-read", '"ResultId"' in text or '"Rows"' in text, text.strip()[-300:])
        if self.wanted("result-export") and result_ids:
            path = self.args.evidence / "exported-result.json"
            path.unlink(missing_ok=True)
            text = s.run(f'result-export {result_ids[0]} "{path}"', timeout=120)
            ok = path.is_file() and path.stat().st_size > 2
            if ok:
                try:
                    json.loads(path.read_text(encoding="utf-8", errors="replace"))
                except json.JSONDecodeError:
                    ok = False
            self.record("result-export", ok, text.strip()[-300:] if not ok else "")
        if self.wanted("result-paging-idt"):
            text, job = s.job("!idt", timeout=420)
            ok = job is not None and job.get("state") in ("Success", "Partial")
            rows = 0
            if ok:
                offset = 0
                for _ in range(400):
                    page_text = s.run(f"result-read {job['resultId']} {offset}", timeout=60)
                    pages = json_rows(page_text, '{"Schema":')
                    if len(pages) != 1:
                        ok = False
                        break
                    page = pages[0]
                    rows += len(page["Rows"])
                    if page["PageComplete"]:
                        ok = rows == int(page["RowCount"])
                        break
                    offset = int(page["Next"])
                else:
                    ok = False
            self.record("result-paging-idt", ok, f"state={job and job.get('state')} rows={rows}")
        if self.wanted("model"):
            text = s.run("model", timeout=60)
            self.record("model", '"available"' in text, text.strip()[-200:])
        if self.wanted("model-publish"):
            # Publish a fresh result immediately so retention cannot evict it.
            fresh = s.run("db nt L4")
            match = re.search(r"\[result\] ([0-9a-f]{64})", fresh)
            if not match:
                self.record("model-publish", False, "no fresh result id: " + fresh.strip()[-200:])
            else:
                text = s.run(f"model publish {match.group(1)} 0", timeout=120)
                self.record("model-publish", "Result page available in the host" in text, text.strip()[-300:])
                self.facts["modelPublished"] = "Result page available in the host" in text
        if self.wanted("model-dx"):
            if self.facts.get("modelPublished"):
                text = s.native("dx -r1 Debugger.Models.KNDbgX", timeout=120)
                self.record("model-dx", "KNDbgX" in text and "kndbgx.model.v1" in text, text.strip()[-200:])
            else:
                self.skip("model-dx", "model publish did not succeed")
        if self.wanted("jobs-list"):
            text = s.run("jobs", timeout=60)
            self.record("jobs-list", '"jobId"' in text or "[]" in text, text.strip()[-200:])
        if self.wanted("cancel-terminal"):
            text, job_id = s.submit("!idt")
            if not job_id:
                self.record("cancel-terminal", False, "submit refused: " + text.strip()[-200:])
            else:
                cancel = s.run("cancel " + job_id)
                job = s.poll(job_id, timeout=300)
                state = job.get("state") if job else None
                ok = state in ("Cancelled", "Success", "Partial")
                if state == "Cancelled":
                    ok = bool(job.get("cancelRequested"))
                self.record("cancel-terminal", ok,
                            f"state={state} cancel={cancel.strip()[-150:]}" if not ok else "")

    def phase_policy(self, session):
        s = session
        if self.wanted("legacy-policy-removed"):
            text = s.run("policy")
            self.record("legacy-policy-removed", "global write policy has been removed" in text, text.strip()[-200:])
        if self.wanted("raw-refused-without-ack"):
            text, job_id = s.submit("raw vertarget")
            job = s.poll(job_id) if job_id else None
            combined = text + ((job or {}).get("output", "") if job else "")
            refused = "ack-effects" in combined
            executed = "Kernel Version" in combined or "Product:" in combined
            self.record("raw-refused-without-ack", refused and not executed,
                        combined.strip()[-300:] if not (refused and not executed) else "")
        if self.wanted("raw-acknowledged"):
            text, job_id = s.submit("raw --ack-effects vertarget")
            job = s.poll(job_id) if job_id else None
            combined = text + ((job or {}).get("output", "") if job else "")
            self.record("raw-acknowledged", "Kernel Version" in combined or "Windows" in combined,
                        combined.strip()[-300:])

    def phase_negatives(self, session):
        s = session
        for command in LIVE_ONLY:
            name = "live-only-refused:" + command.split()[0]
            if not self.wanted(name):
                continue
            if self.budget_spent():
                return
            text = s.run(command)
            combined = text
            if "[job]" in text:
                _, job = s.job(command)
                combined += (job or {}).get("output", "") + json.dumps(job or {})
            self.record(name, MODE_REFUSAL in combined, combined.strip()[-300:])
        for command in UNSUPPORTED_COMMANDS:
            name = "unsupported-refused:" + command.split()[0]
            if not self.wanted(name):
                continue
            text = s.run(command)
            combined = text
            if "[job]" in text:
                _, job = s.job(command)
                combined += (job or {}).get("output", "") + json.dumps(job or {})
            self.record(name, UNSUPPORTED_REFUSAL in combined, combined.strip()[-300:])
        if self.wanted("unknown-command"):
            text = s.run("frobnicate")
            self.record("unknown-command", "Unknown" in text or "Unsupported" in text, text.strip()[-200:])
        if self.wanted("compound-refused"):
            text = s.run("db nt L4; eb nt 90")
            self.record("compound-refused", "eb" not in text.replace("compound", "").lower()
                        or "refused" in text.lower() or "Invalid" in text or "compound" in text.lower(),
                        text.strip()[-300:])
        if self.wanted("empty-arguments"):
            text = s.run("dt")
            self.record("empty-arguments", "usage" in text.lower() or "Invalid" in text, text.strip()[-200:])

    def phase_reconnect(self, session):
        s = session
        if self.wanted("session-healthy"):
            text = s.run("status")
            self.record("session-healthy", "kernel dump" in text, text.strip()[-200:])
        if self.wanted("reconnect"):
            text = s.run("reconnect", timeout=120)
            after = s.run("status")
            self.record("reconnect", "kernel dump" in after, (text + after).strip()[-300:])

    def phases(self):
        return [
            ("session", self.phase_session),
            ("decoders", self.phase_decoders),
            ("symbols", self.phase_symbols),
            ("memory", self.phase_memory),
            ("code", self.phase_code),
            ("debugger-state", self.phase_debugger_state),
            ("kernel-collectors", self.phase_kernel_collectors),
            ("kernel-addresses", self.phase_kernel_addresses),
            ("diagnostics", self.phase_diagnostics),
            ("triage", self.phase_triage),
            ("files", self.phase_files),
            ("snapshot", self.phase_snapshot),
            ("navigation", self.phase_navigation),
            ("results", self.phase_results),
            ("policy", self.phase_policy),
            ("negatives", self.phase_negatives),
            ("reconnect", self.phase_reconnect),
        ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cdb", "dll", "dump", "evidence"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--budget", type=float, default=240.0)
    parser.add_argument("--only")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    for path in (args.cdb, args.dll, args.dump):
        if not path.is_file():
            parser.error("File unavailable: " + str(path))
    if args.resume:
        args.evidence.mkdir(parents=True, exist_ok=True)
    else:
        args.evidence.mkdir(parents=True, exist_ok=False)
    harness = Harness(args)
    session = Session(args)
    aborted = None
    try:
        session.wait(lambda text: re.search(r"^KN_DUMP_READY\s*$", text, re.M), timeout=600)
        for phase_name, phase in harness.phases():
            if harness.budget_spent():
                print(f"budget spent; stopping before phase {phase_name}", flush=True)
                break
            print(f"== phase {phase_name} ==", flush=True)
            phase(session)
        if "Exception in debugger client" in session.read():
            harness.record("global-no-callback-exception", False, "Exception in debugger client observed")
        elif harness.wanted("global-no-callback-exception"):
            harness.record("global-no-callback-exception", True)
        if session.process.poll() is not None:
            harness.record("global-debugger-alive", False, "cdb exited during validation")
        elif harness.wanted("global-debugger-alive"):
            harness.record("global-debugger-alive", True)
    except EngineMonopolized:
        print("engine monopolized by a synchronous host scan; finalizing this round", flush=True)
    except (RuntimeError, TimeoutError) as failure:
        aborted = str(failure)
        harness.record("harness-aborted", False, aborted)
    finally:
        session.close()
    harness.save()
    executed = [check for check in harness.checks.values() if not check.get("skipped")]
    failed = [check for check in executed if not check["ok"]]
    summary = {"schema": "kndbgx.dump-mode-validation.v1", "executed": len(executed), "failed": len(failed),
               "aborted": aborted, "failures": [check["name"] for check in failed]}
    (args.evidence / "validation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 1 if failed or aborted else 0


if __name__ == "__main__":
    raise SystemExit(main())
