"""Validate every live-kernel feature of the kndbgx extension against a remote
kernel-debugged VM (kd over a named pipe such as VMware's \\\\.\\pipe\\com1).

Bring-up contract (established against a VMware Workstation guest whose KD
serial port is exposed through a named pipe):

- This harness resets its guest with vmrun while kd is waiting on the pipe,
  because the previously tested running, silent guest did not reconnect.
  This is a harness lifecycle choice, not a KD protocol requirement: on
  2026-10-03, restarting WinDbgX and requesting Break reconnected to the same
  already-stopped guest without a VM reset. Existing-session validation should
  preserve that guest and try reconnecting before considering a fresh boot.
- Extension paths in kd commands must use forward slashes: kd strips
  backslashes inside quoted command arguments.
- kd is started with -b so it breaks into the kernel when the connection is
  established; without it the initial -c command never runs.
- The boot break is too early for full-system collectors, so the initial
  command chain continues with `sxe ld:<settle-module>; sxe ld:tcpip; g`
  and breaks again once a guest KERNEL module loads (user-mode module loads such
  as vmtoolsd.exe are not reported to a kernel debugger). The default
  --settle-module is vmmemctl (VMware Tools balloon driver): it loads near the
  END of boot, which the process-dependent checks require — on Windows 11
  Insider build 28000 the PsActiveProcessHead list stays zero-linked until late
  boot (verified 2026-09-25: at vmci/tcpip/disk-load breaks dq
  nt!PsActiveProcessHead reads all zeros and kd's native !process 0 0 fails
  with "NULL value in PsActiveProcess List"; at vmmemctl load the list is
  linked and enumeration works). Pick another late kernel module for other
  guests.
- The harness always resumes the target (`g`) and detaches (`qd`) on exit; the
  guest keeps running. Each new harness invocation resets the guest again
  (the checks file supports --resume rounds).

    python tools/test-live-kernel.py --kd <staged-kd> --dll x64\\Release\\kndbgx.dll ^
        --vmx <vm.vmx> --symbols srv*<cache>*https://msdl.microsoft.com/download/symbols ^
        --evidence <dir> [--resume] [--budget 1200] [--only regex]
"""

import argparse
import json
import os
import pathlib
import re
import subprocess
import time

MODE_REFUSAL = "Unsupported in the current session mode"
# LocalKernelX64 commands are refused by the dispatcher's capability gate; the
# handler-level text only appears if that gate is bypassed.
HOST_REFUSAL = "Host-local collection requires verified local kernel context"
EVIDENCE_VERSION = 9

NATIVE_CONTEXT_PROBE = "? @$thread; ? @$proc; r rip"


def native_context_signature(output):
    if "error" in output.lower():
        return None
    pointers = re.findall(r"Evaluate expression:[^\n=]*=[ \t]*(\S+)", output)
    instruction = re.findall(r"\brip=(\S+)", output)
    if len(pointers) != 2 or len(instruction) != 1:
        return None
    values = []
    for token in pointers + instruction:
        if not re.fullmatch(r"(?:[0-9a-fA-F]{1,16}|[0-9a-fA-F]{1,8}`[0-9a-fA-F]{8})", token):
            return None
        value = int(token.replace("`", ""), 16)
        # Accept both x64 address widths. RIP may be in user mode, but the
        # thread and process pseudo-registers must name aligned kernel objects.
        if value == 0 or (1 << 56) <= value < (1 << 64) - (1 << 56):
            return None
        values.append(value)
    if any(value < (1 << 64) - (1 << 56) or value % 8 for value in values[:2]):
        return None
    return tuple(values)


def equivalent_bounded_rows(left, left_job, right, right_job):
    if left == right:
        return True
    common = min(len(left), len(right))
    if common == 0 or left[:common] != right[:common]:
        return False
    shorter = left_job if len(left) < len(right) else right_job
    coverage = (shorter.get("result") or {}).get("coverage") or {}
    return (shorter.get("state") == "Partial" and coverage.get("complete") is False and
            coverage.get("stopReason") == "GlobalWalkBudget")


def has_submission_receipt(command, output):
    return command.startswith("submit ") and re.search(
        r"(?m)^(?:[^\n>]*>\s*)?\[job\] [0-9a-f]{32}\s*$", output) is not None


VMRUN = r"C:\Program Files\VMware\VMware Workstation\vmrun.exe"
# The ready marker must match its own output line: kd echoes the initial
# command chain verbatim, so an unanchored substring would match it and
# report readiness before any debugger prompt exists.
LIVE_READY_RE = re.compile(r"(?m)^KN_LIVE_READY\s*$")
LIVE_TEARDOWN_RE = re.compile(r"(?m)^KN_LIVE_TEARDOWN\s*$")


class EngineMonopolized(Exception):
    """A synchronous host scan holds the dbgeng engine lock; no further CLI
    command can be processed in this invocation, so finalize the round."""


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


def parse_diagnostic_catalog(text):
    """Extract (sorted recipe names, operand kind per recipe) from diag-catalog.

    Catalog rows are one JSON object per line and start with
    {"kind":"DiagnosticRecipe",...}, usually behind a debugger prompt prefix.
    Field-pair regexes anchored on {"name" never match that shape — the silent
    empty result sent every recipe an empty operand for the whole history of
    the harness — so parse the rows as JSON instead. raw_decode tolerates
    trailing output on the same line, which plain json.loads would turn into a
    silently dropped recipe.
    """
    recipes = []
    operand_kinds = {}
    for line in text.splitlines():
        start = line.find('{"kind":"DiagnosticRecipe"')
        if start < 0:
            continue
        try:
            row = json.JSONDecoder().raw_decode(line[start:])[0]
        except json.JSONDecodeError:
            continue
        name, kind = row.get("name"), row.get("operand")
        if name and kind and name not in operand_kinds:
            recipes.append(name)
            operand_kinds[name] = kind
    recipes.sort()
    return recipes, operand_kinds


class Session:
    def __init__(self, args):
        self.args = args
        self.log = args.evidence / "kd-live.log"
        self.output = self.log.open("a", encoding="utf-8")
        dll = args.dll.resolve().as_posix()
        initial = f'.load "{dll}"; .echo KN_LIVE_READY'
        # A previous debugger killed over the pipe can leave VMware's serial
        # slot half-open: kd then exits instantly with Win32 error 231 (all
        # pipe instances busy). That state clears on its own or after a guest
        # reset, so relaunch instead of failing the round.
        # The evidence log appends across resume rounds, so fixed marker names
        # from earlier rounds are still present. Everything this Session waits
        # for must only consider output written by this kd process. The base
        # must be captured BEFORE the launch: a guest that is already polling
        # can connect and run the whole initial command chain during the
        # post-launch alive-check delay, and a base taken after that would
        # skip past the ready marker, trigger a spurious guest reset and then
        # wait for a marker the initial -c command never re-emits.
        self.session_base = len(self.read())
        # Diagnostics make the extension record context-restore failures
        # (which stamp component or restore step) to
        # %LOCALAPPDATA%\kndbgx\logs\kndbgx.log; without them a restore fault
        # only surfaces as the generic session-fault cascade.
        environment = dict(os.environ, KNDBGX_DIAGNOSTICS="1")
        for attempt in range(6):
            self.process = subprocess.Popen(
                [str(args.kd.resolve()), "-b", "-k", args.connect, "-y", args.symbols, "-c", initial],
                stdin=subprocess.PIPE, stdout=self.output, stderr=subprocess.STDOUT, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW, env=environment)
            time.sleep(8)
            if self.process.poll() is None:
                break
            tail = ""
            try:
                tail = self.log.read_text(encoding="utf-8", errors="replace")[-400:]
            except OSError:
                pass
            if "0n231" not in tail:
                break
            print(f"pipe busy (attempt {attempt + 1}); retrying kd launch", flush=True)
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
            # A completed slice may legitimately be empty: the settle step
            # emits no output before its marker, so truthiness would turn a
            # completed wait into a timeout.
            if result is not None:
                return result
            if self.process.poll() is not None:
                self.alive = False
                raise RuntimeError("Debugger exited during validation")
            time.sleep(0.25)
        raise TimeoutError("Debugger operation exceeded its time budget")

    def reset_guest(self, mode):
        """Reset the guest with a bounded, observed vmrun invocation.

        Two failure modes shaped this: a detached, output-less vmrun can fail
        to initialize without any console and vanish silently, and a blocking
        `vmrun reset soft` waits for guest tools that this harness's own
        settle break keeps from ever returning (the guest is frozen mid-boot
        at that point), wedging vmrun's Vix queue for every later command.
        Hard resets return as soon as they are issued, so run in the
        foreground with a generous guard timeout and capture output for
        diagnosis; the reset's effect is confirmed through the kd log.
        """
        try:
            done = subprocess.run([VMRUN, "reset", str(self.args.vmx), mode], check=False, capture_output=True, timeout=120)
            print(f"vmrun reset {mode} rc={done.returncode} out={done.stdout[-100:]!r} err={done.stderr[-100:]!r}", flush=True)
        except subprocess.TimeoutExpired:
            print(f"vmrun reset {mode} timed out", flush=True)
        except OSError as failure:
            print(f"vmrun reset {mode} failed: {failure}", flush=True)

    def wait_ready(self, timeout):
        """Bring the session to the boot break; always through a guest reset.

        Attaching to a polling-but-running guest works on the wire, but the
        -b break-in on a guest that is mid-boot can leave timed-out kernel
        state that bugchecks on resume (observed 2026-09-25: attach to a
        Tools-loading guest, resume, immediate fatal system error). The
        deterministic and validated bring-up is a hard reset with kd already
        waiting on the pipe: the boot break then runs the initial chain.
        """
        self.reset_guest("hard")
        # Predicates must return the match itself (or None), never a bool:
        # wait() treats any non-None value — False included — as completion.
        self.wait(lambda text: LIVE_READY_RE.search(text[self.session_base:]), timeout=timeout)
        return "guest-reset"

    def target_settled(self):
        """Whether the current break is past early kernel initialization.

        kd reports the target uptime in every break header. A boot break
        carries an uptime of seconds; an attach-to-running break carries the
        real uptime. Settling must only continue from the former: resuming a
        settled target never hits the settle-module breaks again, so the
        harness would wait on a marker that cannot appear.
        """
        uptimes = re.findall(r"System Uptime: (\d+) days (\d+):(\d+):(\d+)", self.read()[self.session_base:])
        if not uptimes:
            return False
        days, hours, minutes, seconds = (int(part) for part in uptimes[-1])
        return days * 86400 + hours * 3600 + minutes * 60 + seconds >= 120

    def settle(self):
        """Continue from an early boot break to a settled kernel.

        The boot break is too early for full-system collectors. Resuming with
        module-load breaks armed stops the target again once a guest kernel
        module loads; user-mode module loads (vmtoolsd.exe) are not reported
        to a kernel debugger, so only kernel module names work here.
        """
        marker = "KN_LIVE_SETTLED"
        base = len(self.read())
        # Arm only the settle module: co-arming an early milestone (the old
        # `sxe ld:tcpip`) would break at that earlier load instead, and on
        # build 28000 everything before late boot still has a zero-linked
        # process list.
        self.send(f"sxe ld:{self.args.settle_module}; g; .echo {marker}")

        def complete(text):
            if len(text) < base:
                return None
            segment = text[base:]
            end = segment.find(marker)
            return segment[:end] if end >= 0 else None

        try:
            self.wait(complete, timeout=900)
        except TimeoutError as failure:
            # A dirty-reset boot can take minutes to reach the first settle
            # module. The uptime gate already ensures this step only runs on
            # genuinely early targets; a settled target resumed here never
            # reaches the module breaks again, and every later command would
            # queue behind a running target, so a timeout still aborts the
            # round for the next invocation's reset flow to recover.
            raise RuntimeError("settle did not reach a module-load break within its budget") from failure
        return True

    def run(self, command, timeout=600):
        """Run one CLI command; return output sliced by a unique marker."""
        self.sequence += 1
        marker = f"KN_LIVE_DONE_{self.sequence}"
        base = len(self.read())
        self.send("!kndbgx " + command)
        self.send(f".echo {marker}")

        def complete(text):
            if len(text) < base:
                return None
            segment = text[base:]
            # A host diagnostic can acquire the engine before our queued echo.
            # The receipt confirms submission; only poll() confirms completion.
            if has_submission_receipt(command, segment):
                return segment
            end = segment.find(marker)
            return segment[:end] if end >= 0 else None

        return self.wait(complete, timeout)

    def native(self, command, timeout=600):
        """Run one host debugger command outside the extension."""
        self.sequence += 1
        marker = f"KN_LIVE_NATIVE_{self.sequence}"
        base = len(self.read())
        self.send(command)
        self.send(f".echo {marker}")

        def complete(text):
            if len(text) < base:
                return None
            segment = text[base:]
            end = segment.find(marker)
            return segment[:end] if end >= 0 else None

        return self.wait(complete, timeout)

    def submit(self, command, timeout=120):
        text = self.run("submit " + command, timeout=timeout)
        match = re.search(r"\[job\] ([0-9a-f]{32})", text)
        return text, match.group(1) if match else None

    def poll(self, job_id, timeout=900):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            poll = self.run("job " + job_id, timeout=120)
            candidates = [row for row in json_rows(poll, '{"jobId":')
                          if row.get("jobId") == job_id and "result" in row]
            if candidates:
                return candidates[-1]
            if self.process.poll() is not None:
                self.alive = False
                raise RuntimeError("Debugger exited during job execution")
            remaining = end - time.monotonic()
            if remaining > 0:
                # A debugger command can refresh engine scope even for a
                # status query. Leave room for the collector between polls.
                time.sleep(min(1.0, remaining))
        raise TimeoutError("Job did not complete: " + job_id)

    def job(self, command, timeout=900):
        text = self.run("submit " + command, timeout=120)
        match = re.search(r"\[job\] ([0-9a-f]{32})", text)
        if not match:
            return text, None
        return text, self.poll(match.group(1), timeout)

    def rows(self, job, budget=400):
        rows = []
        offset = 0
        for _ in range(budget):
            text = self.run(f"result-read {job['resultId']} {offset}", timeout=120)
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
        """Resume the target, detach, and leave the guest running.

        The engine may still be busy with a prior command when the harness
        finishes; sending `g` then would only queue it, and killing kd over a
        still-stopped target would freeze the guest at its KD break. Wait for
        an idle marker first, then resume (`g` executes at an idle prompt),
        then detach (`qd`), then fall back to killing the debugger over the
        now-running target.
        """
        try:
            if self.process.poll() is None:
                self.send(".echo KN_LIVE_TEARDOWN")
                try:
                    self.wait(lambda text: LIVE_TEARDOWN_RE.search(text[self.session_base:]), timeout=60)
                except (TimeoutError, RuntimeError):
                    pass
                self.send("g")
                time.sleep(1.5)
                self.send("qd")
                try:
                    self.process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
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
            # Earlier records accepted unfinished scans, unrelated typed
            # operands or invalid context probes. Rerun the corrected checks.
            self.checks = {check["name"]: check for check in json.loads(self.store_path.read_text(encoding="utf-8"))
                           if check.get("evidenceVersion") == EVIDENCE_VERSION}
            self.checks.pop("harness-aborted", None)
            # Older compound checks relied on an error wording substring.
            self.checks.pop("compound-refused", None)
            # Every invocation boots the guest fresh, so the EPROCESS address
            # discovered on a previous boot is stale. Drop the discovery check
            # and the checks that take its value as their operand; the address
            # phase re-discovers on this boot and the diagnostics phase then
            # sends real operands to hex-address recipes instead of 0x0.
            per_boot = {"discover-eprocess", "dt-at-address", "job-query", "job-address",
                        "job-dml-proc-eprocess", "vtop", "kpage"}
            for stale in per_boot:
                self.checks.pop(stale, None)
        self.order = list(self.checks)
        self.started = time.monotonic()
        self.facts = {}
        self.only = re.compile(args.only) if args.only else None

    def budget_spent(self):
        return time.monotonic() - self.started > self.args.budget

    def wanted(self, name, *related):
        names = (name,) + related
        return (self.only is None or any(self.only.search(item) for item in names)) and not (
            self.args.resume and all(self.checks.get(item, {}).get("ok") for item in names))

    def record(self, name, ok, detail=""):
        if name not in self.order:
            self.order.append(name)
        self.checks[name] = {"name": name, "ok": bool(ok), "detail": str(detail)[:600], "evidenceVersion": EVIDENCE_VERSION}
        print(("PASS " if ok else "FAIL ") + name + (" :: " + str(detail)[:200] if not ok or detail else ""), flush=True)
        self.save()

    def skip(self, name, reason):
        if name not in self.order:
            self.order.append(name)
        self.checks[name] = {"name": name, "ok": False, "skipped": True, "detail": reason, "evidenceVersion": EVIDENCE_VERSION}
        print("SKIP " + name + " :: " + reason, flush=True)

    def save(self):
        ordered = [self.checks[name] for name in self.order]
        # Write-then-replace: a round killed mid-write must not truncate the
        # checks store, because every later --resume round loads it and a
        # corrupt store blocks resuming at all. The retry absorbs the
        # real-time scanner races this host is known for (the same %TEMP%
        # race documented for the selftest): a scanner briefly holding the
        # destination fails the replace, not the round.
        tmp = self.store_path.with_name(self.store_path.name + ".tmp")
        for attempt in range(3):
            try:
                tmp.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
                os.replace(tmp, self.store_path)
                return
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(0.2)

    # ---- check helpers ----

    def terminal_ok(self, job, accept=("Success", "Partial", "Unavailable", "Unsupported")):
        state = job.get("state") if job else None
        if state in accept:
            return True, ""
        return False, f"state={state}"

    def diag_job(self, session, name, command, timeout=900):
        """Run a diagnostic/triage job, waiting out engine monopolization.

        Some host-side scans (e.g. !analyze) hold the dbgeng engine lock for
        their whole runtime: CLI job polls queue behind them and time out.
        That is platform serialization, not a product defect — so instead of
        aborting the round, wait for the prompt to come back (a queued marker
        echo completes only once the engine is free again), then poll the job
        to its real terminal state and continue.
        """
        text, job_id = session.submit(command, timeout=120)
        if job_id is None:
            return text, None
        try:
            return text, session.poll(job_id, timeout=timeout)
        except TimeoutError:
            pass
        print(f"WAIT {name}: terminal state unavailable; waiting for the engine", flush=True)
        try:
            session.native(".echo KN_ENGINE_IDLE", timeout=2400)
            job = session.poll(job_id, timeout=900)
            if job is not None and job.get("state") == "StaleContext":
                # Same retry contract as job_check: re-run a stale diagnostic.
                text, job_id = session.submit(command, timeout=120)
                job = session.poll(job_id, timeout=timeout) if job_id else None
            return text, job
        except (TimeoutError, RuntimeError):
            # No terminal result means no validation evidence. Keep this
            # failed so --resume retries it instead of silently skipping it.
            self.record(name, False, "terminal result unconfirmed after the wait budget")
            raise EngineMonopolized()

    def sync_check(self, session, name, command, must=(), must_not=("InternalFault", "native fault"),
                   states=("Success", "Partial"), require_result=True, timeout=600):
        text = session.run(command, timeout=timeout)
        ok = bool(text.strip()) and all(token in text for token in must) and not any(token in text for token in must_not)
        receipt = re.search(r"\[result\] ([0-9a-f]{64})", text)
        state = None
        if receipt:
            pages = json_rows(session.run(f"result-read {receipt[1]} 0 0", timeout=timeout), '{"Schema":')
            page = next((item for item in pages if item.get("ResultId") == receipt[1]), None)
            state = page.get("Metadata", {}).get("status") if page else None
            ok = ok and state in states
        elif require_result:
            ok = False
        detail = text.strip().replace("\n", " | ")[-400:]
        self.record(name, ok, f"state={state}: {detail}" if not ok else "")
        return text

    def job_check(self, session, name, command, states=None, timeout=900):
        text, job = session.job(command, timeout=timeout)
        if job is not None and job.get("state") == "StaleContext":
            # A live collection can race concurrent engine state noise; the
            # product contract for a stale collection is to re-run it.
            text, job = session.job(command, timeout=timeout)
        if job is None:
            self.record(name, False, "not routed to a job and no terminal state: " + text.strip()[-300:])
            return None
        state = job.get("state")
        accepted = states if states is not None else ("Success", "Partial", "Unavailable")
        ok = state in accepted
        result = job.get("result") or {}
        coverage = result.get("coverage") or {}
        detail = f"state={state} visited={coverage.get('visitedEntries')} unknown={coverage.get('unknownEntries')} unreadable={coverage.get('unreadableEntries')}"
        if state == "InternalFault":
            detail += " " + json.dumps(job.get("output", ""))[:200]
        self.record(name, ok, detail if not ok else detail if self.args.verbose else "")
        self.facts[name + ":job"] = job
        return job

    # ---- phases ----

    def job_context_check(self, session, name, command, **kwargs):
        before = native_context_signature(session.native(NATIVE_CONTEXT_PROBE))
        job = self.job_check(session, name, command, **kwargs)
        after = native_context_signature(session.native(NATIVE_CONTEXT_PROBE))
        self.record(name + "-context-preserved", before is not None and before == after,
                    f"before={before} after={after}")
        return job

    def phase_session(self, session):
        s = session
        if self.wanted("version"):
            self.sync_check(s, "version", "version", must=["KNDbgX 0.2.0"], require_result=False)
        if self.wanted("status-kernel-remote"):
            text = self.sync_check(s, "status-kernel-remote", "status", must=["kernel remote"])
            self.facts["status"] = text
        if self.wanted("features"):
            self.sync_check(s, "features", "features", must=["external-ui-process", "ttd-replay"], require_result=False)
        if self.wanted("contract-json"):
            text = s.run("contract", timeout=120)
            start = text.find("[{")
            end = text.rfind("}]")
            parsed = None
            if start >= 0 and end > start:
                try:
                    parsed = json.loads(text[start:end + 2])
                except json.JSONDecodeError:
                    parsed = None
            expected = json.loads((pathlib.Path(__file__).resolve().parents[1] / "docs/command-contract.json").read_text(encoding="utf-8"))
            matches = isinstance(parsed, list) and len(parsed) == len(expected) and all(
                isinstance(row, dict) and isinstance(row.get("name"), str) for row in parsed)
            matches = matches and sorted(row.get("name", "") for row in parsed) == sorted(row["name"] for row in expected)
            self.record("contract-json", matches,
                        f"parsed={parsed is not None} count={len(parsed) if parsed else 0}")
        if self.wanted("help-matrix"):
            text = s.run("help", timeout=120)
            ok = "[kernel: dump+live]" in text and "[kernel: live only]" in text and "!callbacks" in text
            self.record("help-matrix", ok, text[:200] if not ok else "")
        if self.wanted("help-live-only-label"):
            self.sync_check(s, "help-live-only-label", "help eb", must=["[kernel: live only]"], require_result=False)
        if self.wanted("help-dump-live-label"):
            self.sync_check(s, "help-dump-live-label", "help db", must=["[kernel: dump+live]"], require_result=False)

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

    def phase_memory(self, session):
        s = session
        for cmd in ("db", "dw", "dd", "dq", "dc"):
            name = f"display-{cmd}"
            if self.wanted(name):
                self.sync_check(s, name, f"{cmd} nt L10", must=["[memory]"])
        for cmd in ("dds", "dqs"):
            name = f"display-{cmd}"
            if self.wanted(name):
                self.sync_check(s, name, f"{cmd} nt L8")
        if self.wanted("display-da"):
            self.sync_check(s, "display-da", "da nt L4")
        if self.wanted("display-du"):
            self.sync_check(s, "display-du", "du nt L4")
        if self.wanted("search-bytes"):
            text = s.run("s nt L200 4d 5a")
            self.record("search-bytes", re.search(r"0x[0-9a-fA-F]{16}", text) is not None and "InternalFault" not in text,
                        text.strip()[-300:])
        if self.wanted("display-invalid-args"):
            self.sync_check(s, "display-invalid-args", "db nt L0", states=("InvalidInput",))
        if self.wanted("display-unknown-symbol"):
            self.sync_check(s, "display-unknown-symbol", "db kn_nosuchsymbol_xyz L4", states=("InvalidInput",))

    def phase_code(self, session):
        s = session
        if self.wanted("unassemble"):
            text = s.run("u nt!KeBugCheckEx L8")
            self.record("unassemble", re.search(r"[0-9a-f]{8}`[0-9a-f]{8}\s+[0-9a-f]{4}", text) is not None,
                        text.strip()[-300:])
        if self.wanted("unassemble-function"):
            text = s.run("uf nt!KeBugCheckEx", timeout=900)
            self.record("unassemble-function", "KeBugCheckEx" in text, text.strip()[-300:])

    def phase_context_defaults(self, session):
        if not self.wanted("current-context-defaults"):
            return
        before = native_context_signature(session.native(NATIVE_CONTEXT_PROBE))
        if before is None:
            self.record("current-context-defaults", False, "Native context unavailable")
            return
        observed = {}
        jobs = {}
        for command in ("!threads", "!threads ethread:" + format(before[0], "x"), "!process",
                        "!process eprocess:" + format(before[1], "x"), "!token", "!vad /limit 1", "!vad /limit 1 eprocess:" + format(before[1], "x")):
            text, job = session.job(command)
            if job is None or job.get("state") not in ("Success", "Partial") or not job.get("resultId"):
                self.record("current-context-defaults", False, f"{command}: missing readable result: {text}")
                return
            observed[command] = session.rows(job)
            jobs[command] = job
        threads = observed["!threads"]
        processes = observed["!process"]
        tokens = observed["!token"]
        def address_matches(row, field, address):
            value = row.get(field, "")
            return isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{16}", value) is not None and int(value, 16) == address
        ok = (len(threads) == 1 and address_matches(threads[0], "ethread", before[0]) and
              threads == observed["!threads ethread:" + format(before[0], "x")] and
              len(processes) == 1 and address_matches(processes[0], "eprocess", before[1]) and
              processes == observed["!process eprocess:" + format(before[1], "x")] and
              len(tokens) == 1 and tokens[0].get("selection") == "CurrentThreadEffectiveToken" and
              address_matches(tokens[0], "ethread", before[0]) and
              equivalent_bounded_rows(observed["!vad /limit 1"], jobs["!vad /limit 1"],
                                      observed["!vad /limit 1 eprocess:" + format(before[1], "x")],
                                      jobs["!vad /limit 1 eprocess:" + format(before[1], "x")]) and
              native_context_signature(session.native(NATIVE_CONTEXT_PROBE)) == before)
        self.record("current-context-defaults", ok, "Current identity, explicit selection, option-only VAD and unchanged context")

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
            self.sync_check(s, "breakpoints", "breakpoints", states=("Success",))
        if self.wanted("event"):
            self.sync_check(s, "event", "event", states=("Success", "Unavailable"))
        if self.wanted("source-unavailable-graceful"):
            self.sync_check(s, "source-unavailable-graceful", "source nt!KeBugCheckEx",
                            states=("Success", "Partial", "Unavailable"))
        if self.wanted("procctx-flow"):
            names = ("procctx-before", "procctx-select", "procctx-selected", "procctx-reset")
            try:
                self.sync_check(s, names[0], "procctx show", states=("Success",))
                self.sync_check(s, names[1], "procctx pid:4", must=("[procctx] pid=",), states=("Success",))
                self.sync_check(s, names[2], "procctx show", must=("override on",), states=("Success",))
            finally:
                self.sync_check(s, names[3], "procctx reset", must=("override cleared",), states=("Success",))
            self.record("procctx-flow", all(self.checks.get(name, {}).get("ok") for name in names))

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
            ("job-drvobj-disk", "!drvobj disk"),
            ("job-module-all", "!module"),
        ]
        for name, command in success_jobs:
            if command in ("!cr", "!msrcheck", "!idt"):
                if self.wanted(name, name + "-context-preserved"):
                    self.job_context_check(s, name, command)
            elif self.wanted(name):
                job = self.job_check(s, name, command)
                if name == "job-drvobj-disk" and job and job.get("resultId") and job.get("state") in ("Success", "Partial"):
                    for row in s.rows(job):
                        device = row.get("firstDevice", "")
                        if row.get("kind") == "Driver" and isinstance(device, str) and re.fullmatch(r"0x[fF]{2}[0-9a-fA-F]{14}", device):
                            self.facts["diagnostic-operands"] = {
                                **self.facts.get("diagnostic-operands", {}), "device": device, "devstack": device,
                            }
                            break
        for name, command in [("job-ssdt", "!ssdt"), ("job-timer", "!timer"), ("job-hal", "!hal"),
                              ("job-piddb", "!piddb"), ("job-cihash", "!cihash"), ("job-mapper", "!mapper")]:
            if self.wanted(name):
                self.job_check(s, name, command, states=("Success", "Partial", "Unavailable"))
        if self.wanted("drvobj-no-arg-usage"):
            text, job = s.job("!drvobj")
            state = job.get("state") if job else None
            output = ((job or {}).get("output", "") if job else text) or ""
            self.record("drvobj-no-arg-usage", (state == "InvalidInput" or (job is None and "InvalidInput" in output)) and "usage" in output,
                        f"state={state} {output[:200]}")

    def phase_pool(self, session):
        """Big-pool observation over the target-side PoolBigPageTable walk.

        These commands are host-local in their original form; the live-remote
        session must reach a terminal state using the target-side table walk
        (or an explicit layout Unavailable on kernels without the symbols).
        """
        s = session
        for name, command, states in [
            ("pool-summary", "!pool", ("Success", "Partial", "Unavailable")),
            ("pool-big-limit", "!pool big /limit 8", ("Success", "Partial", "Unavailable")),
            ("pool-tag-filter", "!pool /tag Cont /limit 8", ("Success", "Partial", "Unavailable")),
            ("payload-wx", "!payload", ("Success", "Partial", "Unavailable")),
        ]:
            if self.wanted(name):
                job = self.job_check(s, name, command, states=states)
                if job is not None and job.get("state") == "Unavailable":
                    output = job.get("output", "")
                    self.record(name + "-explicit-gap", "PoolBigPageTable" in output or "layout" in output.lower(),
                                output[-200:])

    def phase_host_collectors_remote(self, session):
        """Target-backed collectors run remotely; remaining host collectors refuse."""
        s = session
        for command in ("!hiddenproc", "!handles"):
            name = "target-backed:" + command.lstrip("!")
            if self.wanted(name):
                job = self.job_check(s, name, command, states=("Success", "Partial"))
                provenance = (job or {}).get("result", {}).get("provenance", {})
                self.record(name + "-provenance", provenance.get("source", "").startswith("TargetMemory:"),
                            "Remote observations must come from target memory")
        for command in ("!wfp", "!dma", "!byovd"):
            name = "host-local-refused:" + command.lstrip("!")
            if not self.wanted(name):
                continue
            text = s.run(command)
            combined = text
            if "[job]" in text:
                _, job = s.job(command)
                combined += (job or {}).get("output", "") + json.dumps(job or {})
            self.record(name, HOST_REFUSAL in combined and MODE_REFUSAL not in combined,
                        combined.strip()[-300:])

    def phase_kernel_addresses(self, session):
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
                               states=("Success", "Partial", "Unavailable"))
            if self.wanted("vtop"):
                self.job_check(s, "vtop", f"vtop {eprocess}")
            if self.wanted("kpage"):
                self.job_check(s, "kpage", f"!kpage {eprocess} L4")
        if self.wanted("job-module-nt"):
            self.job_check(s, "job-module-nt", "!module nt")
        if self.wanted("job-devstack", "job-devstack-context-preserved", "job-devstack-observed-device"):
            device = self.facts.get("diagnostic-operands", {}).get("devstack")
            if device:
                job = self.job_context_check(s, "job-devstack", f"!devstack {device}", states=("Success", "Partial"))
                rows = s.rows(job) if job and job.get("resultId") else []
                self.record("job-devstack-observed-device", any(row.get("kind") == "Device" for row in rows),
                            "A verified device must be observed before the traversal budget expires")
            else:
                self.skip("job-devstack", "no verified target device from the driver inventory")

    def phase_diagnostics(self, session):
        s = session
        text = s.run("diag-catalog", timeout=120)
        recipes, operand_kinds = parse_diagnostic_catalog(text)
        if not recipes:
            # A silent zero-recipe phase would look green while exercising
            # nothing, so an unparsable or absent catalog is a recorded check
            # failure (and a resume re-runs it).
            self.record("diagnose-catalog", False, "diag-catalog produced no parseable recipe rows")
            return
        # Some host extensions scan for a long time and hold the dbgeng engine
        # lock while they run: !irpfind walks pool IRPs ("potentially
        # expensive"), and !errrec hunts WHEA records when fed a non-record
        # address (observed 2026-09-26: the harness's generic EPROCESS operand
        # wedged the engine past the wait budget). A wedged scan ends the
        # round, so run these last and let every other check finish first.
        heavy = {"irpfind", "errrec"}
        recipes = [recipe for recipe in recipes if recipe not in heavy] + \
                  [recipe for recipe in recipes if recipe in heavy]
        self.facts["recipes"] = recipes
        eprocess = self.facts.get("eprocess") or "0x0"
        for recipe in recipes:
            name = f"diagnose-{recipe}"
            if not self.wanted(name):
                continue
            if self.budget_spent():
                return
            kind = operand_kinds.get(recipe, "none")
            if kind not in ("none", "hex-address", "module", "optional-module"):
                # An operand kind this harness does not know would fall through
                # to an empty operand and re-create the accepted-InvalidInput
                # pass; record the gap instead of a fake green.
                self.skip(name, f"unknown catalog operand kind: {kind}")
                continue
            if kind == "hex-address":
                # An EPROCESS is valid for allocation/page inspection, but
                # is not an IRP, WHEA record, device or framework handle.
                operand = self.facts.get("diagnostic-operands", {}).get(recipe)
                if operand is None and recipe in ("pte", "pool") and eprocess != "0x0":
                    operand = eprocess
                if not operand:
                    self.skip(name, "no verified target object for this recipe")
                    continue
                command = f"diagnose {recipe} {operand}"
            elif kind == "module":
                module = self.facts.get("wdf-module")
                if not module:
                    self.skip(name, "no verified WDF driver module")
                    continue
                command = f"diagnose {recipe} {module}"
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
            text, job = self.diag_job(session, name, f"triage {profile}", timeout=1200)
            ok, detail = self.terminal_ok(job, accept=("Success", "Partial", "Unavailable"))
            self.record(name, ok, detail)
        if self.wanted("triage-wdf") and not self.budget_spent():
            module = self.facts.get("wdf-module")
            if module:
                text, job = self.diag_job(session, "triage-wdf", f"triage wdf {module}", timeout=1200)
                ok, detail = self.terminal_ok(job, accept=("Success", "Partial", "Unavailable"))
                self.record("triage-wdf", ok, detail)
            else:
                self.skip("triage-wdf", "no verified WDF driver module")
        if self.wanted("triage-wdf-requires-module") and not self.budget_spent():
            text, job = session.job("triage wdf", timeout=300)
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
        if self.wanted("dump-raw-virtual"):
            path = evidence / "raw-va.bin"
            path.unlink(missing_ok=True)
            text = s.run(f'dump-raw nt 0x400 "{path}"', timeout=300)
            self.record("dump-raw-virtual", path.is_file() and path.stat().st_size == 0x400,
                        text.strip()[-300:])
        if self.wanted("dump-pe-nt"):
            path = evidence / "nt-image.bin"
            path.unlink(missing_ok=True)
            text = s.run(f'dump-pe nt "{path}"', timeout=900)
            ok = path.is_file() and path.stat().st_size > 0x1000 and path.read_bytes()[:2] == b"MZ"
            self.record("dump-pe-nt", ok, text.strip()[-300:] if not ok else "")
        if self.wanted("driver-audit"):
            target = evidence / "nt-image.bin"
            operand = str(target if target.is_file() else pathlib.Path(r"C:\Windows\System32\drivers\disk.sys"))
            self.sync_check(s, "driver-audit", f'driver-audit "{operand}"')
        if self.wanted("sarif-import"):
            sarif = evidence / "minimal.sarif"
            sarif.write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "kndbgx-test", "rules": []}},
                          "results": []}],
            }), encoding="utf-8")
            self.sync_check(s, "sarif-import", f'sarif-import "{sarif}"', states=("Success",))
        if self.wanted("etl-import-missing"):
            self.sync_check(s, "etl-import-missing", f'etl-import "{evidence / "absent.etl"}"',
                            states=("IOError",))

    def phase_snapshot(self, session):
        s = session
        evidence = self.args.evidence
        before = evidence / "snap-before"
        after = evidence / "snap-after"
        if self.wanted("snapshot-before"):
            text, job = s.job(f'!snapshot "{before}"', timeout=1200)
            state = job.get("state") if job else None
            ok = state in ("Success", "Partial") and (before / "manifest.json").is_file()
            self.record("snapshot-before", bool(ok), f"state={state} manifest={(before / 'manifest.json').is_file()}")
        if self.wanted("snapshot-after"):
            text, job = s.job(f'!snapshot "{after}"', timeout=1200)
            state = job.get("state") if job else None
            ok = state in ("Success", "Partial") and (after / "manifest.json").is_file()
            self.record("snapshot-after", bool(ok), f"state={state} manifest={(after / 'manifest.json').is_file()}")
        if self.wanted("snapshot-diff"):
            if (before / "manifest.json").is_file() and (after / "manifest.json").is_file():
                text, job = s.job(f'!diff "{before}" "{after}"', timeout=900)
                state = job.get("state") if job else None
                if state == "Unavailable" and job and "cross-session" in json.dumps(job.get("result", {}).get("error", {})):
                    text, job = s.job(f'!diff "{before}" "{after}" /cross-session', timeout=900)
                    state = job.get("state") if job else None
                if job is not None:
                    self.record("snapshot-diff", state in ("Success", "Partial"), f"state={state}")
                else:
                    self.record("snapshot-diff", False, "terminal result missing: " + text.strip()[-300:])
            else:
                self.skip("snapshot-diff", "snapshot bundles missing")

    def phase_navigation(self, session):
        s = session
        if not self.wanted("navigation-flow"):
            return
        details = []
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
            s.run('bookmark "live validation note"')
            text = s.run("bookmarks")
            ok = "live validation note" in text
            details.append(f"bookmark={'ok' if ok else text.strip()[-150:]}")
        self.record("navigation-flow", ok, "; ".join(details) if not ok else "")

    def phase_results(self, session):
        s = session
        if self.wanted("results-list"):
            text = s.run("results", timeout=120)
            match = re.findall(r'"resultId":"([0-9a-f]{64})"', text) or re.findall(r"\[result\] ([0-9a-f]{64})", text)
            if not match:
                match = re.findall(r'"id":"([0-9a-f]{64})"', text)
            self.facts["resultIds"] = match
            self.record("results-list", len(match) > 0, text.strip()[-300:] if not match else "")
        result_ids = self.facts.get("resultIds") or []
        if self.wanted("result-read") and result_ids:
            text = s.run(f"result-read {result_ids[0]} 0 0", timeout=120)
            self.record("result-read", '"ResultId"' in text or '"Rows"' in text, text.strip()[-300:])
        if self.wanted("result-export") and result_ids:
            path = self.args.evidence / "exported-result.json"
            path.unlink(missing_ok=True)
            text = s.run(f'result-export {result_ids[0]} "{path}"', timeout=300)
            ok = path.is_file() and path.stat().st_size > 2
            if ok:
                try:
                    json.loads(path.read_text(encoding="utf-8", errors="replace"))
                except json.JSONDecodeError:
                    ok = False
            self.record("result-export", ok, text.strip()[-300:] if not ok else "")
        if self.wanted("model"):
            text = s.run("model", timeout=120)
            self.record("model", '"available"' in text, text.strip()[-200:])
        if self.wanted("model-publish"):
            fresh = s.run("db nt L4")
            match = re.search(r"\[result\] ([0-9a-f]{64})", fresh)
            if not match:
                self.record("model-publish", False, "no fresh result id: " + fresh.strip()[-200:])
            else:
                text = s.run(f"model publish {match.group(1)} 0", timeout=300)
                self.record("model-publish", "Result page available in the host" in text, text.strip()[-300:])
                self.facts["modelPublished"] = "Result page available in the host" in text
        if self.wanted("model-dx"):
            if self.facts.get("modelPublished"):
                text = s.native("dx -r1 Debugger.Models.KNDbgX", timeout=300)
                self.record("model-dx", "KNDbgX" in text and "kndbgx.model.v1" in text, text.strip()[-200:])
            else:
                self.skip("model-dx", "model publish did not succeed")
        if self.wanted("jobs-list"):
            text = s.run("jobs", timeout=120)
            self.record("jobs-list", '"jobId"' in text or "[]" in text, text.strip()[-200:])
        if self.wanted("cancel-terminal"):
            text, job_id = s.submit("!idt")
            if not job_id:
                self.record("cancel-terminal", False, "submit refused: " + text.strip()[-200:])
            else:
                cancel = s.run("cancel " + job_id)
                job = s.poll(job_id, timeout=600)
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
            job = s.poll(job_id, timeout=300) if job_id else None
            combined = text + ((job or {}).get("output", "") if job else "")
            refused = "ack-effects" in combined
            executed = "Kernel Version" in combined or "Product:" in combined
            self.record("raw-refused-without-ack", refused and not executed,
                        combined.strip()[-300:] if not (refused and not executed) else "")
        if self.wanted("raw-acknowledged"):
            text, job_id = s.submit("raw --ack-effects vertarget")
            job = s.poll(job_id, timeout=300) if job_id else None
            combined = text + ((job or {}).get("output", "") if job else "")
            self.record("raw-acknowledged", "Kernel Version" in combined or "Windows" in combined,
                        combined.strip()[-300:])

    def phase_mutation(self, session):
        """Live-only mutation machinery: one-use approval and typed writes.

        The write operand is chosen so an approved execution rewrites the
        identical original bytes of a kernel global: the feature path is
        exercised without observably changing target state.
        """
        s = session
        if self.wanted("mutation-requires-approval-token"):
            text = s.run("approve missing-plan missing-token")
            self.record("mutation-requires-approval-token", "UnknownPlanOrApprovalToken" in text,
                        text.strip()[-300:])
        if self.wanted("plan-writable-range-validation"):
            text = s.run("plan eb nt 90")
            preview = "[plan] complete preview; no target bytes written" in text and "[plan.approval] approve " in text
            self.record("plan-writable-range-validation",
                        MODE_REFUSAL not in text and "InternalFault" not in text and (preview or "memory range" in text),
                        text.strip()[-300:])
        if self.wanted("plan-approve-same-value"):

            def build_number_value(text):
                # The displayed value is the last bare 8-hex token; address
                # tokens contain a backtick and do not fullmatch.
                for word in reversed(text.split()):
                    if re.fullmatch(r"[0-9a-f]{8}", word):
                        return word
                return None

            original = s.run("dd nt!NtBuildNumber L1", timeout=300)
            value = build_number_value(original)
            if not value:
                self.record("plan-approve-same-value", False, "no build number read: " + original.strip()[-200:])
                return
            text = s.run(f"plan ed nt!NtBuildNumber 0x{value}", timeout=300)
            # Receipt format (MutationService): "[plan.approval] approve <48-hex id> <48-hex token>".
            receipt = re.search(r"\[plan\.approval\] approve ([0-9a-f]{48}) ([0-9a-f]{48})", text)
            if not receipt:
                self.record("plan-approve-same-value", False, "no plan approval receipt: " + text.strip()[-300:])
                return
            approved = s.run(f"approve {receipt.group(1)} {receipt.group(2)}", timeout=300)
            # An unchanged value also follows a refused or partial same-value
            # write. Require the structured applied-and-verified receipt.
            applied_records = json_rows(approved, '{"schema":"kndbgx.result.v2"')
            applied_result = applied_records[0] if len(applied_records) == 1 else {}
            coverage = applied_result.get("coverage")
            ranges = applied_result.get("rows")
            verified = (applied_result.get("status") == "Success" and applied_result.get("commandId") == "ed"
                        and isinstance(coverage, dict) and coverage.get("complete") is True
                        and coverage.get("stopReason") == "AppliedAndVerified"
                        and all(coverage.get(field) == "4" for field in ("expectedEntries", "readEntries", "decodedEntries"))
                        and isinstance(ranges, list) and len(ranges) == 1 and isinstance(ranges[0], dict)
                        and ranges[0].get("requestedBytes") == "4" and ranges[0].get("appliedBytes") == "4"
                        and ranges[0].get("verified") is True and ranges[0].get("status") == "Success")
            after = s.run("dd nt!NtBuildNumber L1", timeout=300)
            unchanged = build_number_value(after) == value
            ok = verified and unchanged and bool(after.strip())
            self.record("plan-approve-same-value", bool(ok),
                        (text.strip()[-200:] + " | " + approved.strip()[-200:] + f" | unchanged={unchanged}") if not ok else "")

    def phase_negatives(self, session):
        s = session
        if self.wanted("unknown-command"):
            text = s.run("frobnicate")
            self.record("unknown-command", "Unknown" in text or "Unsupported" in text, text.strip()[-200:])
        if self.wanted("compound-refused"):
            # WinDbg splits unquoted semicolons before calling the extension.
            # Keep the expression quoted and the sentinel harmless. Direct
            # parser rejection of unquoted compounds belongs in selftests.
            self.sync_check(s, "compound-refused", 'db "nt; .echo KN_COMPOUND_SENTINEL" L4',
                            states=("InvalidInput",), must_not=("[memory] start=", "InternalFault", "native fault"))
        if self.wanted("empty-arguments"):
            text = s.run("dt")
            self.record("empty-arguments", "usage" in text.lower() or "Invalid" in text, text.strip()[-200:])
        if self.wanted("unsupported-physical-write"):
            text = s.run("!eb 1000 41")
            self.record("unsupported-physical-write", "Unsupported capability" in text, text.strip()[-200:])

    def phase_reconnect(self, session):
        s = session
        if self.wanted("session-healthy"):
            text = s.run("status")
            self.record("session-healthy", "kernel remote" in text, text.strip()[-200:])
        if self.wanted("reconnect"):
            text = s.run("reconnect", timeout=300)
            after = s.run("status")
            self.record("reconnect", "kernel remote" in after, (text + after).strip()[-300:])

    def phases(self):
        return [
            ("session", self.phase_session),
            ("symbols", self.phase_symbols),
            ("memory", self.phase_memory),
            ("code", self.phase_code),
            ("context-defaults", self.phase_context_defaults),
            ("debugger-state", self.phase_debugger_state),
            ("kernel-collectors", self.phase_kernel_collectors),
            ("pool", self.phase_pool),
            ("host-collectors-remote", self.phase_host_collectors_remote),
            ("kernel-addresses", self.phase_kernel_addresses),
            ("diagnostics", self.phase_diagnostics),
            ("triage", self.phase_triage),
            ("files", self.phase_files),
            ("snapshot", self.phase_snapshot),
            ("navigation", self.phase_navigation),
            ("results", self.phase_results),
            ("policy", self.phase_policy),
            ("mutation", self.phase_mutation),
            ("negatives", self.phase_negatives),
            ("reconnect", self.phase_reconnect),
        ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kd", "dll", "vmx", "evidence"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--connect", default="com:port=\\\\.\\pipe\\com1,baud=115200,pipe,reconnect",
                        help="kd -k connection string")
    parser.add_argument("--settle-module", default="vmmemctl",
                        help="guest kernel module whose load marks a settled kernel "
                             "(VMware Tools balloon driver; it loads near the end of boot. "
                             "Early milestones like vmci/tcpip are NOT settled enough: on "
                             "Windows 11 build 28000 PsActiveProcessHead stays zero-linked "
                             "until late boot, so process-dependent checks fail there the "
                             "same way kd's native !process does)")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--bringup", type=float, default=1500.0)
    parser.add_argument("--budget", type=float, default=1200.0)
    parser.add_argument("--only")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    for path in (args.kd, args.dll, args.vmx):
        if not path.exists():
            parser.error("Path unavailable: " + str(path))
    if args.resume:
        args.evidence.mkdir(parents=True, exist_ok=True)
    else:
        args.evidence.mkdir(parents=True, exist_ok=False)
    harness = Harness(args)
    session = Session(args)
    aborted = None
    try:
        bringup = session.wait_ready(timeout=args.bringup)
        print(f"bringup={bringup}", flush=True)
        harness.facts["bringup"] = bringup
        if not session.target_settled():
            session.settle()
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
            harness.record("global-debugger-alive", False, "kd exited during validation")
        elif harness.wanted("global-debugger-alive"):
            harness.record("global-debugger-alive", True)
    except EngineMonopolized:
        aborted = "terminal result unconfirmed while the engine was busy"
        print("engine monopolized by a synchronous host scan; finalizing this round", flush=True)
    except (RuntimeError, TimeoutError) as failure:
        aborted = str(failure)
        harness.record("harness-aborted", False, aborted)
    finally:
        session.close()
    harness.save()
    executed = [check for check in harness.checks.values() if not check.get("skipped")]
    failed = [check for check in executed if not check["ok"]]
    skipped = [check for check in harness.checks.values() if check.get("skipped")]
    incomplete = bool(skipped) or harness.budget_spent()
    summary = {"schema": "kndbgx.live-kernel-validation.v1", "executed": len(executed), "failed": len(failed),
               "skipped": len(skipped), "complete": not (failed or aborted or incomplete),
               "aborted": aborted, "failures": [check["name"] for check in failed]}
    (args.evidence / "validation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 1 if failed or aborted else 2 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
