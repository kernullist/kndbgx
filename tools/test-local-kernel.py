"""Validate dump/live session-mode gating against a local live kernel session.

Prerequisites (one-time machine setup, requires an administrator and a reboot):

    bcdedit /debug on
    shutdown /r /t 0

After the reboot, run from an elevated prompt:

    python tools/test-local-kernel.py --kd <staged-kd> --dll x64\\Release\\kndbgx.dll ^
        --symbols srv*<cache>*https://msdl.microsoft.com/download/symbols --evidence <dir>

<staged-kd> is a copy of the installed WinDbg amd64 runtime (kd.exe plus its
DLLs); Appx ACLs prevent running kd.exe in place, and this cdb build rejects
`-kl`. To restore the machine:

    bcdedit /debug off
    shutdown /r /t 0

The harness checks that a live local kernel session is NOT gated as a dump:
read-only commands keep working, live-only commands pass the session-mode gate
and fail only at their own write/execution policy, and help keeps its labels.
"""

import argparse
import json
import pathlib
import re
import subprocess
import time

MODE_REFUSAL = "Unsupported in the current session mode"


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kd", type=pathlib.Path, required=True)
    parser.add_argument("--dll", type=pathlib.Path, required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    args = parser.parse_args()
    for path in (args.kd, args.dll):
        if not path.is_file():
            parser.error(f"File unavailable: {path}")
    args.evidence.mkdir(parents=True, exist_ok=False)
    log = args.evidence.resolve() / "kd-local-kernel.log"
    checks = []
    sequence = 0

    def record(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            raise RuntimeError(f"{name}: {detail}")

    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [str(args.kd.resolve()), "-kl", "-y", args.symbols,
             "-c", f'.load "{args.dll.resolve().as_posix()}"'],
            stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)

        def send(line):
            process.stdin.write(line + "\n")
            process.stdin.flush()

        def read():
            if log.stat().st_size > 16 * 1024 * 1024:
                raise RuntimeError("Debugger output exceeded its evidence budget")
            return log.read_text(encoding="utf-8", errors="replace")

        def wait_for(predicate, timeout=60):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = predicate(read())
                if value:
                    return value
                if process.poll() is not None:
                    raise RuntimeError("Debugger exited before validation completed")
                time.sleep(0.1)
            raise TimeoutError("Debugger validation timed out")

        def run_command(command):
            """Send one command plus a unique marker; return the command output.

            The slice starts at the log length captured before sending, so it
            works whether or not the debugger echoes piped input. The first
            marker occurrence ends the slice: when input is echoed that is the
            echoed `.echo` line, otherwise it is the marker output itself.
            """
            nonlocal sequence
            sequence += 1
            marker = f"LOCALKD_DONE_{sequence}"
            base = len(read())
            send(command)
            send(f".echo {marker}")

            def complete(text):
                if len(text) < base:
                    return None
                segment = text[base:]
                end = segment.find(marker)
                if end < 0:
                    return None
                return segment[:end]

            return wait_for(complete)

        try:
            text = run_command("!kndbgx status")
            record("session-is-local-live-kernel", "kernel local" in text,
                   "expected 'kernel local'; is /debug on and was the machine rebooted?")

            text = run_command("!kndbgx help eb")
            record("help-keeps-live-only-label", "[kernel: live only]" in text)

            text = run_command("!kndbgx help db")
            record("help-keeps-dump-and-live-label", "[kernel: dump+live]" in text)

            text = run_command("!kndbgx db nt L4")
            record("read-only-display-works", "[memory] start=" in text)

            # Live-only commands must pass the session-mode gate in a live
            # session and fail only at their own mutation/execution policy.
            text = run_command("!kndbgx eb nt 90")
            record("mutation-passes-mode-gate", MODE_REFUSAL not in text,
                   "live local kernel was misclassified as a dump session")

            text = run_command("!kndbgx debug-approve 1 2")
            record("execution-passes-mode-gate", MODE_REFUSAL not in text)
            record("execution-refused-by-own-policy",
                   "Execution actions require" in text or "Target must be stopped" in text,
                   text.strip()[:300])

            # Kernel collectors run as jobs; they must reach a terminal state
            # without the session-mode refusal.
            for collector in ("!pool", "!hiddenproc"):
                text = run_command(f"!kndbgx {collector}")
                match = re.search(r"\[job\] ([0-9a-f]+)", text)
                record(f"{collector}-job-submitted", match is not None, text.strip()[:300])
                job_id = match.group(1)
                job = None
                for _ in range(120):
                    send("!kndbgx job " + job_id)
                    time.sleep(0.25)
                    candidates = [row for row in json_rows(read(), '{"jobId":')
                                  if row.get("jobId") == job_id and "result" in row]
                    if candidates:
                        job = candidates[-1]
                        break
                record(f"{collector}-job-completes", job is not None, "job did not reach a terminal state")
                record(f"{collector}-not-mode-gated", MODE_REFUSAL not in job.get("output", ""),
                       json.dumps(job)[:400])

            record("no-debugger-callback-exception", "Exception in debugger client" not in read())
        except (RuntimeError, TimeoutError) as failure:
            detail = str(failure)
            try:
                if "bcdedit" in read():
                    detail += " (local kernel debugging is disabled; run 'bcdedit /debug on' as administrator and reboot)"
            except Exception:
                pass
            checks.append({"name": "harness-aborted", "ok": False, "detail": detail})
        finally:
            try:
                send("qq")
                process.wait(timeout=15)
            except Exception:
                process.kill()

    summary = {"schema": "kndbgx.local-kernel-validation.v1", "checks": checks,
               "passed": sum(1 for check in checks if check["ok"])}
    (args.evidence / "validation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"local kernel validation: {summary['passed']}/{len(checks)} checks passed; evidence in {args.evidence}")
    return 0 if summary["passed"] == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
