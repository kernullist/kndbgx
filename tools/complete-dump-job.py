"""Drive one long-running kndbgx diagnose/triage job to its terminal state.

Synchronous host scans (e.g. !irpfind, !stacks) hold the dbgeng engine lock,
so CLI polls time out while the scan runs; the queued commands flush once the
job ends. This driver submits the command, retries polls patiently, records
the terminal job row to <log>, and quits the debugger.

    python tools/complete-dump-job.py --cdb <cdb> --dll <dll> --dump <dump> ^
        --symbols <path> --command "diagnose irpfind" --log <out.log> [--hours 6]
"""

import argparse
import json
import pathlib
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cdb", type=pathlib.Path, required=True)
    parser.add_argument("--dll", type=pathlib.Path, required=True)
    parser.add_argument("--dump", type=pathlib.Path, required=True)
    parser.add_argument("--symbols", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--log", type=pathlib.Path, required=True)
    parser.add_argument("--hours", type=float, default=6.0)
    args = parser.parse_args()

    log = args.log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [str(args.cdb.resolve()), "-z", str(args.dump.resolve()), "-y", args.symbols,
         "-c", f'.load "{args.dll.resolve().as_posix()}"; .echo KN_JOB_READY'],
        stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW)

    offset = 0
    sequence = 0

    def read():
        nonlocal offset
        log.flush()
        text = args.log.read_text(encoding="utf-8", errors="replace")
        segment = text[offset:]
        offset = len(text)
        return segment

    def run(command, timeout=45):
        nonlocal sequence
        sequence += 1
        marker = f"KN_JOB_DONE_{sequence}"
        base_text = read()
        process.stdin.write("!kndbgx " + command + "\n")
        process.stdin.write(f".echo {marker}\n")
        process.stdin.flush()
        end = time.monotonic() + timeout
        segment = base_text
        while time.monotonic() < end:
            time.sleep(2)
            segment += read()
            idx = segment.find(marker)
            if idx >= 0:
                return segment[:idx]
            if process.poll() is not None:
                raise RuntimeError("debugger exited")
        raise TimeoutError(command)

    result = {"command": args.command, "terminal": None, "state": None}
    try:
        end = time.monotonic() + 600
        while ".echo KN_JOB_READY" not in read() and "KN_JOB_READY" not in read():
            if time.monotonic() > end:
                raise RuntimeError("debugger did not start")
            time.sleep(2)
        text = run("submit " + args.command, timeout=120)
        match = re.search(r"\[job\] ([0-9a-f]{32})", text)
        if not match:
            result["state"] = "submit-refused"
            result["terminal"] = text.strip()[-400:]
            return
        job_id = match.group(1)
        result["jobId"] = job_id
        deadline = time.monotonic() + args.hours * 3600
        while time.monotonic() < deadline:
            try:
                poll = run("job " + job_id, timeout=45)
            except TimeoutError:
                print(f"[{time.strftime('%H:%M:%S')}] poll timed out; scan still holds the engine", flush=True)
                continue
            rows = []
            for line in poll.splitlines():
                start = line.find('{"jobId":')
                if start >= 0:
                    try:
                        rows.append(json.loads(line[start:]))
                    except json.JSONDecodeError:
                        pass
            done = [row for row in rows if row.get("jobId") == job_id and "result" in row]
            if done:
                job = done[-1]
                result["state"] = job.get("state")
                result["rowCount"] = (job.get("result") or {}).get("rowCount")
                result["outputTail"] = (job.get("output") or "")[-400:]
                break
        if result["state"] is None:
            result["state"] = "driver-deadline"
    finally:
        try:
            if process.poll() is None:
                process.stdin.write("qq\n")
                process.stdin.flush()
                process.wait(timeout=30)
        except Exception:
            process.kill()
        log.close()
        args.log.with_suffix(".result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
