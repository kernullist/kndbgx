"""Check source traceability and executed assertions; this is not branch coverage."""

import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SELF_GATE = "release.all-failure-ids-have-executed-product-assertions"


def read_log(path):
    data = path.read_bytes()
    return data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig").replace("\r\n", "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=pathlib.Path)
    args = parser.parse_args()
    mapping = json.loads((ROOT / "docs/acceptance-map.json").read_text(encoding="utf-8"))
    entries = mapping["findings"]
    expected = {f"F{i:02}" for i in range(1, 51)}
    if len(entries) != 50 or {entry["id"] for entry in entries} != expected:
        raise ValueError("Expected exactly F01-F50")
    logs = "\n".join(read_log(path) for path in args.logs)
    if re.search(r"^\s*(?:\[FAIL\]|FAIL\s)", logs, re.MULTILINE):
        raise ValueError("A supplied test log contains failed assertions")
    passed = {match.strip() for match in re.findall(r"^\s*(?:\[PASS\]|PASS)\s+(.+)$", logs, re.MULTILINE)}
    if "release.validation-run-complete" not in passed or "engine integration failures: 0" not in logs:
        raise ValueError("Complete release validation and actual engine test results are required")
    if not re.search(r"^[1-9][0-9]* passed, 0 failed$", logs, re.MULTILINE):
        raise ValueError("Completed native regression summary missing")
    missing = []
    for entry in entries:
        product = ROOT / entry["productPath"]
        if not product.is_file() or not entry["assertions"] or not entry["tests"]:
            raise ValueError("Missing product or tests: " + entry["id"])
        source = "\n".join((ROOT / name).read_text(encoding="utf-8-sig") for name in entry["tests"])
        for assertion in entry["assertions"]:
            if assertion not in source:
                missing.append(f"{entry['id']} assertion absent from test source: {assertion}")
            if assertion != SELF_GATE and assertion not in passed:
                missing.append(f"{entry['id']} no executed PASS: {assertion}")
    if missing:
        raise ValueError("\n".join(missing))
    print(f"PASS {SELF_GATE}")
    print("50 finding IDs traced to product paths and executed assertions. Synthetic fixtures do not establish real kernel support.")


if __name__ == "__main__":
    main()
