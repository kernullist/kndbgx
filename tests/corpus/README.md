# Parser regression corpus

`src/selftest/PureRegression.h` constructs the PE32, PE32+, multiple-module
minidump, minimal minidump and fill inputs using Windows SDK structures. The
tests invoke the same parsers and fill planner used by the shipping handlers.
They also run 2,000 deterministic malformed-input iterations (seed 0x4b4e4458).

`json-invalid.txt` lists UTF-8 inputs that must be rejected. This is an input
corpus, not a JSONL artifact: deliberately malformed JSON is its purpose.
Escaped lone surrogates are rejected. Correct paired UTF-16 surrogates are
preserved. Duplicate object keys are rejected regardless of their value.

From the repository root in PowerShell, run `.\tools\run-selftest.ps1 -Configuration Release`. Real debugger,
WebView2 and kernel/PDB support must be established by separate integration
tests; this corpus does not establish those claims.

See [validation](../../docs/VALIDATION.md) for the separate integration and release workflows.
