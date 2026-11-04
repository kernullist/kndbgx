# Validation

Run these procedures against the source and binaries you intend to use. Record the source revision, DLL SHA-256, compiler/SDK versions, debugger/runtime versions and target image/PDB identity with each result. A version string alone does not identify a build. Store logs, dumps and receipts under ignored `artifacts/`; test output is not a user guide or a compatibility certificate.

## Prerequisites

- Visual Studio 2022 C++ tools (v143), a Windows 10/11 SDK and PowerShell.
- Node.js for frontend tests and Python 3.11+ for release tooling.
- Installed x64 WinDbg for DbgEng integration; WebView2 Evergreen and the Microsoft VC++ x64 runtime for UI/native tests.
- Microsoft Edge and `playwright` resolvable by Node for the separate browser fixture suite.
- WDK only for the independent snapshot-driver sample.

Use a separate checkout/output for release rebuilds when another debugger has the canonical DLL loaded. A generated package does not prove that the test suites were run.

## Reproduce

Run from the repository root and use new output directories under `artifacts/`. Check each command's exit status before continuing.

Build and run native/frontend regressions:

```powershell
.\tools\build.ps1 -Configuration Release -RunTests
python tools\release.py check-docs
python tools\release.py check-deps
```

Exercise installed DbgEng/WebView2 with an owned process and generated dump:

```powershell
.\tools\run-engine-test.ps1 -Configuration Release -EvidenceDirectory artifacts\engine-release
.\tools\run-engine-test.ps1 -Configuration Release -WithoutAppLocalDia -EvidenceDirectory artifacts\engine-no-dia
.\tools\build.ps1 -Configuration Debug -RunTests
.\tools\run-engine-test.ps1 -Configuration Debug -EvidenceDirectory artifacts\engine-debug
```

Run the independent browser fixtures and live-harness unit tests:

```powershell
node tools\test-ui-browser.cjs artifacts\ui-browser-check
python tools\test-live-kernel-harness.py
```

The harness unit tests do not connect to a kernel. The normal `test-live-kernel.py` lifecycle can start, reset or resume a guest; it is not a substitute for read-only inspection of an existing debugger session.

## Release validation

The acceptance map is an executable test input: [acceptance-map.json](acceptance-map.json) binds product paths to assertions consumed by `tools/check-acceptance.py`. Keep it with the test suite. Generated [command metadata](command-contract.json) and [command documentation](COMMANDS.md) must match the compiled registry.

```powershell
New-Item -ItemType Directory -Path artifacts\release-check -ErrorAction Stop
.\tools\validate-release.ps1 -EvidenceDirectory artifacts\release-check -SkipEngine *> artifacts\release-check\validation.log
.\tools\run-engine-test.ps1 -Configuration Release -EvidenceDirectory artifacts\release-check\engine *> artifacts\release-check\engine.log
python tools\check-acceptance.py artifacts\release-check\validation.log artifacts\release-check\engine.log
python tools\release.py check-docs
python tools\release.py check-deps
python tools\test-release-privacy.py
python tools\release.py check-privacy --private-terms-file .publication-terms.local.json
python tools\release.py package --private-terms-file .publication-terms.local.json --output artifacts\KNDbgX-local-check.zip
```

Create the local private-term policy described below before running the explicit policy commands. `-SkipEngine` without the separate engine run, or `-ReleaseOnly`, is a reduced gate. Packaging rejects stale generated documentation, private inputs and existing output paths; it checks binary/dependency metadata and verifies the archive, but does not run the full test suite. Fixed inputs produce a deterministic ZIP.

`tools/review-evidence.py` can produce a source/artifact/assertion receipt for a caller-supplied review map. Its `create` command requires an explicit `--mapping` file and the corresponding executed logs; use `create --help` for required inputs. Keep run-specific maps and receipts local.

## Target-specific validation

Fixture tests, owned user processes, dumps and live kernels establish different scopes. Record the exact target and operation; distinguish Success, Partial, Unavailable, Refused, CancelRequested and unconfirmed outcomes. An accepted command or cancellation request does not establish completion.

- Compare context-bound reads with native WinDbg values before and after a process/thread change, continue/break and reconnect. Retained results must remain historical until recaptured.
- Check kernel collectors with matching symbols and explicit positive/negative cases. Private profiles apply only to their exact image/PDB identities and required code windows. See [symbol test procedures](SYMBOL_SUPPORT.md#reproduce) and [operator kernel validation](KERNEL_ANALYSIS.md#operator-kernel-validation).
- Check unreadable pages, incomplete lists, live registration races, cancellation and native-engine delays on the intended target. A cooperative budget cannot interrupt a pending DbgEng call.
- Verify real floating-window input, DPI changes, docking and accessibility on the intended desktop. Browser fixtures do not establish those host behaviors.
- Treat the independent snapshot-driver sample's build, signing, guest loading and Driver Verifier checks as separate work. Its own README describes those requirements.

The [support matrix](SUPPORT.md) describes current compatibility and interpretation limits. No fixture or single kernel identity establishes support for other hosts, architectures, builds or transports.

## Publication boundary

`python tools/release.py check-privacy` checks Git-tracked and visible untracked files for credential patterns, personal/build paths and raw target addresses/process IDs in Markdown. Documentation paths use generic example roots or known OS/tool installation roots; other absolute drive paths are rejected. Public text inputs must be UTF-8 without embedded NUL bytes. Diagnostics report categories, never matched values. Pattern checks cannot establish that arbitrary sensitive prose or unknown credential formats are absent; review the actual files and commit message before publication.

Private project or customer identifiers belong in the ignored `.publication-terms.local.json`:

```json
{"terms": ["Example Client", "private_prefix"]}
```

Supply actual terms only locally. `check-privacy` and `package` load this file when present. Matching is case-insensitive; spaces, underscores and hyphens between configured word parts are interchangeable and may be omitted. Require a particular policy with `--private-terms-file <private-policy.local.json>`; an explicitly selected missing file, duplicate JSON key or malformed policy stops the operation. An in-checkout policy must use a recognized local-only path; an external file is also accepted. Zero reported private term rules means no private-name policy was loaded. Policies are excluded from packages and source manifests.

`docs/images/` and `docs/videos/` are private raw-capture directories. Publication checks reject them even after forced tracking or deletion of an indexed file's working copy. Original screenshots, recordings, full PDBs, dumps, logs, private profiles and result exports remain local. Byte-level scans do not inspect image pixels or video frames; sanitized media requires its own content review.

Packages include the extension, its required redistributed runtime, current guides, compiled-profile descriptions, dependency notices and manifests. They exclude full PDBs, raw session data and run-specific reports. The manifest fingerprints current bytes of tracked source files; it does not assert that every recorded test was rerun for that source. Cleaning current files does not remove older Git objects, existing archives or remote caches.
