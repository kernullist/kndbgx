# Build verification and release packaging

Run checks against the source and binaries intended for release. Keep the source revision, DLL hash, tool versions and target image/PDB identity with the results under ignored `artifacts/`. Packaging validates its inputs; it does not establish that every test was run.

## Prerequisites

- Visual Studio 2022 C++ tools (v143), a Windows 10/11 SDK and PowerShell.
- Node.js for frontend regressions and Python 3.11+ for release tooling.
- Installed x64 WinDbg for engine integration; WebView2 Evergreen and the Microsoft VC++ x64 runtime for UI/native execution.
- Microsoft Edge and Node-resolvable `playwright` for the separate browser fixture suite.
- WDK only for `samples/snapshot-demo`.

Use a separate checkout/output when a debugger has the canonical DLL loaded. Run commands from the repository root and check each exit status before continuing.

## Build and quick checks

```powershell
.\tools\build.ps1 -Configuration Release -RunTests
python tools\release.py check-docs
python tools\release.py check-deps
```

`check-docs` compares `docs/COMMANDS.md` and `docs/command-contract.json` with the compiled command registry. After a command change, rebuild and regenerate with `python tools\release.py docs`; do not edit generated output manually. `docs/acceptance-map.json` is test input consumed by `tools/check-acceptance.py`, not a release guide.

## Release validation

Use a new evidence directory and ZIP path for each run:

```powershell
New-Item -ItemType Directory -Path artifacts\release-check -ErrorAction Stop
.\tools\validate-release.ps1 -EvidenceDirectory artifacts\release-check -SkipEngine *> artifacts\release-check\validation.log
.\tools\run-engine-test.ps1 -Configuration Release -EvidenceDirectory artifacts\release-check\engine *> artifacts\release-check\engine.log
python tools\check-acceptance.py artifacts\release-check\validation.log artifacts\release-check\engine.log
python tools\release.py check-docs
python tools\release.py check-deps
python tools\release.py check-privacy
python tools\release.py package --output artifacts\KNDbgX-local-check.zip
```

The validation script rebuilds Debug/Release solution and direct projects, runs native/frontend regressions and privacy tests, checks reproducible Release artifacts, and tests an invalid SDK configuration. `-SkipEngine` requires the separate engine run above for the full procedure; `-ReleaseOnly` is a reduced gate. The engine harness owns its test process and creates test dumps using the installed WinDbg runtime.

The packager accepts Release only. It checks generated docs, dependency hashes, binary hardening, matching local PDB identity and publication policy, then verifies the archive. Existing output paths are refused. The ZIP contains the DLL, DIA runtime, MIT license, user guides and their selected screenshots, command metadata, profile descriptions, third-party notices, a release manifest and an SBOM. PDBs and raw session exports remain local. The source manifest hashes current tracked bytes and records a dirty worktree; it does not attest to test completion or include untracked source files.

## Additional and target-specific checks

```powershell
.\tools\run-engine-test.ps1 -Configuration Release -WithoutAppLocalDia -EvidenceDirectory artifacts\engine-no-dia
.\tools\run-engine-test.ps1 -Configuration Debug -EvidenceDirectory artifacts\engine-debug
node tools\test-ui-browser.cjs artifacts\ui-browser-check
python tools\test-live-kernel-harness.py
```

The first command exercises the engine DIA fallback. Browser fixtures use product assets with synthetic replies. The live-harness unit tests do not connect to a kernel; the actual `test-live-kernel.py` lifecycle can start, reset or resume a guest.

For matched x64 kernel dumps, `tools/test-symbol-dump.py` and `tools/test-callback-dump.py` compare collected values with native CDB reads. Use each script's `--help` for paths and required profile/target inputs. Other dump, local-kernel and live-KD scripts likewise require their own configured targets; running fixture suites does not replace these checks.

On the intended target, compare reads with native WinDbg across process/thread changes and reconnects; check missing pages, incomplete lists, cancellation and slow symbol/engine calls. Compare IRP observations with native `!irp`, `!devstack` and `!drvobj`. Verify floating-window input, docking, DPI and accessibility on the intended desktop. The snapshot-driver sample's signing, guest loading and Driver Verifier checks are separate from extension validation. Record unperformed checks explicitly; [SUPPORT.md](SUPPORT.md) defines the supported claims.

### Command record tables

Audit the compiled registry against both collector rows and default UI columns. A list link, tree node or nested collection envelope is not a substitute for the command's record identity. Keep structural fields in row details where they remain useful for navigation.

`CommandRecordRegression.h` covers CI cache payloads, counted names, unreadable memory, cycles, traversal limits, cancellation, profile rejection and flattened mapper coverage. `test-ui-faults.mjs` checks command-specific fields, including zero/false values and missing routine symbols. These synthetic checks do not prove a private layout on another image.

For live read validation, retain the loaded DLL hash and exact NT/CI image identities. Compare CI names/hashes/status, hive paths/flags/sizes, timer objects/due values, driver dispatch names/handlers and native SSDT entries with independent WinDbg reads. Compare device stack membership with `!devstack`, and distinguish verified empty NMI/DPC lists from unavailable layouts. Inspect actual rendered tables and address navigation as well as exported JSON.

The command-table audit exercised one stopped 28000.2952 x64 VMware target. Its CI and mapper collections contained 113 and 266 records; hive, timer, ETW logger and firmware collections contained 15, 192, 37 and 2 records. A follow-up compared all 192 timer objects, due values and decoded DPC addresses with native `!timer`: 84 had a DPC and 108 decoded to NULL. All 1,987 service entries matched native table reads (490 native and 1,497 registered win32k entry thunks). All 169 ALPC names/addresses matched a separate recursive native `!object` inventory of 57 directories and 1,678 objects. After `.cache flushall`, the ALPC traversal completed in approximately 53.5 seconds with no unknown or unreadable fields; its 120-second bound covers all directories together. Namespace reads requested approximately 64 KB and skipped names for 1,453 unrelated objects.

These are bounded observations, not an all-command runtime or cross-version certification. Shadow SSDT does not resolve per-session dispatch destinations or the separate filtered table; ALPC excludes unnamed ports, private namespaces and shadow directories. Full release-matrix, reconnect, target resume and nonempty NMI/DPC checks remain separate validations. Keep raw target captures private; publish only aggregate counts and reviewed image/code profiles.

## Publication boundary

`python tools/release.py check-privacy` scans tracked and visible untracked files for known credential patterns, personal/build paths and raw session addresses/process IDs in Markdown. Diagnostics print categories rather than matched values. The scan cannot establish that arbitrary sensitive prose or unknown credential formats are absent; review public files and commit messages too.

Optional private project/customer terms belong in the ignored `.publication-terms.local.json`:

```json
{"terms": ["Example Client", "private_prefix"]}
```

`check-privacy` and `package` load this file when present. To require a particular policy, pass `--private-terms-file <private-policy.local.json>`; a missing or malformed explicit policy fails. Policies are excluded from packages and source manifests.

Keep full PDBs, dumps, logs, result exports, private profiles and raw media local. `docs/images/` and `docs/videos/` are reserved for private captures and rejected by publication checks, even if force-added to Git. Byte scans do not review image pixels or video frames. Cleaning the current tree does not remove older Git objects or existing archives.

`docs/screenshots/` contains the selected lab screenshots used by the README and [workspace guide](UX.md). Review visible content before adding or replacing one: omit unrelated applications, personal paths and private target information. The published examples retain their lab addresses and observed status so the workflow can be understood; they are documentation examples, not exhaustive compatibility evidence. The packager lists each image explicitly and does not collect raw captures by directory glob. Keep capture provenance, DLL hashes and additional session evidence under ignored `artifacts/`.

PNG publication checks validate chunk boundaries, CRCs, image layout and the complete compressed raster before excluding pixel data from text scans. Metadata remains scanned, including compressed text and color profiles. Invalid images, trailing payloads, metadata above 4 MiB and decoded rasters above 256 MiB are rejected. These checks do not read text drawn in pixels; inspect screenshots visually and use OCR as an additional check. Park the pointer outside the captured window and update captions when a fresh capture changes counts or status.
