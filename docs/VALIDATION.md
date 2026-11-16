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

`tools/test-release-privacy.py` also builds a fixture archive and checks that every profile linked by packaged `SUPPORT.md` is present with its exact source bytes and manifest hash, including the Win32kbase process-filter policy profile.

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

The semantic hive/timer/DPC row regressions exercise inspector Memory/Disassembly requests and native result binding, including NULL routines, stale context and attempts to reinterpret a routine as physical memory. Snapshot regressions compare earlier routine rows with their semantic row kinds: new fields remain Unknown, while a changed routine is still detected. This imported-v2 compatibility check does not expand the default snapshot collector set.

For live read validation, retain the loaded DLL hash and exact NT/CI image identities. Compare CI names/hashes/status, hive paths/flags/sizes, timer objects/due values, driver dispatch names/handlers and native SSDT entries with independent WinDbg reads. Compare device stack membership with `!devstack`, and distinguish verified empty NMI/DPC lists from unavailable layouts. Inspect actual rendered tables and address navigation as well as exported JSON.

The command-table audit exercised one stopped 28000.2952 x64 VMware target. Its CI and mapper collections contained 113 and 266 records; hive, timer, ETW logger and firmware collections contained 15, 192, 37 and 2 records. A follow-up compared all 192 timer objects, due values and decoded DPC addresses with native `!timer`: 84 had a DPC and 108 decoded to NULL. All 1,987 service entries matched native table reads (490 native and 1,497 registered win32k entry thunks). All 169 ALPC names/addresses matched a separate recursive native `!object` inventory of 57 directories and 1,678 objects. After `.cache flushall`, the ALPC traversal completed in approximately 53.5 seconds with no unknown or unreadable fields; its 120-second bound covers all directories together. Namespace reads requested approximately 64 KB and skipped names for 1,453 unrelated objects.

The subsequent ALPC global-list collector found 1,183 initialized ports: the same 169 named connection ports plus 507 unnamed client and 507 unnamed server communication ports. Every port address, owner EPROCESS, communication-info address, connection/client/server address, raw state, port type and name-presence classification matched a separate WinDbg typed-object inventory. All 169 full names matched the earlier recursive native `!object` inventory. Native `!alpc /p` and `!object` corroborated a connection/client/server sample, and `!alpc /lpp` corroborated the selected process's endpoints. All 84 owner PIDs matched `!process 0 0`; their short image names matched native `_EPROCESS.ImageFileName` reads exactly. The short field can differ from the longer image name shown by `!process`.

After `.cache flushall`, the final build's global-list traversal completed in approximately 70.5 seconds with no unknown or unreadable entries, using 4,115 reads requesting approximately 114 KB. The 120-second traversal bound excludes symbol discovery and owner-process inventory. Actual UI checks covered named and unnamed rows, client/server types, owners, connection names, address fields and consistent `Unnamed` labels in the table and row details.

The subsequent Shadow SSDT investigation reviewed all 1,497 service thunks and filtered wrappers on the same stopped target: 1,223 session dispatch thunks and 274 direct import/jump thunks. Native WinDbg reads captured 2,998 pointer bindings across two populated sessions, including the two filter helpers in each session. Each session had 38 NULL service implementations; its nonzero implementations currently matched the other session while its pointer slots differed. The raw-pointer inventory uses reviewed route offsets; separate native disassembly samples and offline instruction decoding corroborate those routes. One service also has a conditional watchdog fallback. Filtered wrappers can invoke policy helpers, reject the call or transfer to the original service, so that dispatch-only view does not infer per-process allow/deny decisions.

`Win32kDispatchRegression.h` exercises relocated thunk validation, changed code/call targets, session-specific pointers, NULL versus unreadable targets, direct-import disagreement, filter service-ID pairing, signed rejection values, snapshot identities and entry-only compatibility, cancellation, row/session limits, changed session bindings and serialized collection metrics. The Release build passed 1,505 native assertions and the bootstrap, UI policy and UI fault suites. Replaying the captured win32k code/tables and captured pointer bindings through the collector produced all 5,988 normal/filtered rows with no unknown or unreadable entries. The replay reconstructs pointer storage from the native inventory and uses synthetic ownership; live validation remains a separate check.

The final DLL then collected 6,478 rows in WinDbg after `.cache flushall`: 490 native entries plus 1,497 normal and 1,497 filtered entries for each of two populated sessions. All native table values and all session implementation targets, pointer slots, service names, raw encodings, filter helpers/imports, possible rejection returns and four conditional-fallback fields matched the native capture. Coverage was complete with zero unknown and unreadable entries; 152 rows represented verified NULL implementations. Session-dispatch traversal took approximately 33.6 seconds, using 251 reads requesting approximately 426 KiB. Its timer excludes profile discovery, native-table collection and subsequent symbol annotation; the shared traversal deadline also includes owner inventory and native collection. The target stayed stopped in its original process context. Actual UI checks covered service/session columns, normal and filtered rows, NULL labels, separate wrapper/implementation addresses and wrapper-to-Disassembly navigation. Live review also caught and fixed an omitted padding byte in the session-lookup code profile and missing initialization of serialized traversal metrics.

The process-filter follow-up used the same stopped 28000.2952 target and matched NT, win32k and win32kbase PDBs. Native `uf`/`dt` established the process flag bits, filter-set accessor, session lookup and bitmap test. An independent debugger script read 87 process policies and seven bitmap slots in each of two sessions. The extension's 87 summaries agreed on process identity, session, flags, set and every aggregate decision count. Two enforced processes in different sessions each exposed 1,497 service rows: 1,496 blocked and one allowed (`NtGdiExtEscape`). All service indices, names, bitmap bits, decisions, wrapper addresses and rejection-return values matched the native captures. A process with filtering disabled supplied the separate allow-path check. These checks compare policy evidence without executing a syscall or changing the implicit process. The final UI displayed service names beside decisions and sorting brought the single allowed service ahead of blocked services. Its final resource-only build retained byte-identical native `.text` and `.pdata` sections; the affected UI suite passed again.

The policy suite covers enforcement versus audit, NULL versus missing bitmap bytes, out-of-range sets, stale process identity, missing/changed helpers and wrappers, cancellation, and recheck changes adjacent to unreadable bytes. No audit-only process was present in this VM snapshot; that branch is covered by fixtures and the reviewed native predicate/handler code. The explicit `win32kDisable` fields describe GUI conversion separately from filtered-service decisions.

These are bounded observations, not an all-command runtime or cross-version certification. Shadow SSDT describes the first implementation call and its conditional filter route, not execution or nested dispatch. ALPC covers initialized objects linked in the reviewed global list, not detached/freed/not-yet-linked objects or pool discovery. Its named-namespace fallback still excludes unnamed ports and reports that gap. Full release-matrix, reconnect, target resume and nonempty NMI/DPC checks remain separate validations. Keep raw target captures private; publish only aggregate counts and reviewed image/code profiles.

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
