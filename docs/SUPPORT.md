# Supported sessions and limits

KNDbgX is an x64 preview extension. `Stable` in the command registry describes a typed command contract; it does not certify every Windows build or debugger. Kernel security collectors, field mutation and Data Model integration remain experimental. See [COMMANDS.md](COMMANDS.md) for each command's capability and session mode.

## Host and target requirements

Use an x64 Windows host and x64 WinDbg. Windows 11 with modern WinDbg is the primary environment; classic/system DbgEng is not broadly validated. The Microsoft VC++ x64 runtime is required. WebView2 Evergreen Runtime is needed for the optional UI; CLI remains available after UI initialization failure. Keep the bundled `runtime/dia/msdia140.dll` for PDB metadata access. The preview DLL is unsigned and does not alter host loading policy.

- **Live x64 user mode:** stopped-context reads, supported planned writes, breakpoints and execution controls.
- **User dump:** read-only inspection of available memory and metadata.
- **Remote live x64 kernel:** experimental collection over an already connected KD transport, plus supported writes and execution controls while stopped. KNDbgX does not configure the transport.
- **Local live kernel:** experimental, read-only. Requires operator-configured local KD; some hosts return `E_NOTIMPL` when attaching.
- **x64 kernel dump:** experimental, read-only. Commands marked LiveKernel remain unavailable; omitted pages and metadata reduce coverage.
- **WOW64/native ARM64:** unsupported for kernel collection and mutation. Paging support is x64 4-/5-level and requires a known target paging mode.
- **Data Model:** optional, requiring `IHostDataModelAccess`. Unsupported hosts retain CLI/UI results.

Physical/MMIO writes, minifilter callback modification, a separate UI process, TTD and Replay SDK integration are disabled. `features` reports unavailable optional features. Build and target-specific verification procedures are in [VALIDATION.md](VALIDATION.md).

## Symbols and kernel profiles

Kernel collection requires a matching image/PDB and validated field metadata. A public symbol address does not establish the private record's size or layout. Missing types cannot be repaired by repeatedly loading the same PDB. Available DIA and DbgEng metadata must agree; mismatches are not bypassed.

The source includes these compiled fallback profiles:

- NT image **26100.8655 x64**: [callbacks](../profiles/nt-26100.8655-callbacks-x64.json), [additional symbol/layout coverage](../profiles/nt-26100.8655-symbols-x64.json) and [native SSDT](../profiles/nt-26100.8655-x64.json).
- NT image **28000.2952 x64**: [callbacks](../profiles/nt-28000.2952-callbacks-x64.json), [PiDDB records](../profiles/nt-28000.2952-piddb-x64.json), and [ETW host-silo storage, NMI, unloaded drivers, firmware providers and native SSDT](../profiles/nt-28000.2952-symbols-x64.json).
- CI image with PDB **F660C9DA-4538-E0B7-62AA-C762F4FA8CDB**, age 1: [kernel hash-cache records](../profiles/ci-28000.2952-hash-cache-x64.json), observed with that 28000.2952 target. CI identity is checked independently of NT identity.

These profiles identify individual images, which can differ from the OS build number. Fallbacks require the exact image/PDB identity and required symbol RVAs; private record layouts additionally check target code windows. Editing profile JSON does not add support: the implementation is compiled into the extension. Missing pages, changed required code or contradictory metadata refuse the affected fallback. A profile match validates that layout, not whole-image integrity or another kernel version.

Routine annotation can load the owning module's PDB through the current WinDbg symbol path. Verified names retain their provenance; missing or rejected names use `module+RVA` when ownership is known. A pending symbol load can delay cancellation. Use [Context details > Symbols](UX.md#context-symbols-and-waits) to inspect one module's identity and type availability.

Shadow SSDT, private layouts on other images, encoded timer DPC pointers and other missing metadata can remain unverified. PiDDB and CI cache decoding require their exact reviewed image/PDB and code profiles. Timer metadata remains visible when its DPC cannot be decoded. Callback coverage includes declared notify, object and registry families, not every callback mechanism in Windows. Object flags are the operation mask; notify context and registry flags have different meanings.

## Interpretation limits

**Partial** results may contain useful observations. Missing pages, layouts, ownership, identities or budget-limited traversal prevent a complete conclusion. An empty Partial result does not establish absence; an external routine address or cross-view difference is not proof of a hook or hidden object.

- `!hiddenproc` on remote live KD compares target active-list and CID views. Process creation/teardown can produce differences, and a process absent from both views is invisible to that comparison. Verified local KD uses Toolhelp for its second view.
- `!handles` reads target process handle tables on remote live KD, requiring matched layouts and verified Process types. Verified local KD uses a host handle snapshot. Unreadable owner tables remain scoped gaps; VM-access rights alone do not prove injection.
- `!ci` requires verified local live kernel context. `/host` explicitly inspects the debugger host from other sessions or without a target; those flags do not establish remote-target CI/HVCI state. Unknown option bits retain known fields with Partial coverage.
- `!wfp`, `!dma` and `!byovd` require verified local KD because they use host BFE, firmware and driver-file APIs. Remote KD cannot supply those guest APIs/files.
- `!hv` labels host CPUID separately from target CR4. ACPI table presence does not establish active DMA protection. `!cr`/`!idt` use saved processor state; `!msrcheck` reads only a verified current event processor and leaves other CPUs unavailable.
- VAD endpoint samples and pool `/wx` first-page samples do not describe an entire allocation. A VAD display label is not verified page protection when the target mapping table is unavailable. Module disk comparisons use bounded, identity-matched samples, not a complete relocated-memory integrity check.
- `diagnose`/`triage` retain native extension text as Partial, even if DbgEng accepts a command. `driver-audit` observes an embedded signature using host trust policy; it does not evaluate catalog signing, revocation or target signing/HVCI policy. SARIF/ETL inputs are not automatically correlated with the debuggee. ETL import does not decode arbitrary WPP payloads or infer DPC latency from unrelated events.

Historical results retain their captured context. Process selection, implicit address space and register thread/CPU are separate. Context changes invalidate sensitive actions; matching numeric addresses alone cannot make an old result current.

## Resource and operational limits

- **Engine work:** one execution slot per session. Native calls can outlast cooperative deadlines; Busy or CancelRequested does not mean a call has finished.
- **Traversal:** generally 65,536 nodes and five seconds. Process inventory, callbacks and target handle scans use 30-second budgets; target CID comparison uses 120 seconds; minifilters use one 60-second traversal deadline after setup. Missing data or exhausted budgets remain Partial.
- **Planned changes:** at most 64 KiB per memory plan, 60-second expiry and one use. Context and original bytes are rechecked; partial writes have no automatic retry or rollback. Physical writes are disabled.
- **Retention:** up to 16 unpinned recent results and 128 protected open-tab results share 64 MiB. Up to 128 operation records remain in memory; completed records become eligible for expiry after 30 minutes, and acknowledged records may be evicted earlier. Results and receipts do not survive DLL unload.
- **File inputs/outputs:** memory/PE export and driver PE inspection are bounded to 64 MiB. SARIF input is limited to 16 MiB. ETL input is limited to 4 GiB, with 2,048 events by default, at most 16,384 events and a cooperative ten-second processing budget. Snapshot imports are bounded to 32 files, 64 MiB and 100,000 rows.

Fixture tests do not establish compatibility with every debugger, kernel, transport, live registration race or desktop configuration. Validate the intended target and physical floating-window/DPI/accessibility behavior separately.
