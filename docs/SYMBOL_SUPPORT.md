# Symbol resolution and kernel layout coverage

Symbol resolution and private-layout collection have separate requirements. Truncated symbol names are omitted; truncated module names reduce inventory coverage. Kernel string descriptors and nonempty buffers must stay in kernel address space.

KNDbgX resolves symbol addresses separately from storage layouts. A matching public PDB can name a global without describing its type, array length or private registration records. A missing type does not mean the table is empty.

The **Context details > Symbols** panel makes this distinction explicit for a selected module: load state, image/PDB match, PDB GUID/age, type metadata and an optional type/field query have separate results. Opening uses cached information; inventory and inspection are explicit stopped-x64 reads. Context/module identity checks reject stale results. **Insert reload draft** never runs `.reload` automatically. See [diagnostic workflow and limits](CONTEXT_DIAGNOSTICS.md#symbols-for-one-module); this UI adds no compiled kernel profile or layout authorization.

Collected virtual addresses use one shared annotation path after target traversal. It queries names through DbgEng and allows the owning module's PDB to load on demand from the existing symbol path. It does not skip a module merely because its symbols are deferred. Cancellation is checked between address queries; pending native symbol-server calls must return before cancellation can be observed. A loaded name must resolve back to its start in the containing module, and that start plus the returned displacement must equal the requested address. Synthetic `<PERF>` labels and inconsistent nearest names fall back to the module's exact RVA. Results retain `LoadedDebuggerSymbols`, `ModuleRva`, `Unavailable`, `NullAddress` or `NotRegistered` provenance; `symbolDisplacement` is known only for a verified loaded name. Auxiliary thread and IRP routine fields retain their own symbol sources. Address descriptions are verified before console output or navigation storage, so history and bookmarks retain the same binding. Physical addresses and addresses imported from a different dump are not interpreted with the current target's symbols. Snapshot comparison excludes these display annotations while retaining actual address and ownership changes.

Module-inventory base rows do not fetch deferred PDBs for every loaded module. A module already reported as `DEBUG_SYMTYPE_NONE` retains its fallback without repeating failed lookups for each address. After supplying a matching PDB or correcting the symbol path, explicitly reload that module's symbols in WinDbg and run the query again. A public symbol server does not necessarily supply every driver's exact PDB; a module/RVA fallback remains valid when native WinDbg also lacks the name.

The annotator caches reverse bindings, including lookup failures, by module base and qualified name for one result. Every row still validates its own address, displacement and containing range. No cache crosses result boundaries, so subsequent queries retry after symbol or target changes. This avoids repeated reverse lookups without bounding DbgEng lock or symbol-server waits.

Cancelled, stale-context and native-fault results retain their observations without additional symbol queries. The same guard applies when a collector finishes through its internal path. Console coverage reflects the final diagnostic partition, including records that could not be presented as observations.

Callback traversal has one thirty-second budget, started after the first table's layout preparation; subsequent callback families share it. Other collectors retain their existing traversal limits. Diagnostic rows are retained under `analysis.diagnostics`; moving them out of the observation table never promotes incomplete coverage to Success.

`LayoutResolver` requires a matching image/PDB identity for kernel addresses and corroborates available public RVAs. Fields, arrays, bit positions and function-pointer classification come from validated DIA metadata. Available DbgEng offsets and sizes must agree; a second API's inability to describe a field does not discard valid DIA metadata. An offset and storage size alone cannot replace missing bitfield or array metadata. Profile and type-alias fallbacks require proof that an unresolved member is absent from the matched PDB. Provider failure, ambiguity or a declared member with invalid metadata is not absence.

DIA activation first uses `runtime/dia/msdia140.dll` beside the extension, then the registered COM provider. If both are unavailable, it copies `msdia140.dll` from the already loaded DbgEng directory into a new private temporary directory. The standard DIA factory and BSTR allocator then belong to that private module; the extension does not share DbgHelp's allocator-configured DIA instance. Concurrent metadata readers share the copy, retain its module until their interfaces are released, and remove the copy after the final reader closes. File activation uses absolute paths. A failed PDB identity check is never retried with relaxed validation. A missing engine provider or unwritable temporary directory leaves an explicit failure; keep the bundled provider for hosts without this fallback. Process-layout failures retain the provider or metadata diagnostic in the result and console. Process traversal starts its deadline after layout discovery and never renews an already started budget.

After building Release, run `tools/run-engine-test.ps1 -WithoutAppLocalDia -EvidenceDirectory artifacts/engine-no-dia` to stage the extension and test host without the bundled provider and exercise the engine-provider fallback through the real DbgEng layout and mutation tests.

Negative field-cache entries retain their own failure diagnostic. Repeating a failed lookup after another field query reports the original field's failure; layout invalidation clears both the field and diagnostic caches.

Process and device-chain traversal deadlines start after required layout discovery. A deadline already started by the caller is not renewed. Process inventory has a 30-second traversal budget; ordinary device/list walks use five seconds. Cancellation and expiry are checked between reads, so a pending native call can outlast either budget and incomplete collection remains `Partial`.

Nested offsets require an embedded composite field. Pointer, scalar, array and bitfield storage cannot stand in for a containing structure. Array selection preserves the PDB leaf kind and validates the first dimension, total extent and stride before composing a member offset. Pointer paths require an explicit checked dereference.

Kernel list walkers validate every node as a kernel address before reading its link, including the first node and singly linked chains. Required routine slots report `NullRequiredRoutine` and reduce coverage when their value is zero. Optional HAL and pre/post-operation slots retain `NullObserved`; the existing object-callback check still rejects a registration with both operation routines missing.

Read queries can load deferred symbols or initialize DbgEng's local scope. Those notifications preserve the active read. Explicit reloads, symbol-path changes, unloads and external context changes still invalidate results and caches. The dispatcher restores query/context suppression depth after native exceptions and faults the session. Field misses and successful address/storage lookups are cached within a resolver's epoch. Unicode readers reuse the collector's resolver instead of reopening the PDB for every name.

Job polling, submission/cancellation acknowledgments and result inspection do not occupy result-history slots. This keeps a large result available while its pages are being read. UI inspection responses use a bounded transient text preview; the original stored result remains available in history.

## Metadata requirements

Collectors use `LayoutResolver` and DbgEng symbol/type queries under the requirements below. A completed bounded inventory describes its declared scope; it does not establish whole-system integrity.

| Consumer | Metadata requirements and behavior |
| --- | --- |
| `dt`, `x`, `ln`, expressions, disassembly, stack/source annotation | Deferred loading and scope notifications; complete DIA field descriptions; nearest-symbol coverage records the observed row. Display-only annotations can use the debugger's available symbols. |
| Process list/selection, `procctx`, threads, token | Matched process-list address; PDB links, scalar widths, nested fields and fast-reference bit widths. The existing mutation/context policy remains in force. |
| VADs and their page samples | Matched VAD fields and protection table. A verified 32-entry mapping supplements this exact kernel's untyped public global. Samples remain bounded to selected pages. |
| Driver objects, dispatch, device chains, ALPC and handle type resolution | PDB object headers, directory buckets and links; verified type/name table bounds. ALPC supports the PDB-described `CommunicationInfo` indirection when `ConnectionPort` is not a direct port member. Host handle inventory remains restricted to local live kernel sessions. |
| Notify/object/registry callbacks | Exact-identity callback profiles for the reviewed 26100.8655 and 28000.2952 images/PDBs; PDB metadata takes precedence and contradictions reject the fallback. Invalid nonnull routine addresses reduce coverage. |
| NMI and firmware providers | PDB fields when present; otherwise exact-identity registration/allocation/traversal code verifies private record fields. NMI nodes use a singly linked list; firmware records contain a separate list entry. |
| Host ETW logger inventory | Verified host-silo storage binding and PDB logger fields. Pointer metadata and kernel addresses are checked before reading child fields; the array extent is bounded before traversal. On the reviewed image, code verifies the unused slot value `1` and integer clock selector range `0..3`. Other unsigned representations remain `RawInteger`. Optional `ClockType` can be omitted only when the matched PDB proves its absence; lookup failure or invalid declared metadata reduces coverage. Unknown clock representations and null function clocks cannot count as decoded. Other silos are outside this inventory. |
| Unloaded drivers | Supports PDB-described inline arrays and the reviewed pointer-to-ring layout. The ring has 50 records, each 40 bytes; its wrapping next-write index is not an occupied-record count. Empty, invalid and unreadable records stay distinct. |
| Minifilters | Automatically loads the matched fltmgr PDB; resolves frames, filters and operation arrays. A partial layout from one named type is not overwritten by a different type alias. |
| SSDT, IDT, DPCs, timers, hive, HAL, PiDDB, CI hashes and mapper | Shared address/field validation and honest partial coverage. CPU enumeration restores the caller's context without treating internal scope notifications as external changes. Remaining gaps are listed below. |
| IRP/stack locations and typed field writes | Validated nested field bounds and scalar/bitfield distinctions. Private profile fields do not authorize typed writes. Existing plan identity, old-byte, epoch and approval checks remain required. |
| Module ownership, module PE inspection and diagnostic recipes | Module ranges use the debugger inventory; address names do not establish ownership or integrity. Diagnostic recipes retain host-extension text and partial coverage rather than parsing missing output as an empty inventory. |

## Exact-identity fallback

The [symbol profile](../profiles/nt-26100.8655-symbols-x64.json) covers the same NT identity as the callback profile: x64, timestamp `0x90b083da`, image size `0x1450000`, PDB GUID `11D7FE79-CC24-5612-0555-03EE86BB0E3E`, age 1. The profile name identifies the kernel image version, which can differ from the target OS build number. Build numbers alone never select a profile.

The compiled profile checks global RVAs and 18 relevant code/data windows before supplying missing information. `ObpInfoMaskToOffset` exposes only the four-byte prefix required for name lookup. The VAD profile checks all 128 mapping bytes and the PDB's five-bit protection field. NMI, firmware and unloaded-driver layouts are corroborated by allocation sizes, field stores and traversal/indexing instructions. ETW storage is tied to the server-silo getter and logger release/clock code. Existing typed symbols are never replaced merely because their metadata is malformed or contradictory.

The JSON file records the layout review. Editing it cannot enable another kernel. New identities require independent layout checks, negative tests and target-memory verification. A changed code window or missing dump page disables the affected fallback; this is layout corroboration, not an image-integrity verdict.

The [28000.2952 callback profile](../profiles/nt-28000.2952-callbacks-x64.json) selects x64 image timestamp `0xe1a9f520`, size `0x1459000`, PDB GUID `4660396C-2030-4C03-9AF4-5FC6B15ADF98`, age 1. Its compiled layout requires matching allocation, registration and enumeration code windows. It supplements callback layouts only; it does not enable unrelated symbol-profile fallbacks on this kernel. Every use still checks the matched image/PDB, required symbol RVAs and target code bytes.

Object callbacks retain one registration row with both routine addresses, separate ownership observations, symbols and the `OB_OPERATION` mask. Notify registration context and registry registration flags retain their own meanings. Table metadata, raw first-slot observations and coverage gaps are stored in `analysis.diagnostics`. The collector completes target traversal before optional symbol annotation so symbol lookup does not consume the linked-walk deadline. Annotation loads each needed PDB on demand and records a module/RVA fallback when a name is unavailable or fails address binding. There is no separate two-second annotation cutoff; a cold PDB request can delay later lookups. DbgEng retains loaded symbols for subsequent queries.

## Remaining coverage limits

Native SSDT, HAL and timer collection depends on the exact matched PDB/profile. The shadow SSDT, missing public HAL types, encoded timer DPC pointers, PiDDB private payloads and CI hash-chain layouts can remain unverified. These commands and the combined mapper retain `Partial` coverage with explicit gaps. Stack requests also return `Partial` when their frame budget is reached.

A compiled profile applies only to its exact image/PDB identity and required code windows. It does not establish compatibility with other kernels, live registration/removal races, other transports or live handle cross-views. Reader, IRP and mutation fixtures do not expand the supported kernel matrix; use the [validation procedures](VALIDATION.md) for target-specific checks.

## Reproduce

Run from the repository after building Release and use a new test-output directory. The script loads the extension without preloading NT symbols, executes 29 commands, retrieves every result page and compares NMI, firmware, ETW, unloaded-driver, VAD mapping and ALPC values with raw CDB reads. It requires the exact reviewed profile. Dump contents and test logs stay local.

```powershell
python tools/test-symbol-dump.py `
  --cdb C:\Debuggers\x64\cdb.exe `
  --dll x64\Release\kndbgx.dll `
  --dump C:\dump\livedump.DMP `
  --symbols 'srv*C:\Symbols*https://msdl.microsoft.com/download/symbols' `
  --evidence artifacts\symbol-dump-run
```

The separate `tools/test-callback-dump.py` verifies callback routine values, ownership and list sentinels.

Microsoft documents [deferred symbol loading](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/deferred-symbol-loading), the separate PDB/type-information fields in [IMAGEHLP_MODULEW64](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-imagehlp_modulew64), and DIA's [IDiaSymbol metadata](https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiasymbol). Private layouts were checked against the matching image, PDB and target disassembly recorded in the profile.
