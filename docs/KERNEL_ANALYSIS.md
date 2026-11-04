# Kernel and driver analysis

KNDbgX provides typed decoders, a PDB-bound IRP reader, bounded file imports and fixed read-only WinDbg diagnostic workflows. Kernel collectors remain Experimental; consult the [support matrix](SUPPORT.md) and [validation procedures](VALIDATION.md) before interpreting their results. A command invocation or retained native diagnostic text is not a complete positive feature test.

Use `!kndbgx` before each command in WinDbg. The embedded UI accepts the command directly. The **Kernel investigation** selector inserts an editable command and never executes it automatically. Results use the existing stored result IDs, row inspector, export and Data Model paths.

## Start with the question

| Investigation | Entry point | Follow-up |
| --- | --- | --- |
| Crash or KASAN failure | `bugcheck`, `triage crash` | `stack`, `diagnose errrec <address>`, `diagnose blackbox-ntfs` |
| Hang, IRQL, deadlock | `triage hang` | `diagnose irql`, `diagnose running`, `diagnose deadlocks` |
| IRP and IOCTL handling | `irp <address>`, `ioctl <code>` | `diagnose iovirp <address>`, `diagnose devstack <address>` |
| Power and PnP | `triage power` | `diagnose devnode <address>`, `diagnose device <address>` |
| WDF ownership and queues | `triage wdf mydriver` | `diagnose wdf-queues <WDFDEVICE>`, `diagnose wdf-request <WDFREQUEST>` |
| Pool and memory pressure | `triage memory` | `diagnose pool <address>`, existing `!pool`/`vtop`/VAD collectors |
| Network driver | `triage network` | `diagnose net-adapter <handle>`, `diagnose net-oid <handle>`, `diagnose net-cx <NETADAPTER>` |
| Storage or USB device | `triage devices` | `diagnose storage-adapter <device-object>`, existing driver/device collectors |
| Build artifact | `driver-audit "C:\evidence\mydriver.sys"` | Match file SHA-256/PDB identity to the target before correlation |
| Static analysis | `sarif-import "C:\evidence\results.sarif"` | Inspect suppressions, source locations, code flows and raw results |
| Recorded events | `etl-import "C:\evidence\driver.etl" 2048` | Inspect provider, activity ID, timestamp, PID/TID, event ID and metadata availability |

Numeric decoder inputs and diagnostic addresses are hexadecimal by default; `0x` is accepted, and `0n` explicitly selects decimal. ETL row limits are decimal by default. Diagnostic operands accept literals, not debugger expressions. Module operands permit ASCII letters, digits, underscores, hyphens and dots; no paths, whitespace, switches or command suffixes. WDF recipes remove a final `.sys` from the module name.

## Typed observations

`!ci` reads the public `SystemCodeIntegrityInformation` flags only in a verified local kernel session.
Use `!ci /host` to explicitly inspect the debugger host from another session or without a target. Rows retain
`scope=DebuggerHost`; remote targets and dumps never inherit host CI state implicitly. API/status/length failures
produce null flags and Unavailable. Unknown option bits are retained with Partial coverage. CI debugger mode and
HVCI enabled, audit, strict and IUM flags are independent; private `ci!g_CiOptions` has a different contract.
The default query checks target identity through dispatch completion and returns StaleContext if it changes.
Explicit `/host` observations remain independent of target switches.

`!hv` retains separate host CPUID and debuggee CR4 rows. Host hypervisor hardware registers require the advertised
leaf range and vendor-neutral `Hv#1` interface. Unsupported leaves remain null, distinct from a supported zero mask.
Neither observation establishes remote VBS state or system integrity. See the
[support matrix](SUPPORT.md#interpretation-limits) for interpretation limits.

`!snapshot` bundles include `unloaded-drivers` with collectorVersion 3 and the existing snapshot v2 schema.
Unload events use verified name, address range and unload time; moving ring slots do not create changes, while
repeated unloads at a reused address remain distinct. Missing/duplicate identities, incomplete inventories and
cross-session events stay Unknown. Comparisons with older bundles lacking this collection remain Partial;
recapture both sides for full collection coverage. Ring eviction is not evidence of deliberate history erasure.
Imported Success/complete metadata does not override a missing row identity: that collection cannot establish
Added/Removed events until all identities are known. Matched known rows can still be compared.

Remote big-pool collection reads the matched PDB's `_POOL_TRACKER_BIG_PAGES` layout. The global variables and the full table must lie in aligned kernel storage without address overflow; invalid storage returns `Unavailable` before the table is read. `NumberOfBytes` remains a byte count, freed slots are skipped, and an unverified pool class remains unknown.

Process names, including `image:NAME` and bare names, require a complete process inventory so a second matching process cannot be missed. If enumeration is partial, select a recorded `pid:PID` or `eprocess:ADDRESS` instead. An EPROCESS address outside the collected list still requires a successful typed-object read. This applies to process listing, thread/VAD/token inspection and `procctx`.

`!cr` and `!idt` use the matched PDB's `_KPRCB.ProcessorState.SpecialRegisters` for each CPU, and label the source `SavedProcessorState`. They do not change the selected debugger CPU. Saved state can lag a running target; these values cannot establish system-wide integrity.

`!msrcheck` reads LSTAR, CSTAR, STAR, FMASK and EFER directly only when the selected processor matches the debugger's event processor. Other CPUs have null values and `ProcessorSwitchRequired`; an unverified mapping reports `CurrentEventProcessorUnverified`. Select another CPU with WinDbg's native `~Ns`, wait for its break prompt, and rerun. Automatic CPU switching is avoided because a remote KD switch can finish after an extension's context restoration. Saved PRCB fields are not treated as authoritative current MSR values. A multi-CPU result is therefore `Partial`, even when every MSR on the selected CPU is readable. No cross-CPU comparison or hook verdict follows from that partial result.

`ioctl <code>` separates device type, function, method, access requirements and vendor bits. The full 16-bit device type and 12-bit function are retained. It does not send a device request or conclude that a dispatch routine is vulnerable.

`ntstatus <code>` decodes severity, customer/facility/code fields and the signed `NT_SUCCESS` condition. A message is added when the host's English ntdll table contains one; the message source is identified separately from the target.

```text
ioctl 0x8000e007
ntstatus 0xc0000005
bugcheck-decode 0x1f2 <target-address> 8 <target-address> 0x187
```

`bugcheck` obtains the stopped kernel target's code and four parameters through DbgEng. `bugcheck-decode` accepts five explicit numbers without a target. KASAN 0x1F2 adds the accessed address, access size, instruction pointer, read/write flag, shadow byte and any uninterpreted parameter bits. Offline decoded addresses are not associated with the active target for navigation. Other recognized bugchecks retain their names and all parameters; parameter interpretation remains in the host diagnostic.

`irp <address>` requires a stopped x64 kernel target and matched nt PDB layouts. It reads the bounded allocation, validates the IRP type/size, stack count, current location and current stack pointer, and decodes every available stack slot. Rows contain status/information, requestor mode, cancel/pending state, buffer pointers, major/minor functions, completion flags, device/file objects and IOCTL lengths. Callback symbols and image ownership, plus device-to-driver dispatch observations, are added when readable. Unknown fields remain null and reduce coverage. Slots can be unused or stale; user buffers are never dereferenced.

## Kernel callback ownership

Run `!kndbgx !callbacks` at the WinDbg prompt, or `!callbacks` inside KNDbgX. The scan runs as a job; `!kndbgx jobs` and `!kndbgx job <job-id>` retrieve its status and complete structured output. The CLI initializes the target stamp before submitting the first job, so no warm-up command is required.

The collector covers process, thread and image notification arrays; process, thread and desktop object callbacks; and registry registrations. Rows retain the registration address, routine, owning module and layout source. Object rows separate PreOperation from PostOperation and include the operation mask. A null optional object routine is valid when the other routine is present. Registry rows also retain altitude, context, cookie and the unregistering bit.

Public symbols can name a callback table without describing its extent or private entry types. Missing metadata produces `Table extent unavailable from matched PDB` or `Callback entry fields unavailable`. Repeating a symbol reload cannot create metadata absent from that PDB.

The [26100.8655 callback profile](../profiles/nt-26100.8655-callbacks-x64.json) supplies three 64-slot notify tables, 0x18-byte notify blocks, 0x40-byte object entries and 0x50-byte registry entries. It applies only to x64 NT with PDB GUID `11D7FE79-CC24-5612-0555-03EE86BB0E3E`, age 1, timestamp `0x90b083da` and image size `0x1450000`. Runtime checks also require exact symbol RVAs and the family's code windows. The profile name follows the kernel image identity, which can differ from the target OS build number. Build number alone never selects the profile.

Matched notify/object PDB fields take precedence. The fallback completes missing fields only when any existing metadata agrees. Fast-reference bits and `_OBJECT_TYPE.CallbackList` still come from the matched PDB. Registry decoding requires the verified profile. Missing pages, altered code, unrecognized kernels, inconsistent list links, invalid routines or unknown ownership keep coverage Partial. `Success` means completion of these declared families, not enumeration of every callback mechanism in Windows.

The separate [28000.2952 callback profile](../profiles/nt-28000.2952-callbacks-x64.json) supplements callback layouts only; it does not enable the 26100.8655 symbol-profile fallbacks on that kernel. See [exact-identity requirements](SYMBOL_SUPPORT.md#exact-identity-fallback) for both identities and their limits.

Compare routine addresses, module ownership and list sentinels with native WinDbg reads for the intended target. See the [callback and symbol checks](SYMBOL_SUPPORT.md#reproduce) for test procedures.

## Host diagnostics and triage

`diag-catalog` lists every recipe, operand type, exact command prefix and reference. `diagnose <recipe> [operand]` accepts only a registered recipe. The current catalog has 53 entries across crash, hang, Verifier, I/O, power, memory, WDF, NDIS/NetAdapterCx, Storport and USB.

The eight triage profiles are `crash`, `hang`, `io`, `power`, `memory`, `wdf`, `network` and `devices`. The optional module scopes Verifier observations and WDF commands; `wdf` requires it. A profile reports attempted and skipped steps, checks the original session/target/stop state before every step, stops on engine/context failure, and uses a 30-second cooperative deadline between steps. One slow host extension call can outlast that deadline; Stop requests an engine interrupt.

The adapter captures debugger system/process/thread/processor and scope, runs a fixed read-only command, then restores that context. If capture or restoration fails, the failure is reported. Each response retains the exact host command, engine acceptance, context-restoration outcome and bounded output. The engine can accept a command whose extension prints an error; therefore host text is always **Partial / HostDiagnosticUnparsed**, never a machine-verified diagnosis. Missing extension DLLs, private symbols, Verifier history, IFR records or dump pages remain visible in that text. These commands do not enable Verifier, change boot settings, install drivers, start tracing or permit arbitrary extension switches.

NDIS recipes omit capture-file and application-launch switches. Verifier uses the fixed read-only flags `3`; changing flags and `-disable` are not exposed. DML output, if present, is displayed as plain text; its links cannot execute commands in the UI. A blackbox recipe depends on the host extension and the corresponding dump stream.

## Inspect driver files and import results

`driver-audit` reads one file under a read handle that denies writes/deletion. It reports SHA-256, machine, subsystem, entry RVA, image size, timestamp, section permissions, KASAN section presence, CodeView GUID/age bytes, imports and PE hardening declarations. Load-configuration observations include the security-cookie VA, GuardFlags, CFG function count and EH-continuation count when the structure provides them. A writable/executable section is a review finding, not a malware verdict.

Import rows retain the raw lookup value. An unavailable or out-of-image IAT slot has a null `iatRva`; invalid ordinal bits and unavailable hint/name bytes reduce coverage. A missing CodeView record is distinguished from malformed or unreadable debug metadata through `debugMetadataComplete`. The latter makes the audit Partial. These checks follow the [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) and do not replace the Windows loader or validate every PE directory.

The embedded Authenticode check uses the same file handle and host trust policy with cached resources. It reports the numeric trust status. Catalog signing, revocation and the target's kernel signing/HVCI policy are not evaluated. A missing embedded signature does not imply an unsigned driver. Delay imports are explicitly reported as unenumerated when present. File addresses/RVAs are not target addresses.

`sarif-import` accepts UTF-8 SARIF 2.1.0. It keeps producer/run metadata, rule definitions, severity, suppressions, baseline state, source locations and raw result objects, including code flows. Driver rule IDs/indices and message IDs/arguments are resolved when available. Extension-component rules and external property files remain unresolved and make the result Partial; they are preserved rather than assigned another component's defaults. Artifact URIs and base IDs are retained without opening URLs or source files. Imported results are analyzer claims, not independently confirmed defects.

SARIF `resultKind` preserves `pass`, `open`, `informational`, `notApplicable`, `review` and `fail`. Nonfailure results use `StaticResult` rows with severity `none`; they do not inherit a rule's error level. Explicit severity takes precedence over a matching invocation override, then the rule default. Overrides resolve driver rule IDs/indices; missing, conflicting or unsupported references remain unknown. Message braces are unescaped even without arguments, and unresolved placeholders retain raw data with Partial coverage. A run with unavailable results still retains its producer and invocation records. This importer does not perform full SARIF schema validation.

`etl-import` uses OpenTrace/ProcessTrace to consume an existing ETL file. It retains exact 64-bit FILETIME timestamps and keywords, provider/activity GUIDs, event ID/version/opcode/task, processor index, PID/TID, TDH provider/task/opcode names when available, and at most 256 raw payload bytes per event. It does not interpret arbitrary payload schemas, WPP/TMF messages, call stacks or calculate DPC latency from unrelated events. Lost events, lost buffers, unavailable metadata and row/time limits make coverage Partial. Header decoding has synthetic regression coverage; real driver ETL/KD interpretation remains an operator validation item.

Target observations become StaleContext when the target/context stamp changes, including observations already marked Partial. Offline file data does not become stale solely because the debugger target changes. Cancellation preserves an existing InternalFault or StaleContext diagnosis. If result retention fails, the original failure and stop reason remain visible alongside the retention error; no stored result ID is returned. A native handler fault resets internal context-event suppression to the caller's scope and leaves the session faulted for reconnect.

## Memory and mapped-image export

`dump-raw <address> <length> <path> [/phys]` writes the requested memory range. `dump-pe <module|address> <path>` resolves a loaded module and writes its complete mapped image. Both preserve an existing destination and publish a new file only after every requested byte has been read, the target context still matches and the temporary file has been flushed. A failed read, cancellation, context change or file error removes the temporary output.

`dump-pe` validates the DOS header, NT header and section table before exporting. The required header range may exceed one page; parsing is bounded to 64 KiB and 96 sections. The output format is `MappedPeImage`: section bytes remain at their virtual offsets. It is not a reconstruction of the original disk PE, and missing or discarded pages are not filled with zeros or copied from a disk file.

Once range export begins, coverage counts are bytes. `expectedEntries` is the requested length, `visitedEntries` counts bytes requested from the reader and `readEntries` counts valid bytes returned, including a short final read. Bytes not returned remain `unknownEntries`: one incomplete block read does not establish the page state of the entire remaining range. `unreadableEntries` is not used to infer that all those bytes are inaccessible. An incomplete memory read stops with `ReadFailed`; cancellation and engine faults retain their own statuses. A failed write or commit can have all bytes read while `complete` and `artifactCommitted` remain false.

For an incomplete read, `analysis.firstUnreadAddress` and `analysis.firstUnreadOffset` locate the first byte not returned. The offset is an RVA for `dump-pe`. `readAddress`, `readRequestedBytes` and `readTransferredBytes` describe the last memory request. The console also prints the failure address, offset/RVA and total bytes read. These values describe the observed read, not the cause of a missing page; compare `!pte` and native memory reads when investigating it.

## Budgets

DPC/timer and object-directory walks start their five-second traversal budget after the initial symbol/layout lookup and first processor or bucket read. Later CPUs, buckets and child directories share the same deadline. This prevents setup from exhausting the walk before it starts; it does not make a slow serial KD walk complete. DPC/timer metadata includes `completedQueues` and `expectedQueues`. These count fully traversed queues, including empty queues, rather than timer/DPC objects. Unreadable or interrupted queues remain outside the completed count.

`!minifilter` and its `!fltmgr` alias use a 60-second traversal budget after layout and ownership discovery. All frames, filters and operation arrays share that deadline; entering another filter does not renew it. This gives slow remote KD reads more time than the general five-second limit. Entry/row bounds, pointer validation, `IRP_MJ_OPERATION_END` checks and cancellation remain active. The command still reports Partial for an exhausted budget, unreadable pages or incomplete registrations; it does not convert unknown data into a complete result. A pending DbgEng read must return before cancellation or expiry can be observed.

Minifilter results contain a `Minifilter` row for each filter's object, name and altitude, followed by `RoutineObservation` rows for its operation entries. `Minifilter.PreOperation` and `Minifilter.PostOperation` identify the callback phase. These are address/ownership observations, not detections of a hook or malicious driver; a zero optional callback means Not registered. The table's **Major** column displays `IRP_MJ_...` names, including FltMgr's byte-valued pseudo operations. Records retain the original numeric `major` and add `majorName`; the Inspector and export expose both. Sorting and cell copying use the displayed name. Unknown operation codes display `IRP_MJ_UNKNOWN (number)`, and older results without `majorName` retain the numeric display. Snapshot comparison uses the original code and ignores the derived minifilter label.

| Operation | Bound |
| --- | --- |
| IRP allocation and stack | 65,535 bytes, 64 slots; PDB types at most 4 KiB |
| Host diagnostic output retained per step | 262,144 UTF-16 units; engine capture also bounded |
| Triage | 30 seconds between steps; no hard interruption guarantee inside DbgEng |
| Minifilter traversal | 60 seconds after setup; 65,536 visited entries and rows; 256 operation records per filter, requiring the end marker |
| PE file | 64 MiB; 256 import descriptors, 4,096 thunks per descriptor, 8,192 total rows |
| Memory export | 64 MiB; 64 KiB per memory read; mapped PE headers through the section table at most 64 KiB |
| SARIF file | 16 MiB bytes; 8 Mi UTF-16 parser units, 200,000 nodes, depth 32, 64 runs, 4,096 results |
| SARIF normalized labels/messages | 512 / 2,048 UTF-16 units; raw data remains retained within overall result limits |
| ETL file/import | 4 GiB; default 2,048 events, maximum 16,384; 10-second cooperative processing budget |
| Shared result retention | Up to 16 unpinned recent results and 128 protected open UI-tab results share 64 MiB; oversized results may be refused; export before eviction/unload |

## References

The implementation uses the existing DbgEng backend and does not configure Verifier, tracing, boot policy or driver signing. External tool setup remains separate from the read/import commands above.

- [IOCTL definitions](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes), [IRP inspection](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-irp), [KASAN](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/kasan) and [WDF debugger extensions](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/debugger-extensions-for-kmdf-drivers).
- [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier), [NDIS extensions](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ndis-extensions--ndiskd-dll-), [Storport](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-storagekd-storadapter) and [USB tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-usb3kd-usb-tree). `diag-catalog` retains per-recipe references.
- [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) and [ProcessTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace).

## Operator kernel validation

For a matched-symbol x64 kernel dump or stopped KD target, compare `irp` with `!irp <address> 1`, including an unused stack, a completed/cancelled request, METHOD_NEITHER and a missing page. Compare the callback/dispatch ownership with `!devstack` and `!drvobj`. Check process/thread/CPU/scope before and after `diagnose` and cancellation. Exercise unavailable WDF/Verifier/blackbox data and a reconnect during triage; results must remain Partial/Unavailable/Stale rather than complete. Verify file identity before correlating SARIF/ETL with that target. No actual kernel correctness claim is based solely on the fixture suite.
