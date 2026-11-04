# Context, operation waits and symbol health

Use Context details, Operations and Symbols to inspect observed debugger state and run explicit diagnostic reads. For target restrictions, see the [support matrix](SUPPORT.md).

## Context details

Open **Context details** in the current-process strip. Opening the drawer uses the most recent status and capture data; it does not submit an additional engine read. Ordinary status polling continues. **Refresh context** requests a fresh observation through the existing worker. It does not refresh retained Results or switch processes.

The drawer separates these values:

- **Selected Processes row** is a UI selection. Selecting a different row does not attach its address space.
- **Virtual address space** shows the debugger's implicit EPROCESS and the last observed process name/PID. A translation DTB override is listed separately; it does not mean that every memory operation uses that DTB.
- **Registers / debugger thread** is a debugger ID, not an OS thread ID. A CPU number is shown only when DbgEng's processor-to-debugger-thread mapping confirms the candidate. Otherwise it remains Unknown. The implicit ETHREAD is a separate value.
- **Current scope** contains the observed instruction, stack, frame address and frame index. The origin of an external `.trap` or `.cxr` register context remains Unknown; an instruction pointer cannot establish that origin.
- **Last event observation** retains its existing location provenance. A current-scope fallback is labeled accordingly and is not promoted to a verified stop address.
- **Observed generations**, **Selected result capture** and **Inspect Registers capture** distinguish current observations from older captured data.

Running, disconnected, Busy or changed contexts can leave the previous observation visible with an unconfirmed/historical explanation. Unknown values remain unknown. **Show Processes** opens the existing inspector; its Attach address space action retains all existing target and identity checks. Manual expressions, source-bound navigation and physical reads keep their existing distinct contracts.

## Operations while waiting

Open **Operations** to see the last host-observed stage, total elapsed time, time in that stage, time since progress, and elapsed time since a recorded cancellation request. While open and visible, the drawer queries active operation receipts about every 1.5 seconds. Closing it stops this additional polling. Receipt reads do not enter DbgEng, execute commands or replay saves.

If a receipt becomes unavailable, malformed or cannot be bound to the displayed operation, its outcome becomes **Unknown** with a refresh instruction. The previous Running/CancelRequested label is no longer shown as current. A completed receipt received by live polling is acknowledged after it is displayed; Acknowledged is shown only after the host confirms it. Hiding the document stops subsequent queued queries from this additional observation loop after the in-flight query returns.

Work already submitted can still finish. The separate recovery timer for pending worker requests remains enabled while hidden. It is armed for four seconds when the request is sent and rearmed after each recovery reply that leaves the worker request pending; response latency and timer scheduling can lengthen the interval between checks. Hiding the window does not cancel that work.

Observed stages are worker queue, worker processing, debugger-context query, symbol API call, target-memory API call, engine-command call and retained outcome. These are instrumented call boundaries, not a diagnosis of the engine's internal wait. A long symbol API call does not prove a network download; a long memory API call does not prove a transport fault. Unobserved wait causes remain unconfirmed. Some uninstrumented work can remain at the broader Worker stage.

**CancelRequested** means cancellation was recorded; execution has not completed. A native call may need to return before cancellation can be acted on. Completed operations freeze their elapsed timing and show delivery state separately. Existing result recovery, delivery acknowledgements, expiry and retention rules remain unchanged. Short module-inventory pages leave history after acknowledgement, as background status and completion reads already do; active/unacknowledged pages remain recoverable.

**Pause automatic inspection reads** suppresses automatic Processes refresh, Registers refresh and Disassembly Follow IP reads, including floating views. It persists in the WebView profile when storage is available and is off by default. The context button and affected view summaries visibly indicate the paused state; an enabled Follow IP shows **IP follow suspended** while the global pause applies. Manual reads, context checks, execution eligibility and explicit cancellation remain available. This preference does not cancel an operation already in progress or suppress WinDbg's own panes. Clear it when automatic inspection should resume.

## Symbols for one module

1. Open **Context details > Symbols**. Previously observed information is shown first. No module inventory or PDB load is requested merely by opening the section.
2. Use **Read modules** in a known, stopped x64 context. Inventory responses contain up to 64 module slots per page. One click reads up to eight pages; **Read more modules** continues, up to 4096 displayed modules. Invalid entries and truncated names remain unavailable rather than being guessed. The backend rejects inventories exceeding 65536 loaded slots.
3. Select a module and use **Inspect selected module**. Leave Type/Field empty for metadata-only inspection. To test a specific layout query, enter a simple type such as `_EPROCESS` and an optional field such as `UniqueProcessId`. Each operand accepts up to 128 ASCII letters, digits or underscores; arbitrary expressions, nested field syntax and command fragments are rejected.
4. Read **Load state**, **Image / PDB match**, **PDB identity**, **Type metadata** and **Query result** separately. A matching PDB can still lack the requested field. Successful type size/offset values are symbol observations, not authorization for a private-layout collector or a memory write. Zero offsets remain valid values. Native failures include their HRESULT when available.
5. **Insert reload draft** places `.reload /f <module>` in the command input and closes the drawer. Review it before running. Inspection never executes that draft, changes the symbol path, forces mismatched symbols, or reloads every module. A reload can still fetch symbols and block when the user explicitly runs it.

Metadata-only inspection does not deliberately resolve deferred types. An explicit type/field query can cause DbgEng to load that selected module's symbols using its existing configuration and can wait for a native call. Use Operations to observe the last boundary and cancellation state.

Both requests verify the full session/context stamp. Selected-module inspection also rechecks base, image size, timestamp and checksum before and after the query. A stale page or late result cannot replace current data. Previous successful observations are retained and marked historical; reread the inventory before inspecting after a context change. Unsupported/missing module metadata produces Unknown, never an inferred match.

## Implementation and compatibility

`hello` advertises `contextExplanation.v1`, `operationObservation.v1` and `symbolHealth.v1`. The UI does not send new symbol requests or enable operation-stage polling when the corresponding capability is absent. Basic cached context information remains useful with older hosts. Existing RPC envelopes remain `kndbgx.rpc.v3` with strict parameter shapes and string representations for addresses, counts and durations.

The symbol worker methods are `symbolModules(cursor, expectedStamp)` and `symbolHealth(moduleKey, typeName, fieldName, expectedStamp)`. They share the existing executor, cancellation and stamp rules. Module names used for reload drafts are separately constrained. No path, server credential or PDB file path is added to diagnostic replies. Operation observation uses bounded host memory and does not call the engine from the UI/control thread.

This feature does not add kernel-build support, a new transport, automatic reconnect, cold-cache performance guarantees, proven deadlock detection, private-symbol recovery or a saved investigation format. Deferred/unknown/mismatched states and separate type availability describe evidence; they do not promise a remedy.
