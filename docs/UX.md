# KNDbgX workspace

Use the workspace to run commands, inspect captured results, manage debugger context and recover operation outcomes. See [COMMANDS.md](COMMANDS.md) for syntax, [CONTEXT_DIAGNOSTICS.md](CONTEXT_DIAGNOSTICS.md) for context and symbol diagnostics, and [SUPPORT.md](SUPPORT.md) for target restrictions.

The workspace combines command input, structured Results and Console output. **Inspect** contains the Processes, Memory, Disassembly and Registers views; **Row details** shows fields of the selected result row. Their visibility and width controls are independent.

The main workspace, floating Inspect group and individual views have an 8-pixel outer inset. Overlay panels and their resize handles follow the same inset. This spacing is independent of Compact/Comfortable row density.

## Workspace defaults

Results uses the remaining height rather than a fixed 280-pixel table. At ordinary paired-window widths, Inspect leaves at least 560 pixels for Results and Library opens as a drawer. At smaller widths, Inspect itself becomes a drawer. Console and Row details start collapsed; explicit visibility and density choices persist independently. **Windows > Restore adaptive layout** restores these defaults without changing captures or command drafts.

The Inspect drawer follows the current process strip and stays above command input when docking a view or wrapping toolbar/context text changes the layout.

**Windows** lists the four inspection views, with Show/Dock actions, **Dock all views** and **Bring windows into view**. Recovery restores minimized windows and clamps them to the main workspace monitor's work area. Existing X behavior remains compatible: the group hides, while an individual view returns to its tab. The menu explains this distinction and the limits of persistence. Compact/Comfortable density preserves virtual-row selection; the menu also contains shortcut help.

The toolbar distinguishes **Capture stack** and **Last event** reads from Results navigation. Recent captures and Open by ID share **Results menu**. **Navigate** exposes address history/bookmarks independently of Row details. **Capture info** describes the selected capture, while **Row details** describes one selected record. Empty workspaces offer supported stopped-context reads and command discovery; none runs merely because the screen opens.

Tool menus stay within the visible window and scroll when needed, including above Console and Inspect. Opening another tool menu, **Context details** or **Operations** dismisses the previous surface. Clicking or moving keyboard focus outside a tool menu closes it; **Escape** from within it returns focus to its toggle. Approval dialogs preserve the originating menu so cancellation can restore focus to its control.

## Find and run commands

Use **Find a command**, **Ctrl+K** or **Ctrl+Shift+P** to search names, aliases, syntax and recent input. Exact command names rank first. Arrow keys select an entry; Enter inserts an editable draft. Library entries and the **Kernel investigation** selector also insert drafts without executing them. Replace required operands, then press Enter or **Run**. IME composition never submits input.

Library group headers fold their commands. **Sort** selects Recommended or Name (A-Z); filtering temporarily reveals matches without replacing saved group choices. **Selected: ...** clears a hiding filter and focuses the current command. Group and sort preferences persist in the WebView profile when storage is available. Star a command to keep it in **Favorites only**. Alias search still inserts the selected alias as a draft. Input hints identify KNDbgX versus WinDbg direct routing and known preview/mode restrictions; they do not assert that an arbitrary engine command is read only.

**Tab** completes command names, aliases, help operands, selector prefixes and registered options. For example, `!threads et` becomes `!threads ethread:` and `!vad pid:4 /ex` becomes `!vad pid:4 /exec`. Required arguments appear as templates such as `irp <hex-address>`; Tab inserts the template and selects each field. Unresolved fields keep Run disabled, and Enter selects the next field. Completion does not invent addresses, PIDs, paths or approval tokens. Quoted/option-bearing input keeps its normal argument rules; Shift+Tab and empty input retain focus navigation.

Address operands also suggest loaded modules/symbols, for example `u nt!KeBug`. Up/Down selects and Tab completes the current operand while preserving later arguments. This works in Memory and Disassembly inputs too; selecting a suggestion never starts a read. Enter or Read does. Suggestions overlay the address input without moving its buttons. Physical-address inputs stay manual. For deferred symbols, load the needed module in WinDbg first, for example `.reload /f module.sys`.

Symbol suggestions require a current stopped context. Lookup does not evaluate expressions, reload PDBs or execute commands. All inputs share one pending request and the newest queued prefix; lookup waits 180 ms after typing, returns at most 24 entries and searches at most eight loaded modules for an unqualified prefix. Its cooperative 200 ms engine budget can be exceeded by a native call. After eight seconds the UI discards optional lookup results; that does not prove the call stopped. Required templates remain available. Escape, blur, IME, edits or changed context invalidate obsolete suggestions. Click/refocus an address input to retry an unchanged prefix after an empty or failed lookup.

With completion closed, **Up/Down** browses the 200-entry command history. Returning past the newest entry restores the unfinished draft, its selection and required-argument markers. Editing a recalled command starts a new draft. Stack, Event and other toolbar actions preserve input without submitting it, including when new history entries evict the recalled entry.

`command-schema` exports command definitions as JSON. Its previous spelling remains accepted for existing scripts but is omitted from the command list and completion.

`help ui` or `:help` displays workspace help. `help <command-or-alias>` shows grammar and session requirements. `ln`, `uf` and `source` default to the current instruction; memory displays and `u` use their separate continuation cursors. Process/thread/token defaults and explicit selector forms are in [Omitted targets](COMMANDS.md#omitted-targets).

For CI/HVCI, search `HVCI` in the Library to find `!ci` under **Kernel**, or search `/host` in the command palette. `help !ci` explains the scope, and Tab completes `!ci /h` to `!ci /host`. The registry has 126 commands and 20 aliases. Library groups aliases beneath their canonical command by default; all 146 names remain searchable. Selecting or completing a command only edits its draft.

In a remote session, `!ci` shows Unsupported and directs the user to explicit `/host` inspection. A host CI query with unknown option bits shows **Partial result** and a collection notice while retaining known fields. **Capture info** identifies the host source and `NotRequested` target correlation. For `!hv`, select each row in **Row details** to see `DebuggerHost`/`DebuggerHostCpuid` versus `Debuggee`/`DebuggeeRegister`. The Current process strip describes the selected debuggee independently of those row scopes.

## Status, execution and approval

**Context details** explains the last observed address space, debugger thread/CPU, register/scope information, last event and capture generations separately from the selected Processes row. Opening it uses cached data; **Refresh context** requests a new status observation. External `.trap`/`.cxr` origins stay Unknown. **Symbols** provides explicit module inventory and selected-module inspection, separating PDB identity from requested type/field availability. Its reload action inserts a command draft only. See [Context, operation waits and symbol health](CONTEXT_DIAGNOSTICS.md) for failure behavior and limits.

**Operations** observes active stages and elapsed times through host receipts without engine reentry. A cancellation request remains pending until execution finishes; internal wait causes remain unconfirmed. **Pause automatic inspection reads** suppresses automatic Processes/Registers/Follow IP refreshes while preserving manual reads and context checks. The preference persists and is visible in the Context button. Small Context and Operations drawers keep their close controls above scrollable content.

The **Current process** strip shows the selected kernel process name, decimal PID and full EPROCESS, independently of the selected result. Values copy on click. The bounded `ImageFileName` may be shorter than a full executable name. Missing identity is Unavailable; EngineBusy retains the last checked identity with a busy label. Running/disconnected targets and non-busy status failures clear it.

Status normally refreshes every three seconds while visible and idle, and every 500 ms during an execution transition. **Refresh context** requests an immediate check; it does not replace retained captures. Capture summaries label Debug target, Debugger host, Host + target or other documented sources separately from current/historical debugger context. Current context describes a retained snapshot, not a continuously live value. Initial, failed or malformed status, reopening and forwarded WinDbg commands lock target actions until valid stopped or explicit no-target status arrives. Busy preserves drafts and captures without submitting them automatically. No-target status permits debugger setup commands.

The header button switches between green **Continue** and amber **Break**, including with Inspect hidden. **F5** continues from any workspace tab. **F10 / F11** step over/into while Disassembly is visible, including in its own floating window, with a KNDbgX window focused. Continue/step requires a stopped live user or remote-kernel target and no active workspace operation. Dumps, local KD and unsupported sessions cannot execute.

**Break** sends an active interrupt independently of workspace **Cancel operation**. A confirmed running status enables Break even if Continue's completion receipt is delayed. **Breaking...** lasts until a fresh status confirms a stop or target change. An interrupt acknowledgement alone is not a stop. Failure or a wait exceeding ten seconds produces a message without repeating the interrupt; refresh status or inspect WinDbg before another attempt. WinDbg's own Break remains available.

Registered memory changes open a complete preview with one-use approval. Plans expire after 60 seconds; memory changes are limited to 64 KiB and recheck original bytes and target/context identity. Missing, cancelled, expired or stale plans cannot apply. Partial writes report their ranges without automatic retry or rollback. Physical/MMIO writes and minifilter callback modification are disabled. `setfield` accepts only verified 1/2/4/8-byte integer/bool fields, not pointer, enum, bitfield or composite writes.

There is no global Planned writes switch. Legacy `policy` / `gate` report its removal. Breakpoint Add/Delete uses explicit approval; Enable/Disable and execution buttons apply bound one-use actions on click. Those controls do not enable later memory writes.

Names outside the registry entered **manually in the UI** are forwarded unchanged to WinDbg, including quotes and command separators. Examples are `.echo hello`, `.formats @rip` and qualified external extension commands. They use WinDbg's semantics and may change the target or host without a KNDbgX preview. Registered names and aliases take precedence, so malformed `db` or `eb` stays a KNDbgX error. Forwarding retains text with WinDbg provenance and invalidates cached context and approvals. CLI and jobs require explicit `raw --ack-effects` for this path.

During work, the `knx>` marker shows the phase and elapsed time, including queueing, approval and output delivery. It is not a completion estimate. **Cancel operation** requests cancellation; duplicate clicks do not send repeated interrupts. **Cancellation unconfirmed** permits checking the same operation and trying Cancel operation again. Late replies cannot revive a cancelled preview or change a later operation. Completion restores the normal prompt; an unknown outcome is queried without replay.

## Inspect results

Each stored command result opens a tab; selecting it reads saved data without executing the command again. Tabs retain Rows/Findings selection, sorting, original row selection, columns and scroll positions. The toolbar's **Capture stack**, **Breakpoints** and **Last event** buttons open auxiliary views; **Results** returns to the active tab's command result. The retained **Inspect > Registers** panel is separate and leaves that result visible.

**Stack capture** shows the captured process name, Windows PID/TID and selected CPU above the frames, including when reopening a saved `stack` / `k` result. In x64 kernel sessions it identifies the selected implicit thread and its owning process, independently of the current address space or last-event thread. User-mode captures use system IDs. Hover for engine IDs and availability details. Sorting, paging and later context changes keep the original identity; missing identity and older captures stay **Unavailable**. The same context is retained in each frame and `analysis.stackContext`. Explicit `.cxr`/`.trap` contexts can override the stack's register context, and an address space belonging to another process can prevent correct user-mode unwinding.

- Double-click a label or press **F2** to rename. Enter or focus change saves, Escape cancels, and an empty name restores the command label. Names are limited to 128 UTF-16 units and do not change exports.
- Drag labels or use **Ctrl+Shift+Left/Right** to reorder. Left/Right, Home and End select focused tabs; Delete closes one. Right-click or Shift+F10 offers Close tab, Close other tabs and Close all tabs.
- Closing a tab releases its protection but does not immediately delete its stored result. **Results menu > Recent results** recalls up to 16 IDs seen by the document; **Open by ID** accepts a CLI result ID. Expired IDs report an error without command replay.
- Up to 128 open tabs protect results within the shared 64 MiB budget; up to 16 unpinned recent results share that budget. If a new result cannot fit without evicting protected data, retention fails. Close tabs and export important results before unload.

**Rows** and **Findings** have separate counts and pages. Finding-only results open in Findings. **Capture info** shows status, source, consistency, coverage, stop reason, limitations and result identity. **View output** retrieves saved console text, even after Output Off; it does not rerun the command. A zero-row Partial result does not establish absence. Oversized records use `RecordReference`; Export contains their originals. Inconsistent page counts produce an error rather than a silently shortened result.

Tables choose columns from the actual records. **Columns** selects fields, restores Recommended or shows all discovered paths. Up to 96 field paths are discovered, with nested columns two components deep; deeper objects remain in Raw record and Export. Recommendations show at most nine data columns, plus an Observation summary when needed. Unknown/null, absent, zero and false remain distinct. Display ellipses never truncate copied/exported values.

Click a header to toggle ascending/descending sort; **#** restores source order. Sorting covers the displayed collection, up to 100,000 records, loading remaining pages first. It preserves exact integer/address values and original action bindings. Unknown values remain last. A failed page load preserves the previous view. Export retains stored source order.

Drag a header's right divider to resize. Keyboard Left/Right uses 16-pixel steps, Shift uses 64; Home/End selects limits, Escape cancels, double-click restores the default. **Columns > Reset widths** resets the current collection. Data columns allow 64–4,096 pixels, the row-number column 48–4,096, and breakpoint Enabled at least 160. Open tabs retain their layouts; other layouts use a bounded 32-entry document cache.

**Row details** shows the selected row and Raw record. Drag its divider or use the same keyboard sizing controls. Its saved width is 240–800 pixels while leaving at least 320 pixels for Results; when Inspect leaves a compact data area, Row details opens over the table without reducing its width. Temporary constraints do not replace its preferred width. Double-click restores the responsive default. Resizing does not read the target.

Right-click a recognized address cell or Row details field for **Open Memory** / **Open Disassembly**. The host resolves the source result, original row and field again at dispatch. Physical addresses, including PA zero and DTB, open Physical Memory only. Flags, offsets, RVAs, timestamps and arbitrary hex strings stay copy-only. Null/unavailable pointers, historical results, expired sources and user addresses without the matching owning process cannot start a read. Offline file/diff records do not acquire current-target bindings. Discovery is bounded to 32 addresses and four path components per record.

For callbacks, **Callback address** selects Routine, Pre or Post independently, including after sorting. Object registrations keep paired Pre/Post values in one row. Not registered, Unknown and Unresolved have different meanings. Coverage gaps remain in Capture info and `analysis.diagnostics`, not blank observation rows. Verified symbols retain loaded-symbol provenance; unresolved names use module/RVA when ownership is known. Module-base names omit zero displacement. [SYMBOL_SUPPORT.md](SYMBOL_SUPPORT.md) explains loading and binding.

Minifilter Major labels use `IRP_MJ_...`; Row details/export retains the numeric code. `RoutineObservation` records a callback observation, including an optional unregistered routine, and is not itself a security finding.

### Shared inspection panel

**Inspect / Ctrl+M** shows or hides Processes, Memory, Disassembly and Registers beside Results. First use shows Memory; saved visibility/tab/width preferences take precedence. The left divider supports pointer and keyboard resizing. Small windows use a drawer. Hiding or changing tabs retains captures and does not cancel an active read. Selecting Memory/Disassembly alone does not read the target; visible Processes and Registers collect when their context needs refreshing.

### Floating inspection windows

The toolbar separates **Inspect** from result views and marks it with a panel icon and **DOCKABLE** badge. Its highlight indicates whether Inspect is shown; **Ctrl+M** toggles it.

Each view's **Float** opens it in its own movable, resizable native window, including from the floating Inspect group. All four views and the group can stay open together. **Dock** or that individual window's **X** returns only its view to the current Inspect group, retaining drafts, filters, captured data, selection and scroll. Its tab offers **Show window** and **Dock here**; **Dock all** returns every independent view.

Independent windows have a view-specific icon and accent, a visible **Dock** button, and a bottom status strip for execution state, process, PID and session type. The floating group shares this styling, with a workspace heading, four prominent tabs and a title-bar docking hint. State labels distinguish Stopped, Running, Working, Debugger busy and unavailable status; shared feedback appears beneath them. Hover the session type for the full debugger status. In compact windows, the content scrolls beneath the fixed heading while the status strip stays visible. Docking restores the compact in-panel heading.

Both individual views and **Float group** use standard Windows frames with the KNDbgX app icon, system menu, minimize/maximize buttons and resizable edges. Each has a taskbar entry for restoring a minimized window; **Show window** also restores an individual view. Windows renders the border and shadow according to the active desktop theme. Minimizing retains the document and differs from the close-button behavior described here.

**Float group** detaches the tab group while any independent views stay open. **Dock / Dock Inspect** returns the group without closing those independent views; the grouped window's **X / Hide** hides it, and **Inspect** reopens it. This differs from the individual window's X, which docks that view immediately.

Drag a floating window by its native Windows title bar to reveal drop guides. Release over **Dock to workspace** to return Inspect to the main window, or drop an individual view over the floating group's guide to join its tabs. If the group is floating, dropping an individual view onto the main window returns the group there as well; other independent views stay open. The guide highlights the active destination. Releasing outside a guide, cancelling the move with **Esc**, or dragging over a covering application keeps the window floating. Resizing alone does not dock it.

Closing/reopening the main window hides/restores all floating views while the same document survives. Explicit shutdown, unload or document recreation starts the next workspace docked. Popup, stylesheet or native visibility failure returns an independent view to Inspect. If the floating group cannot be shown or restored, the group returns to the main workspace. Docking does not allow an older native focus reply to override the newly focused tab.

Floating views share Busy/context checks, completion, Recent, copying and debugger shortcuts with the main window. A detached view remains visible when another main-window tab is selected or the docked panel is hidden. Process details still open in Results. Approval dialogs and the palette appear in the main window, temporarily hiding/disabling floating views, then restoring them. Cross-monitor DPI and physical keyboard behavior across hosts remain validation gaps.

### Processes tab

Processes collects `!dml_proc` on first use on a stopped kernel target and after a context change while visible. Search the retained inventory by image, PID or EPROCESS. Select a row for Open details, Threads, Memory (VADs), Token or Attach address space. Detail results leave the process list available; a narrow drawer hides to show Results. Hidden/inactive tabs retain their snapshots. **Refresh list** replaces a failed or expired capture.

Click a **PID**, **Image**, **EPROCESS**, **DTB** or **Created (FILETIME)** header to sort ascending; click it again to sort descending. The arrow marks the active direction. Tab reaches each header, and Enter or Space changes its direction. Sorting covers the entire collected inventory, preserves exact 64-bit values and puts unavailable values last in either direction. Equal values keep capture order. Filtering and refresh retain the chosen sort. Sorting keeps selection and actions bound to their original processes without reading the target again.

The list and selected-process details share the available pane height and scroll separately. In a short window, scroll the Processes pane to reach the details; the detail area keeps a minimum usable height. Changing Compact/Comfortable density preserves the selected process and adjusts the scrolled list without reading the target again. Floating and docking retain this state.

The inventory has a 30-second shared traversal deadline and 65,536-node limit. Pending native reads can exceed that cooperative deadline. Partial/failed/cancelled collection remains explicit; failed page retrieval preserves the prior list. Filtering does not recollect. Cancel operation during page delivery does not interrupt already completed engine collection. Failed prerequisite process selection does not expose intermediate process rows as thread/VAD/token results.

**Attach address space** requires a stopped x64 remote kernel or dump, readable matched identity and current source context. It rechecks process type, PID, creation time and DTB, selects the implicit process address space and verifies the result. Failed switching restores the old context; failed restoration faults the session. It does not resume, change thread/register context, reload user symbols or page memory in. Thread state can still belong to another process. User-mode/local-KD sessions cannot attach this way. `procctx` alone is a translation-DTB override, not an implicit process switch.

### Memory tab

Enter an address, symbol or expression such as `nt!NtBuildNumber`, `nt + 0x10` or `@rip`, then use Enter or **Read**. Blank input, command separators and quotes are refused. Successful reads replace the input with the resolved address; re-enter an expression to evaluate it again.

Expand **Read options** for Virtual/Physical and 64, 256 or 1,024 bytes. Virtual reads use DbgEng's selected process; a `procctx` translation override does not change them. Physical reads retain their kernel-target requirements. Display selects little-endian byte/word/dword/qword values without rereading. **Bytes / row** selects 8 or 16 and **ASCII** toggles the text column. These controls preserve bytes and selection and never initiate a read. The captured input remains in the context line/tooltip separately from the resolved range. Missing bytes are `??`; a numeric unit containing a hole has no numeric copy action. ASCII distinguishes readable nonprintable bytes from missing bytes.

Previous/Next range moves by the captured size and refuses address wraparound. Editing address, space or size disables navigation until a successful read. Context changes preserve the original capture but require explicit refresh. Failed/cancelled reads and invalid pages retain the prior view; the UI does not periodically reread memory.

**Read details** opens the saved capture's requested range, readable/unavailable byte counts, address space, implicit process, generations and capture kind. Click a `??` cell to inspect its row, or select a row and press Enter in the grid. Enter on a readable cell keeps its copy action, including held keys. Escape or **Close** returns focus to the details toggle. The panel follows Memory into a floating window and back; ordinary status updates preserve its reading position. A failed refresh is shown separately from the previous capture it did not replace.

New captures include the status, transferred count and HRESULT for each page-bounded read request. A short transfer can have a successful HRESULT, so the byte count remains independent of the error code. This follows the [DbgEng ReadVirtual documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugdataspaces-readvirtual). Physical reads report the final result of the existing physical-read fallback path. Missing metadata from an older host, or metadata inconsistent with the bytes, is labeled unavailable; the byte view remains usable.

The native capture kind and optional dump format flags are observed during the explicit memory command. The panel itself sends no RPC or target read. A failed read leaves its cause **Unknown**: it does not prove an invalid pointer, paging, a missing dump page or a wrong process. Mapping and page inclusion remain unconfirmed; dump origin (crash versus live capture) is not inferred from the generic dump kind. The panel shows saved read details; it does not run page-table or VAD diagnostics. It never runs `.pagein`, Continue or an automatic context switch.

Right-click a captured row's address for **Open Disassembly**. The action uses the original context and retained 16-byte source row, with a checked byte offset for an 8-byte display row. Offsets cannot escape the source row or overflow the address. Physical Memory cannot open Disassembly. Readable byte cells and ASCII cells remain copy-only. Expired captures do not fall back to manual reads.

Memory and Disassembly each keep up to 20 completed manual expressions in **Recent**, with at most 1,024 UTF-16 units per expression. Selecting an entry reads it in the current stopped context and current read size; Memory restores its address space. Disassembly Recent pauses Follow IP. Restoring settings never starts a read. Automatic Follow IP and breakpoint-maintenance refreshes do not enter Recent. Storage failure leaves document-local history usable; captures and target bindings are not stored in these lists.

### Disassembly tab

Enter a virtual address/expression and choose 16, 32 or 64 instructions. **Current IP** reads `@$ip`. Rows show addresses, decoded text, verified bytes, symbols and the saved IP marker. Raw native instruction text remains in the stored result. Unreadable/invalid initial instructions are Unavailable; a decoded prefix remains Partial. `uf` retains native function text as Partial because complete function coverage is unverified.

**Next instructions** follows the verified decoded boundary of a complete current view. **Previous view** restores up to 16 captures without reading or guessing backward boundaries. Changed context disables Next; failed/cancelled reads retain the previous view. Right-click an instruction address for **Open Memory**, using the original row/context and current byte count. Both directions preserve Results and work docked or floating.

**Follow IP** defaults On and remembers an explicit Off choice. A new live stop, breakpoint hit or completed step refreshes Disassembly at the actual IP without replacing Results or the command draft. A detached Disassembly view updates in its own window. If the docked Registers tab is selected, it stays selected while both views refresh; otherwise following can reveal Disassembly. Initial status establishes a baseline without an automatic read. Manual input, Next, Previous view or result-address browsing pauses following; Current IP or Follow IP enables it again. Automatic reads wait for active work and reject newer-context/Off/cancellation races. Hidden workspaces pause them; a later stop can reveal Inspect while following is enabled.

At a CALL, F10 runs through its return and F11 enters the callee. Follow IP shares DbgEng with other debugger windows. Reuse within one result avoids repeated reverse symbol lookups, but pending symbol, stack or Data Model queries can still delay status and reads. Reduce unrelated automatic inspection while investigating a slow step; this does not impose a latency bound on native calls.

### Registers tab

Open **Inspect > Registers** for a retained register view beside Results, or use its **Float** button to keep it visible with the other inspection windows. It reads the debugger's current stopped thread/CPU context on first use and after a new stopped-context status while visible. **Refresh** requests another capture, including after a failed read. Running targets, Busy and other active workspace operations disable new reads; hidden register views wait until shown again.

Filter by register name or **All / Pinned / Changed** without reading the target. **All** places pinned registers first, preserving capture order within the pinned and remaining groups. Unpin returns a register to its position among the remaining names. Pins retain names across documents; they do not retain captured values. Scalar values and raw vector bytes preserve their exact text; unreadable values display **Unavailable**, never an invented zero. **Changed** compares successive captures only for the same session, target and process/thread/CPU context. Copy a name or value on click, or use the context menu for a value or row JSON. Replacing/filtering register rows closes their old copy menu while preserving copy menus in other views.

The summary shows the captured process name, Windows **PID/TID** and selected **CPU**. In x64 kernel sessions the identity comes from the selected implicit thread and its owning process, independently of the selected address space. In user-mode sessions it uses Windows system IDs. Hover the summary for separate engine IDs, kernel object addresses and availability details. Missing identity stays **Unavailable**, and legacy engine IDs are never presented as Windows IDs. The identity is saved with the register capture; previous or partial captures keep their own summary. Some kernel registers remain processor-specific, and explicit `.cxr`/`.trap` contexts can override register values.

Running, context changes, cancellation and read/page failures preserve the last capture with a notice. Changed comparisons reset when the captured thread identity or implicit address space changes, even if the engine IDs stay the same. A failed automatic read does not loop at the same stop; use Refresh to retry. The view is read only. Process selection or **Attach address space** does not select a new register thread/CPU context.

Register browsing uses **Inspect > Registers**. The `registers [name]` / `r [name]` commands remain available for separate snapshots in Results, including export. They do not select or replace the retained Inspect panel.

### Breakpoint management

1. Stop a supported live target and choose **Breakpoints** to read its list.
2. Open **New breakpoint**, enter an expression and **Review and add** an enabled software code breakpoint through preview approval. **Delete** also needs approval. Existing data/deferred breakpoints can be managed in the list; creating them remains a WinDbg operation.
3. Use each row's **Enable/Disable** button or the selected-row toolbar for immediate bound actions. Sorting preserves original GUID/configuration identity. Changed/reused IDs, historical rows and failed refreshes cannot apply.
4. In Disassembly, filled/hollow BP markers show enabled/disabled code breakpoints. Click a marker or press **F9** to toggle. **+** permits an addition preview only with a complete current inventory; **?** is unknown/stale. Multiple breakpoints at one address open the list for selection.

**Refresh breakpoints** updates markers without decoding. Successful instruction-origin changes may reread the same instruction range; cancellation, failed inventory refresh or changed/Busy context suppresses that follow-up. An uncertain apply is never replayed: refresh before deciding on another action. Dumps/local KD/running targets cannot apply breakpoint changes.

A new breakpoint stop displays a persistent notification at the bottom right of the workspace. **Open Event** opens the Event view without replacing the command draft; **Dismiss** closes the notification while an unread mark stays on **Last event** until the current stop is opened. It does not take keyboard focus. The initial status is a baseline, and repeated polls or thread/symbol changes do not repeat a dismissed notification. Continue, a different stop or a target change clears it. Manual Break, single-step exceptions, dumps and local KD do not produce breakpoint-hit notifications. Notification delivery follows the workspace's status polling while visible; it is not a Windows desktop notification.

Notifications require available breakpoint-hit observation. If observation is lost, the notification is cleared; recovery establishes a new baseline without replaying the last recorded hit. Command-related stop-generation changes alone cannot create a hit notification.

Breakpoint notifications label **Current BP setting address** explicitly. The last-event API does not establish a reliable breakpoint stop IP, so that value remains unavailable rather than being replaced with the current register context. The setting is read by breakpoint ID at query time; it may have changed since the hit, may be a watched data address rather than an instruction, and may be unavailable after a one-shot breakpoint is removed. Exception events retain the exception-record address. The original address text remains exact when copied.

The last-stop card shows the target's process name, **PID**, **TID** and, for x64 kernel sessions, **CPU**. Kernel identity is read from the thread running on the event CPU and its owning process at capture; changing the selected implicit thread does not substitute that selection. This is an observation of the stopped target, not a historical process snapshot. Missing event, symbol layout or memory data stays **Unavailable**. Hover the context line for EPROCESS/ETHREAD, availability details and the separate engine process/thread IDs. In user-mode sessions the engine IDs are mapped to Windows IDs; an event thread in a different selected process remains unavailable without switching context.

**Breakpoints** and **Last event** show **Symbol** beside **Address** by default, using the existing address annotation (resolved symbol plus displacement, or module plus RVA when only module information is available). Deferred entries show their expression with a **(deferred)** suffix. The last-stop card also shows the symbol for the current breakpoint setting; that symbol does not verify the historical hit IP.

**Last event** opens Event with a separate last-stop card and breakpoint settings table. The last event remains in the exported source result but is not a settings row. Paging, sorting and row actions retain original source indexes. Matching breakpoint IDs are marked; this does not prove that their settings were unchanged since the hit. Each Breakpoint row includes its address (or deferred address expression), software/hardware trigger, data access and size, `/w` condition, on-hit command text, pass counts, debugger thread restriction, one-shot and go-only flags. Select a row in Row details for all fields. Condition strings are read from WinDbg's Data Model without evaluating them; an unavailable getter is shown as **Unavailable**, separately from **None**. Command-based `.if` conditions remain in the command text. Settings describe the current inventory, not a historical snapshot at the hit; a removed one-shot breakpoint may only remain in LastEvent.

### Copy values

Click a cell or Row details value to copy its full content; right-click/Shift+F10 offers value and row-JSON copying. In the grid, arrows select a row, Tab reaches its fields, and Enter/Space/Ctrl+C copies a focused field. Ctrl+C on the grid copies the selected row; ordinary selected text takes precedence. Escape returns to the grid. Copying does not execute debugger commands.

Strings copy as text; other values use JSON. Embedded NUL uses JSON string escaping. Missing fields have no copy action; a RecordReference copies the reference, so use Export for its original. If clipboard access fails, a read-only field exposes the exact text for manual Ctrl+C in the visible window. Console Copy is limited to displayed text; Clear removes only that display.

## Export and recovery

**Export** saves the complete retained result and output with completion hashes, using a temporary file and non-overwriting publication. It includes rows outside the viewport. Disk/permission failures identify the destination and Win32 code; disk-full messages include a `result-export <id> "<path>"` recovery command for another destination. Save before result eviction or unload. Success reports the path outside Console; **Capture info > Copy saved path** copies the last confirmed export path. Paths can also be copied from Operations. Files are not opened automatically.

Export participates in Queued/Running/Cancel operation controls. Eight seconds without a receipt triggers outcome queries, not a repeated save. Cancellation before publication leaves no final artifact; a completed publication retains its path even if cancellation arrives later. **Outcome unknown; checking** means the transport has not confirmed the result, not that execution failed.

**Output On / Off** controls new UI console text independently of panel collapse or stored results. Off retains existing text and Export while showing errors/outcomes outside the console. A muted or interrupted stream is not replayed when output returns; View output retrieves saved text explicitly. The console displays at most 262,144 UTF-16 units. Collection notices start with a concise expandable summary. Full errors and coverage details remain available. Ordinary confirmations disappear after five seconds; errors/warnings and result notices remain until dismissed/replaced. Dismiss changes presentation, not status or stale-action checks.

## UI recovery

Closing the window hides the document and preserves its draft, console, result tabs and inspection captures in the loaded extension. `!kndbgx` reopens it and waits for fresh status. Hidden workspaces pause periodic/automatic reads; already submitted work may finish. Explicit shutdown, extension unload, debugger exit or failed-document recreation releases this state. It is not a disk-backed session restore.

Library layout/favorites, Inspect preferences, Row details width, Console visibility, density, register pins, Follow IP, output preference and Recent lists persist separately when browser storage is available. Malformed/unavailable settings fall back to defaults or document-local state. Floating placement and captured bytes/instructions are not persistent settings.

GPU/utility recovery may preserve a surviving document. Browser/main-renderer loss discards pending approval plans and shows the exact failure stage/HRESULT with **Retry UI**. A fresh handshake is required; commands are never replayed. There is no global write policy to restore. The native boot/handshake watchdog is 15 seconds.

**Operations** opens a separate drawer containing host operation records from current/prior documents, their phases/outcomes, retained result links and saved paths. Acknowledged background status/symbol reads leave this history so polling does not displace user operations. Active or unacknowledged reads remain recoverable. It works with Console collapsed or Output Off. **Refresh outcomes** only queries receipts; it never replays work. Unavailable or mismatched receipts remain Unknown. A failed page refresh preserves the previous list and its last successful check time; an incomplete first load is labeled explicitly. At most 128 records remain in memory; completed entries become eligible for expiry after 30 minutes, and acknowledged entries may be evicted earlier under pressure. Active work never expires. Result content has its own retention budget, and records end at DLL unload. If an outcome is absent/expired, inspect saved results/files before resubmission; absence does not prove no side effect occurred.

## Keyboard and layout

| Shortcut | Action |
| --- | --- |
| Ctrl+K / Ctrl+Shift+P | Find a command |
| Ctrl+L | Focus command input |
| Ctrl+B / Ctrl+J / Ctrl+M | Toggle library / console / Inspect |
| F5 | Continue a supported stopped live target |
| F9 in Disassembly | Toggle an existing code breakpoint or preview an addition |
| F10 / F11 with Disassembly visible | Step over / into, including with a floating view |
| F2 on a result tab | Rename |
| Ctrl+Shift+Left/Right on a result tab | Reorder |
| Shift+F10 on a cell/tab | Open its context menu |
| Escape | Dismiss transient UI or cancel an active edit/preview |

Narrow layouts wrap Results controls. When docked Inspect leaves a compact data area, Row details opens over the grid; without Inspect, narrow or short windows place it below the grid. Library/console/inspection panels can be collapsed independently. Dialogs trap and restore focus. Text/icons accompany colors, and CSS supports reduced motion and forced colors. OS Narrator speech and physical contrast-theme switching remain untested.

Builds run bootstrap, policy and fault frontend suites. The separate Edge suite checks product assets against fixture replies; the DbgEng harness checks owned native processes and WebView2. Use the [validation procedures](VALIDATION.md) for these checks and for separate target-specific testing.
