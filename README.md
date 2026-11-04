# KNDbgX

English · [한국어](README.ko.md)

KNDbgX is an x64 WinDbg extension for debugger navigation and Windows security inspection. Its CLI, embedded WebView2 workspace and optional Data Model views share structured results, debugger context and coverage information. The extension itself installs no kernel driver.

**Context details** explains the current debugger context and selected-module symbol health. **Operations** shows operation stages, waits and retained outcomes. **Memory > Read details** shows saved read ranges, transferred bytes and native errors without rereading the target. See the [diagnostic workflow](docs/CONTEXT_DIAGNOSTICS.md) and [workspace guide](docs/UX.md).

Kernel collectors and Data Model integration remain **Experimental**. Missing layouts, unreadable pages and collection limits remain explicit; a partial inventory is not proof of object absence or system integrity. Compatibility is bounded by the [support matrix](docs/SUPPORT.md).

## Build and load

Building the extension requires Visual Studio 2022 C++ tools (v143) and a Windows 10/11 SDK. Scripts discover Visual Studio through `vswhere`. Node.js is required for frontend tests; Python 3.11 or later is required for release tooling. WDK is needed only for the separate snapshot-driver sample. The UI requires WebView2 Evergreen Runtime, and the binary requires the Microsoft VC++ x64 runtime. CLI remains available if UI initialization fails.

```powershell
.\tools\build.ps1 -Configuration Release -RunTests
.\tools\run-engine-test.ps1 -Configuration Release -EvidenceDirectory artifacts\engine-check
```

The engine test starts its own user-mode process and creates test dumps using an installed WinDbg runtime. Keep the generated `runtime/dia/msdia140.dll` directory beside `kndbgx.dll` when copying the build.

Release ZIPs exclude PDBs and raw session data. Keep full build output, dumps and exported results local; see the [publication boundary](docs/VALIDATION.md#publication-boundary) before sharing artifacts.

Load it in x64 WinDbg:

```text
.load C:\path\to\kndbgx.dll
!kndbgx version
!kndbgx status
!kndbgx help
!kndbgx
```

The last command opens the workspace. Use `!kndbgx <command>` in WinDbg and `<command>` in KNDbgX. `help ui` explains the workspace; `help <command-or-alias>` shows syntax and session requirements. The [command reference](docs/COMMANDS.md) is generated from the compiled registry.

## Work with the debugger

- **Find a command / Ctrl+K** inserts an editable draft. Tab completes registered syntax and loaded symbols; it never executes a command. Up/Down recalls history and restores unfinished input when returning past the newest entry.
- **Inspect / Ctrl+M** opens Processes, Memory, Disassembly and Registers beside Results. Each view's **Float** opens its own window, including from a floating group, so all four can remain visible together. **Dock** or the individual window's close button returns that view; **Dock all** restores all four. Drag the native title bar onto a workspace or group drop guide to dock. Inputs, captured data, selection and scrolling are retained. **Float group** detaches the whole tab group while individual windows stay open. **Row details** is the selected-result detail pane and has its own visibility and width controls.
- **Inspect > Registers** refreshes on a new stopped context while visible, shows changed values and raw vector bytes, and supports name filtering and copying. Running, unreadable or failed captures retain the previous values with an explicit notice. This view uses the debugger's current thread/CPU context; selecting a process does not switch register context. `registers` / `r` create separate command-result snapshots.
- **Windows** restores the adaptive layout, selects Compact/Comfortable density and brings detached windows into view. **Operations** shows retained outcomes, opens retained results and recovers completion status after UI recreation without replaying commands, even with Output Off.
- Right-click a recognized result address to open Memory or Disassembly. Callback rows let you choose Routine, Pre or Post. Actions retain the source context and address space; stale results and mismatched process ownership refuse target reads.
- **Continue / Break** controls a live target from the header. F5 continues; F10/F11 step with Disassembly active. **Follow IP** follows new stops, while manual code browsing pauses it. **Cancel operation** requests cancellation of a workspace operation and is separate from Break.
- Results stay in tabs with independent names, ordering, columns, sorting and selection. Closing the window retains the workspace in the loaded extension; bare `!kndbgx` reopens it. Explicit `!kndbgx shutdown`, unload or document recreation releases that workspace.

Target reads wait for valid stopped status. Existing captures remain visible through Busy and context changes, with historical actions disabled. See the [workspace guide](docs/UX.md) for controls, recovery and limits.

## Changes, collection and export

Registered memory changes require a complete preview and one-use approval. There is no global write switch; legacy `policy` / `gate` only report its removal. UI breakpoint Add/Delete uses preview approval; Enable/Disable and execution controls apply context-bound actions on click. Dump and local-kernel sessions cannot apply these changes.

Unregistered **manual UI input** is forwarded directly to WinDbg and can change the target or host under WinDbg's own semantics. Registered names retain KNDbgX validation. CLI and jobs require `raw --ack-effects <command>` for opaque execution.

```text
!kndbgx plan eb <address> 41 42
!kndbgx approve <plan-id> <approval-token>
!kndbgx !snapshot "C:\captures\before"
!kndbgx !snapshot "C:\captures\after"
!kndbgx !diff "C:\captures\before" "C:\captures\after"
!kndbgx results
!kndbgx result-export <result-id> "C:\captures\result.json"
```

Replace placeholders before use and wait for each snapshot job to finish. `jobs`, `job <id>` and `cancel <id>` expose asynchronous work. Cancellation acceptance does not prove a pending engine call has ended. Snapshots require new directories; different sessions require `/cross-session`, and incomplete inputs remain Partial.

**Export** saves the full retained result, including rows outside the viewport. Failures identify the destination and Win32 error; a retained result can be exported to another writable path. **Operations > Refresh outcomes** queries retained operation records without repeating commands or saves. **Open result** opens retained content; **Copy saved path** copies a confirmed export path. Operation records can expire or be evicted and do not survive DLL unload. Result content has its own retention budget: 64 MiB shared by at most 16 unpinned recent entries and 128 protected UI-tab entries. Save important data before eviction or unload.

## Documentation

- [Workspace guide](docs/UX.md): commands, inspection, execution, result tabs and recovery.
- [Command reference](docs/COMMANDS.md): generated grammar, aliases, effects, defaults and session requirements.
- [Kernel and driver analysis](docs/KERNEL_ANALYSIS.md) and [symbol support](docs/SYMBOL_SUPPORT.md): collectors, diagnostics, profiles and interpretation.
- [Support matrix](docs/SUPPORT.md): target requirements, unsupported features and resource limits.
- [Validation](docs/VALIDATION.md): build checks, test procedures and publication requirements.
- [Design](DESIGN.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

The repository also contains the independent `samples/snapshot-demo` driver lab; its Korean README documents build, signing and guest test requirements. It is not part of the extension package. Release validation and packaging commands are in [VALIDATION.md](docs/VALIDATION.md#release-validation).
