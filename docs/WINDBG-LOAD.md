# Loading the extension in WinDbg and running commands

This page records the operational procedure for loading a built `kndbgx.dll` into an already-connected x64 WinDbg, running registered commands from the debugger console, and reloading after a rebuild. The generated [command reference](COMMANDS.md) remains the source for registered names, aliases, options and session modes; the [workspace guide](UX.md) covers the UI. The short form of the load step is in [Open the workspace](../README.md#open-the-workspace).

## Requirements

- x64 WinDbg, the Microsoft VC++ x64 runtime and the WebView2 Evergreen Runtime.
- `runtime\dia\msdia140.dll` present relative to the folder that holds `kndbgx.dll`.
- The target stopped before memory is inspected.

## Build

From the repository root in PowerShell:

```powershell
.\tools\build.ps1 -Configuration Release -RunTests
```

The script finds Visual Studio with `vswhere` and writes the extension to `x64\Release`. `-RunTests` requires Node.js for frontend regressions; Release tooling requires Python 3.11+.

## Load

In WinDbg's command input:

```text
.load "C:\path\to\kndbgx.dll"
!kndbgx
```

The DLL exports one debugger command, `kndbgx` (`src/ext/Extension.cpp`). `!kndbgx` with no argument opens the workspace window. Closing that window keeps the workspace in the loaded extension, and `!kndbgx` reopens it.

Keep the path quoted. When the quotes are lost on the way to the debugger, the path can arrive without its separators and the load fails:

```text
The call to LoadLibrary(C:pathtokndbgx.dll) failed, Win32 error 0n2
```

Read the console text rather than only the caller's status: a programmatic caller can report success while this message is what actually happened.

## Run a command

Use `!kndbgx <command>` in WinDbg and `<command>` in the KNDbgX UI. A registered name already carries its leading `!`, because that is how the registry stores it — `src/cmd/CommandSpec.cpp` registers `L"!mapper"`, `L"!callbacks"` and the rest:

```text
!kndbgx help
!kndbgx status
!kndbgx version
!kndbgx !mapper
!kndbgx !callbacks
```

Two mistakes are easy to make here:

- `!kndbgx mapper` is rejected with `Unsupported: unknown command; use explicit raw mode for host commands`. The registered name is `!mapper`, not `mapper`.
- `!mapper` on its own is a WinDbg extension-export lookup rather than a KNDbgX command, and answers `No export mapper found`.

Three subcommands are handled before the registry lookup:

| Input | Effect |
|---|---|
| `!kndbgx` | Open or focus the workspace window |
| `!kndbgx cancel` | Request cancellation of the active collection |
| `!kndbgx shutdown` | Close the workspace window |

`!kndbgx help` lists registered commands, `!kndbgx help <command>` shows grammar, aliases and session availability, and `!kndbgx help ui` describes the workspace. `!kndbgx version` reports the extension version and `!kndbgx status` reports engine and session state.

In the workspace window, **Library** or **Ctrl+K** searches the same registry, Enter inserts the draft, and **Run** opens the capture in a new **Results** tab. Selection and completion do not execute the command.

## Collecting commands run as jobs

Kernel target-read commands that do not change the session context are submitted to the job queue, so the console prints a job id instead of rows:

```text
!kndbgx !mapper
[job] <job-id>
```

Read the stored result with the job commands:

```text
!kndbgx jobs
!kndbgx job <job-id>
!kndbgx result-read <result-id> 0
!kndbgx result-export <result-id> C:\captures\mapper.json
```

`jobs` lists recent jobs, `job <id>` reports its state and stored result id, `result-read` prints stored rows and findings, and `result-export` writes the complete stored result. A synchronous command that produced a stored page prints `[result] <result-id>` instead. Save results before unloading the DLL: `results` and `result-read` share a bounded store, and closing a result tab or destroying its UI document releases that result's protection.

## Reload after a rebuild

The engine keeps the DLL loaded, so the file cannot be replaced while it is in the chain:

```text
.unload "C:\path\to\kndbgx.dll"
```

Build or copy the new DLL, load it again, and confirm the version:

```text
.load "C:\path\to\kndbgx.dll"
!kndbgx version
```

`.unload` matches the path the extension was loaded with. A different path answers `No extension named '<path>' in chain` and leaves the old DLL loaded, so check that line instead of assuming the unload happened. A name that exists in your source but answers `Unsupported: unknown command` means the loaded DLL is older than your build; rebuild and reload.

## Console messages worth recognising

| Message | Meaning |
|---|---|
| `No export <name> found` | The name was sent as a WinDbg extension command instead of a `!kndbgx` subcommand |
| `Unsupported: unknown command; use explicit raw mode for host commands` | The subcommand is not in the loaded registry — check the leading `!`, the spelling, or the DLL version |
| `The call to LoadLibrary(...) failed, Win32 error 0n2` | The path did not resolve; quote the full path and check that the file exists |
| `No extension named '<path>' in chain` | The unload path does not match the loaded extension path |
| `EngineBusy: retry after the active request finishes` | Another request holds the engine; wait, or use `!kndbgx cancel` |
| `EngineBusyOrUnavailable: retry after the active request finishes` | A job could not take a session stamp; retry after the active request finishes |

## Limits

Registered names keep KNDbgX validation and approval rules. Unregistered input typed in the UI is forwarded directly to WinDbg, and opaque host commands need `raw --ack-effects <command>` in the CLI and in jobs. Dumps and local kernel debugging do not support target writes or execution control, and `!byovd` and `!dma` run only in verified local kernel debugging. See [SUPPORT.md](SUPPORT.md) for the tested configurations.
