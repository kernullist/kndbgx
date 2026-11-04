#pragma once

#include "CmdTypes.h"

namespace kncmd
{
enum class Effect : unsigned
{
    None = 0,
    TargetRead = 1,
    SessionContextChange = 2,
    TargetMutation = 4,
    ExecutionControl = 8,
    HostFileRead = 16,
    HostFileWrite = 32,
    SymbolResolution = 64,
    OpaqueEngine = 128,
    PrivilegedHostOperation = 256
};
constexpr Effect operator|(Effect left, Effect right)
{
    return static_cast<Effect>(static_cast<unsigned>(left) | static_cast<unsigned>(right));
}
constexpr bool HasEffect(Effect set, Effect effect)
{
    return (static_cast<unsigned>(set) & static_cast<unsigned>(effect)) != 0;
}
enum class Capability
{
    None,
    Engine,
    Target,
    StoppedTarget,
    KernelX64,
    LocalKernelX64
};
enum class SupportLevel
{
    Stable,
    Experimental,
    Unsupported
};
// Kernel session modes a command can run in. Any means the command does not
// depend on the dump/live distinction (host-only commands, or target commands
// whose effective modes are derived by EffectiveTargetModes).
enum class TargetMode : unsigned
{
    Any = 0,
    KernelDump = 1,
    LiveKernel = 2,
    DumpAndLive = static_cast<unsigned>(KernelDump) | static_cast<unsigned>(LiveKernel)
};
constexpr bool HasTargetMode(TargetMode set, TargetMode mode)
{
    return (static_cast<unsigned>(set) & static_cast<unsigned>(mode)) != 0;
}
struct OptionSpec
{
    const wchar_t *Name;
    bool TakesValue;
};
struct CommandSpec
{
    const wchar_t *Name;
    std::vector<const wchar_t *> Aliases;
    const wchar_t *Group;
    const wchar_t *Synopsis;
    const wchar_t *Grammar;
    Effect Effects;
    Capability Requires;
    SupportLevel Support;
    size_t MinArguments;
    size_t MaxArguments;
    std::vector<OptionSpec> Options;
    HandlerFn Handler;
    // Kernel session modes in which this command is supported. Any selects the
    // derived default: host/engine commands are mode-independent, other target
    // commands run in both kernel dump and live kernel sessions. Set an
    // explicit value only when a command is restricted to one mode.
    TargetMode Modes = TargetMode::Any;
};
struct ParsedCommand
{
    const CommandSpec *Spec = nullptr;
    std::vector<std::wstring> Arguments;
    std::vector<bool> Quoted;
    std::vector<std::wstring> Positionals;
    std::wstring RawArguments;
    std::wstring Error;
};

const std::vector<CommandSpec> &CommandSpecs();
const CommandSpec *FindCommand(const std::wstring &name);
bool ParseCommand(const std::wstring &line, ParsedCommand *parsed);
// UI console input keeps registered commands strict and delegates other syntax to WinDbg.
bool ParseUiCommand(const std::wstring &line, ParsedCommand *parsed);
const wchar_t *SupportName(SupportLevel support);
// Resolves CommandSpec::Modes: explicit values win; Any derives DumpAndLive
// for target-dependent commands and Any for host/engine commands.
TargetMode EffectiveTargetModes(const CommandSpec &spec);
const wchar_t *TargetModeName(TargetMode modes);
// Display name for docs, contract JSON, help and the UI library: like
// EffectiveTargetModes, except that host-machine collectors (LocalKernelX64)
// are marked LiveKernelLocal because they refuse remote live targets even
// though they are live-only in the mode sense.
std::wstring TargetModeDisplayName(const CommandSpec &spec);
knjson::Value CommandContract();
void BuiltinCommand(Ctx &context);
void WinDbgCommand(Ctx &context);
void DebuggerCommand(Ctx &context);
void DebugActionCommand(Ctx &context);
void MutationCommand(Ctx &context);
void KernelAnalysisCommand(Ctx &context);
void DriverEvidenceCommand(Ctx &context);
void EtlEvidenceCommand(Ctx &context);
} // namespace kncmd
