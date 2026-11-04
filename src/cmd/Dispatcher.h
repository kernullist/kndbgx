#pragma once

// Public dispatcher surface used by the WebView2 bridge.
//
// Extension input uses registered commands. The UI console also accepts WinDbg input.

#include <string>
#include "../core/Result.h"

namespace knengine
{
class DbgSession;
}

namespace kncmd
{
struct CommandSpec;
enum class CommandInput
{
    Registered,
    UiConsole
};
// True when the first token maps to a native handler (or the leading
// '?' evaluator).
bool IsNativeCommand(const std::wstring &line);

struct CommandResult
{
    bool Ok;
    bool Blocked;
    bool Native;
    bool Cls;
    std::wstring Output;
    std::wstring Error;
    std::wstring ResultId;
    kncore::Result Data;
};

// Apply completion policy using the captured stamps, without engine I/O.
void FinalizeCollection(CommandResult &result, const CommandSpec *spec, const kncore::SessionStamp &current, bool cancelled);
void MarkResultNotRetained(CommandResult &result);
bool IsResultInspection(const std::wstring &commandId);

// Registered commands share policy across the UI and extension. Only explicit
// UiConsole input delegates unregistered commands to the host engine.
CommandResult DispatchCommand(knengine::DbgSession &session, const std::wstring &line, const kncore::SessionStamp *expected = nullptr,
                              const std::function<bool()> &requestCancelled = {}, CommandInput input = CommandInput::Registered);

// Executes a native command. The formatted output is additionally echoed
// into the host consoles through chunked .printf so the WinDbg command
// window shows exactly what ran.
bool RunNative(knengine::DbgSession &session, const std::wstring &line, std::wstring *output, kncore::Result *details = nullptr,
               const kncore::SessionStamp *expected = nullptr, const std::function<bool()> &requestCancelled = {});
} // namespace kncmd
