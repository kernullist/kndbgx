#pragma once
#include "Result.h"
#include "../util/Log.h"
#include <span>

namespace kncore
{
template <typename Value, typename Getter, typename Setter>
bool RestoreIfDifferent(const Value &expected, Getter get, Setter set)
{
    Value current = {};
    if (get(&current) && current == expected)
    {
        return true;
    }
    return set(expected);
}

inline void LogStampMismatch(const wchar_t *where, const SessionStamp &saved, const SessionStamp &current, bool symbolsMayChange)
{
    std::wstring detail(where);
    detail += L": restore refused, stamp changed";
    if (saved.SessionId != current.SessionId)
    {
        detail += L" session";
    }
    if (saved.TargetGeneration != current.TargetGeneration)
    {
        detail += L" target";
    }
    if (saved.StopEpoch != current.StopEpoch)
    {
        detail += L" stop";
    }
    if (saved.ContextGeneration != current.ContextGeneration)
    {
        detail += L" context";
    }
    if (!symbolsMayChange && saved.SymbolGeneration != current.SymbolGeneration)
    {
        detail += L" symbol";
    }
    detail += L" generations saved(t=" + std::to_wstring(saved.TargetGeneration) + L",s=" + std::to_wstring(saved.StopEpoch) +
              L",c=" + std::to_wstring(saved.ContextGeneration) + L",y=" + std::to_wstring(saved.SymbolGeneration) + L") current(t=" +
              std::to_wstring(current.TargetGeneration) + L",s=" + std::to_wstring(current.StopEpoch) + L",c=" +
              std::to_wstring(current.ContextGeneration) + L",y=" + std::to_wstring(current.SymbolGeneration) + L")";
    knlog::Write(detail);
}

inline void LogStepFailure(const wchar_t *where, size_t step)
{
    knlog::Write(std::wstring(where) + L": restore step " + std::to_wstring(step) + L" failed");
}

inline bool RestoreContext(const wchar_t *where, const SessionStamp &saved, const SessionStamp &current,
                           std::span<const std::function<bool()>> steps, const std::function<void()> &fault,
                           const std::function<void()> &drift, const std::function<SessionStamp()> &observe = {},
                           bool symbolsMayChange = false)
{
    // Symbol generation tracks additive metadata (deferred PDB loads); it never moves
    // target bytes, so operations that deliberately run symbol-loading host commands
    // may tolerate it. Target/stop/context generations still pin the observation.
    const auto unchanged = [&](const SessionStamp &stamp)
    {
        return saved.SessionId == stamp.SessionId && saved.TargetGeneration == stamp.TargetGeneration &&
               saved.StopEpoch == stamp.StopEpoch && saved.ContextGeneration == stamp.ContextGeneration &&
               (symbolsMayChange || saved.SymbolGeneration == stamp.SymbolGeneration);
    };
    if (!unchanged(current))
    {
        LogStampMismatch(where, saved, current, symbolsMayChange);
        fault();
        return false;
    }
    // Steps 0..2 (system/process/thread identity) define the engine's current
    // context: when they fail, the context is unknown and the session faults.
    // Later steps (implicit offsets, scope) describe auxiliary resolution
    // state that a long host scan can invalidate (a restored implicit thread
    // offset may no longer exist); when the identity itself restored, record
    // the drift instead so the session stays usable and later commands
    // observe the changed context.
    constexpr size_t IdentitySteps = 3;
    bool ok = true;
    bool identityFailed = false;
    for (size_t index = 0; index < steps.size(); ++index)
    {
        if (observe && !unchanged(observe()))
        {
            LogStampMismatch(where, saved, observe(), symbolsMayChange);
            fault();
            return false;
        }
        if (!steps[index]())
        {
            LogStepFailure(where, index);
            ok = false;
            if (index < IdentitySteps)
            {
                identityFailed = true;
            }
        }
    }
    if (!ok)
    {
        if (identityFailed)
        {
            fault();
        }
        else
        {
            drift();
        }
    }
    return ok;
}
} // namespace kncore
