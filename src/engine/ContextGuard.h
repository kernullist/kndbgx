#pragma once

#include "EngineCore.h"
#include "../core/ContextRestore.h"
#include "../util/Log.h"
#include "SymbolQuery.h"
#include "SessionWalk.h"
#include <dbgeng.h>
#include <cstring>

namespace knengine
{
inline thread_local unsigned InternalContextDepth = 0;

class ContextGuard
{
  public:
    explicit ContextGuard(DbgSession &session) : session_(session)
    {
        // Announce the walk before touching the engine or reading the saved
        // stamp: deferred engine events delivered by the session-observer
        // thread can bump generations at any moment, and one landing between
        // the saved-stamp read and the walk announcement would already
        // invalidate the restore. EnterWalk does not itself change the stamp,
        // so reading it inside the walk is exact.
        savedStamp_ = Epochs().Stamp();
        auto *system = session_.SystemObjects();
        auto *control = session_.Control();
        SymbolQueryScope passive;
        if (system != nullptr && control != nullptr && session_.Symbols() != nullptr)
        {
            Record(system->GetCurrentSystemId(&system_), 1, capturedMask_);
            Record(system->GetCurrentProcessId(&process_), 2, capturedMask_);
            Record(system->GetCurrentThreadId(&thread_), 4, capturedMask_);
            Record(control->GetEffectiveProcessorType(&processor_), 8, capturedMask_);
            Record(system->GetImplicitProcessDataOffset(&implicitProcess_), 16, capturedMask_);
            Record(system->GetImplicitThreadDataOffset(&implicitThread_), 32, capturedMask_);
            Record(session_.Symbols()->GetScope(&instruction_, &frame_, &registers_, sizeof(registers_)), 64, capturedMask_);
            valid_ = capturedMask_ == 127;
        }
        ++InternalContextDepth;
    }
    ~ContextGuard()
    {
        Restore();
        --InternalContextDepth;
    }
    bool Valid() const
    {
        return valid_;
    }
    ULONG CapturedMask() const
    {
        return capturedMask_;
    }
    ULONG RestoredMask() const
    {
        return restoredMask_;
    }
    bool Restore()
    {
        if (finished_)
        {
            return restored_;
        }
        finished_ = true;
        if (!valid_)
        {
            return false;
        }
        auto *system = session_.SystemObjects();
        // Restore dependencies before dependent IDs; all failures are retained.
        const std::function<bool()> steps[] = {
            [&]()
            {
                return RestoreValue(system, system_, 1, &IDebugSystemObjects4::GetCurrentSystemId,
                                    &IDebugSystemObjects4::SetCurrentSystemId);
            },
            [&]()
            {
                return RestoreValue(system, process_, 2, &IDebugSystemObjects4::GetCurrentProcessId,
                                    &IDebugSystemObjects4::SetCurrentProcessId);
            },
            [&]()
            {
                return RestoreValue(system, thread_, 4, &IDebugSystemObjects4::GetCurrentThreadId,
                                    &IDebugSystemObjects4::SetCurrentThreadId);
            },
            [&]()
            {
                return RestoreValue(session_.Control(), processor_, 8, &IDebugControl4::GetEffectiveProcessorType,
                                    &IDebugControl4::SetEffectiveProcessorType);
            },
            [&]()
            {
                return RestoreValue(system, implicitProcess_, 16, &IDebugSystemObjects4::GetImplicitProcessDataOffset,
                                    &IDebugSystemObjects4::SetImplicitProcessDataOffset);
            },
            [&]()
            {
                return RestoreValue(system, implicitThread_, 32, &IDebugSystemObjects4::GetImplicitThreadDataOffset,
                                    &IDebugSystemObjects4::SetImplicitThreadDataOffset);
            },
            [&]()
            {
                // Identity restoration often restores the scope as well.
                // Reapplying that scope can trigger an unbounded remote
                // stack walk inside DbgEng, even for a read-only CPU scan.
                ULONG64 instruction = 0;
                DEBUG_STACK_FRAME frame = {};
                CONTEXT registers = {};
                if (session_.Symbols()->GetScope(&instruction, &frame, &registers, sizeof(registers)) == S_OK &&
                    instruction == instruction_ && std::memcmp(&frame, &frame_, sizeof(frame)) == 0 &&
                    std::memcmp(&registers, &registers_, sizeof(registers)) == 0)
                {
                    restoredMask_ |= 64;
                    return true;
                }
                // SetScope returns S_FALSE when it successfully changes the scope.
                return Record(session_.Symbols()->SetScope(instruction_, &frame_, &registers_, sizeof(registers_)), 64, restoredMask_,
                              true);
            }};
        restored_ = kncore::RestoreContext(
            L"ContextGuard", savedStamp_, Epochs().Stamp(), steps,
            [&]()
            {
                session_.MarkFault();
            },
            [&]()
            {
                // Auxiliary restore steps failed after the identity itself
                // restored: record the drift, keep the session usable.
                knlog::Write(L"ContextGuard: auxiliary restore step failed; recording context drift");
                Epochs().ContextChanged();
            },
            [&]()
            {
                return Epochs().Stamp();
            },
            symbolsMayChange_);
        return restored_;
    }
    // Operations that deliberately execute symbol-loading host commands (host
    // diagnostics) declare that additive symbol loads are expected; target,
    // stop and context generations still pin the restore.
    void AllowSymbolChanges()
    {
        symbolsMayChange_ = true;
    }
    ContextGuard(const ContextGuard &) = delete;
    ContextGuard &operator=(const ContextGuard &) = delete;

  private:
    template <typename Interface, typename Value, typename Getter, typename Setter>
    bool RestoreValue(Interface *object, Value expected, ULONG bit, Getter getter, Setter setter)
    {
        // Reapplying an unchanged implicit thread offset can replace the
        // stopped CPU's register context with its saved thread context.
        const bool restored = kncore::RestoreIfDifferent(expected,
            [&](Value *current)
            {
                return (object->*getter)(current) == S_OK;
            },
            [&](Value value)
            {
                return (object->*setter)(value) == S_OK;
            });
        if (restored)
        {
            restoredMask_ |= bit;
        }
        return restored;
    }
    static bool Record(HRESULT status, ULONG bit, ULONG &mask, bool allowChanged = false)
    {
        const bool ok = status == S_OK || (allowChanged && status == S_FALSE);
        if (ok)
        {
            mask |= bit;
        }
        return ok;
    }
    DbgSession &session_;
    SessionWalk walk_;
    kncore::SessionStamp savedStamp_;
    ULONG system_ = 0;
    ULONG process_ = 0;
    ULONG thread_ = 0;
    ULONG processor_ = 0;
    ULONG64 implicitProcess_ = 0;
    ULONG64 implicitThread_ = 0;
    ULONG capturedMask_ = 0;
    ULONG restoredMask_ = 0;
    ULONG64 instruction_ = 0;
    DEBUG_STACK_FRAME frame_ = {};
    CONTEXT registers_ = {};
    bool valid_ = false;
    bool finished_ = false;
    bool restored_ = false;
    bool symbolsMayChange_ = false;
};
} // namespace knengine
