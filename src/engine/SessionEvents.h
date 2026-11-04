#pragma once

#include "ContextGuard.h"
#include "SymbolQuery.h"
#include "../util/Log.h"
#include <atomic>
#include <string>
#if defined(_DEBUG) || defined(KNDBGX_UI_TESTS)
#include <mutex>
#include <vector>
#endif

namespace knengine
{
#if defined(_DEBUG) || defined(KNDBGX_UI_TESTS)
struct SessionEventObservation
{
    DWORD Owner = 0;
    DWORD Caller = 0;
    unsigned Kind = 0;
    ULONG Flags = 0;
    bool Suppressed = false;
};
inline std::mutex SessionTraceMutex;
inline std::vector<SessionEventObservation> SessionTrace;
#endif
// Notifications can arrive on the engine's calling thread. They update locked
// epoch state and the observer's hit counter only; engine calls stay on the owner thread.
class SessionEvents final : public DebugBaseEventCallbacksWide
{
  public:
    explicit SessionEvents(kncore::EpochTracker &epochs = Epochs(), std::atomic<uint64_t> *breakpointSequence = nullptr)
        : epochs_(epochs), breakpointSequence_(breakpointSequence)
    {
    }
    STDMETHOD_(ULONG, AddRef)() override
    {
        return ++references_;
    }
    STDMETHOD_(ULONG, Release)() override
    {
        const ULONG remaining = --references_;
        if (remaining == 0)
        {
            delete this;
        }
        return remaining;
    }
    STDMETHOD(GetInterestMask)(PULONG mask) override
    {
        if (mask == nullptr)
        {
            return E_POINTER;
        }
        *mask = DEBUG_EVENT_SESSION_STATUS | DEBUG_EVENT_CHANGE_ENGINE_STATE | DEBUG_EVENT_CHANGE_SYMBOL_STATE |
                DEBUG_EVENT_CHANGE_DEBUGGEE_STATE;
        if (breakpointSequence_ != nullptr)
        {
            *mask |= DEBUG_EVENT_BREAKPOINT;
        }
        return S_OK;
    }
    STDMETHOD(Breakpoint)(PDEBUG_BREAKPOINT2) override
    {
        // Only the dedicated observer counts hits. Never inspect engine objects in this callback.
        if (breakpointSequence_ != nullptr)
        {
            breakpointSequence_->fetch_add(1);
        }
        return DEBUG_STATUS_NO_CHANGE;
    }
    STDMETHOD(SessionStatus)(ULONG) override
    {
        if (epochs_.WalksInFlight() == 0)
        {
            epochs_.TargetChanged();
        }
        return S_OK;
    }
    STDMETHOD(ChangeEngineState)(ULONG flags, ULONG64) override
    {
        Trace(1, flags, InternalContextDepth != 0);
        // Walks and guarded host diagnostics issue engine calls (thread
        // switches, system-id restores, !analyze state transitions) that
        // transiently flip the reported execution status, current thread and
        // systems list. Those flips belong to the operation, not the session:
        // recording them would bump the stop, context or target generations
        // and refuse the operation's own context restore (the restore's
        // SetCurrentSystemId step fires DEBUG_CES_SYSTEMS itself). The first
        // observation after the walk still sees any change that persists.
        const bool inWalk = epochs_.WalksInFlight() > 0;
        if ((flags & DEBUG_CES_SYSTEMS) != 0 && !inWalk)
        {
            knlog::Write(L"SessionEvents: systems changed (walks in flight: " + std::to_wstring(epochs_.WalksInFlight()) + L")");
            epochs_.TargetChanged();
        }
        if ((flags & DEBUG_CES_EXECUTION_STATUS) != 0)
        {
            knlog::Write(std::wstring(L"SessionEvents: execution status event, inWalk=") + (inWalk ? L"1" : L"0"));
            if (!inWalk)
            {
                epochs_.ExecutionChanged();
            }
        }
        if (!inWalk && InternalContextDepth == 0 && (flags & (DEBUG_CES_CURRENT_THREAD | DEBUG_CES_EFFECTIVE_PROCESSOR)) != 0)
        {
            epochs_.ContextChanged();
        }
        return S_OK;
    }
    STDMETHOD(ChangeSymbolState)(ULONG flags, ULONG64) override
    {
        const ULONG passiveFlags = DEBUG_CSS_LOADS | DEBUG_CSS_SCOPE;
        const bool passiveQuery = PassiveSymbolQueryDepth != 0 && flags != 0 && (flags & ~passiveFlags) == 0;
        const bool internalScope = InternalContextDepth != 0 && flags == DEBUG_CSS_SCOPE;
        Trace(2, flags, passiveQuery || internalScope);
        // Deferred PDB loads triggered by a walk's own thread switches are
        // additive metadata, not a symbol-state change of the session; the
        // collector's finalize check still pins real reloads outside walks.
        if (!passiveQuery && !internalScope && epochs_.WalksInFlight() == 0)
        {
            epochs_.SymbolsChanged();
        }
        return S_OK;
    }
    STDMETHOD(ChangeDebuggeeState)(ULONG flags, ULONG64 argument) override
    {
        const bool displayRefresh =
            flags == DEBUG_CDS_REFRESH && (argument == DEBUG_CDS_REFRESH_EVALUATE || argument == DEBUG_CDS_REFRESH_EXECUTE ||
                                           argument == DEBUG_CDS_REFRESH_EXECUTECOMMANDFILE);
        Trace(3, flags, InternalContextDepth != 0 || displayRefresh);
        // Context evaluation during a walk (a CLI poll resolving scope or
        // implicit offsets fires register refresh events on its own thread,
        // outside the walking thread's depth) is transient walk state, not a
        // session context change; recording it refuses the walk's restore.
        if (epochs_.WalksInFlight() == 0 && InternalContextDepth == 0 && !displayRefresh)
        {
            epochs_.ContextChanged();
        }
        return S_OK;
    }

  private:
    void Trace(unsigned kind, ULONG flags, bool suppressed)
    {
#if defined(_DEBUG) || defined(KNDBGX_UI_TESTS)
        std::lock_guard lock(SessionTraceMutex);
        if (SessionTrace.size() < 512)
        {
            SessionTrace.push_back({owner_, GetCurrentThreadId(), kind, flags, suppressed});
        }
#else
        UNREFERENCED_PARAMETER(kind);
        UNREFERENCED_PARAMETER(flags);
        UNREFERENCED_PARAMETER(suppressed);
#endif
    }
#if defined(_DEBUG) || defined(KNDBGX_UI_TESTS)
    const DWORD owner_ = GetCurrentThreadId();
#endif
    std::atomic<ULONG> references_{1};
    kncore::EpochTracker &epochs_;
    std::atomic<uint64_t> *breakpointSequence_ = nullptr;
};
} // namespace knengine
