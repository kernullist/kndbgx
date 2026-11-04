#pragma once

#include "Result.h"
#include <atomic>
#include <mutex>
#include <optional>
#include <string>

namespace knlog
{
void Write(const std::wstring &line);
}

namespace kncore
{
// Diagnostics-only generation trace: names the mutating operation when the
// restore-refusal hunt needs it (KNDBGX_DIAGNOSTICS=1 gates the write).
inline void TraceEpochMutation(const wchar_t *what, const SessionStamp &stamp, unsigned walks)
{
    knlog::Write(std::wstring(what) + L" generations now t=" + std::to_wstring(stamp.TargetGeneration) + L" s=" +
                 std::to_wstring(stamp.StopEpoch) + L" c=" + std::to_wstring(stamp.ContextGeneration) + L" y=" +
                 std::to_wstring(stamp.SymbolGeneration) + L" walks=" + std::to_wstring(walks));
}

template <typename T> class EpochValue
{
  public:
    void Set(const T &value, const SessionStamp &stamp)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ = value;
        stamp_ = stamp;
    }
    std::optional<T> Get(const SessionStamp &stamp) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return stamp == stamp_ ? value_ : std::nullopt;
    }
    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        value_.reset();
    }

  private:
    mutable std::mutex mutex_;
    SessionStamp stamp_;
    std::optional<T> value_;
};

enum class SessionState
{
    Disconnected,
    Connecting,
    ReadyStopped,
    ReadyRunning,
    Closing,
    Faulted
};

struct TargetObservation
{
    bool Present = false;
    bool Stopped = false;
    uint32_t Kind = 0;
    uint32_t Qualifier = 0;
    uint32_t System = UINT32_MAX;
    uint32_t Process = UINT32_MAX;
    uint32_t Thread = UINT32_MAX;
    uint32_t Architecture = 0;
    ContextIdentity Context;
    bool operator==(const TargetObservation &) const = default;
};

class EpochTracker
{
  public:
    explicit EpochTracker(const std::wstring &id)
    {
        stamp_.SessionId = id;
    }
    SessionStamp Stamp() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return stamp_;
    }
    SessionState State() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_;
    }
    // A per-processor walk switches the engine's current thread while it
    // runs; that transient belongs to the walk, not to the session. The
    // switching thread already masks it through internalContext, but
    // observations from OTHER threads (CLI job polls run outside that
    // thread-local depth) would otherwise record the switched thread as the
    // session identity, permanently bumping ContextGeneration and
    // stale-killing the walk's own context restore. Any in-flight walk
    // therefore suppresses identity tracking for every observer; target,
    // stop and kind changes still invalidate.
    void EnterWalk()
    {
        walksInFlight_.fetch_add(1, std::memory_order_release);
    }
    void LeaveWalk()
    {
        const unsigned previous = walksInFlight_.fetch_sub(1, std::memory_order_acq_rel);
        if (previous == 0)
        {
            // An unbalanced leave would wrap the counter to UINT_MAX and pin
            // masking on forever; clamp and record it for diagnosis instead.
            walksInFlight_.store(0, std::memory_order_release);
            knlog::Write(L"Epochs: LeaveWalk without a matching EnterWalk; counter clamped to zero");
        }
    }
    unsigned WalksInFlight() const
    {
        return walksInFlight_.load(std::memory_order_acquire);
    }
    void SetWalksInFlight(unsigned value)
    {
        walksInFlight_.store(value, std::memory_order_release);
    }
    void Observe(TargetObservation next, bool internalContext = false)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool walking = walksInFlight_.load(std::memory_order_acquire) > 0;
        if (internalContext || walking)
        {
            next.Process = observed_.Process;
            next.Thread = observed_.Thread;
            next.Context = observed_.Context;
        }
        if (walking)
        {
            // Engine status reads concurrent with a walk (CLI job polls) see
            // the walk's transient state; the first observation after the
            // walk records any flip that is still present, which is the real
            // one. Bare internal observations keep reporting resumes.
            next.Stopped = observed_.Stopped;
        }
        if (next.Present != observed_.Present || next.System != observed_.System || next.Kind != observed_.Kind ||
            next.Qualifier != observed_.Qualifier || next.Architecture != observed_.Architecture)
        {
            TraceEpochMutation(L"Epochs: observe invalidated target", stamp_, walksInFlight_.load());
            InvalidateTarget();
        }
        if (next.Stopped != observed_.Stopped)
        {
            ++stamp_.StopEpoch;
            ++stamp_.ContextGeneration;
            TraceEpochMutation(L"Epochs: observe stop flip", stamp_, walksInFlight_.load());
        }
        if (next.Process != observed_.Process || next.Thread != observed_.Thread || next.Context != observed_.Context)
        {
            ++stamp_.ContextGeneration;
            TraceEpochMutation(L"Epochs: observe identity change", stamp_, walksInFlight_.load());
        }
        observed_ = next;
        stamp_.Context = next.Context;
        if (state_ != SessionState::Faulted && state_ != SessionState::Closing)
        {
            state_ = !next.Present ? SessionState::Disconnected : (next.Stopped ? SessionState::ReadyStopped : SessionState::ReadyRunning);
        }
    }
    void TargetChanged()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        TraceEpochMutation(L"Epochs: TargetChanged", stamp_, walksInFlight_.load());
        InvalidateTarget();
    }
    void ExecutionChanged()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++stamp_.StopEpoch;
        ++stamp_.ContextGeneration;
        TraceEpochMutation(L"Epochs: ExecutionChanged", stamp_, walksInFlight_.load());
    }
    void ContextChanged()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++stamp_.ContextGeneration;
        TraceEpochMutation(L"Epochs: ContextChanged", stamp_, walksInFlight_.load());
    }
    void SymbolsChanged()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++stamp_.SymbolGeneration;
        TraceEpochMutation(L"Epochs: SymbolsChanged", stamp_, walksInFlight_.load());
    }
    void Fault()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = SessionState::Faulted;
        InvalidateTarget();
    }
    void Reconnect()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = SessionState::Connecting;
        InvalidateTarget();
    }

  private:
    void InvalidateTarget()
    {
        ++stamp_.TargetGeneration;
        ++stamp_.StopEpoch;
        ++stamp_.ContextGeneration;
        ++stamp_.SymbolGeneration;
    }
    mutable std::mutex mutex_;
    mutable std::atomic<unsigned> walksInFlight_{0};
    SessionStamp stamp_;
    TargetObservation observed_;
    SessionState state_ = SessionState::Disconnected;
};
} // namespace kncore
