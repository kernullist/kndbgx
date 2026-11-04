#pragma once

#include "Result.h"
#include <array>
#include <mutex>

namespace kncore
{
enum class DisplayKind
{
    VirtualMemory,
    PhysicalMemory,
    Disassembly
};

class DisplayCursorStore
{
  public:
    std::optional<uint64_t> Next(DisplayKind kind, const SessionStamp &stamp, std::optional<uint64_t> dtb)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &entry = entries_[static_cast<size_t>(kind)];
        if (!SameContext(entry.Stamp, stamp) || entry.Dtb != dtb)
        {
            entry = {};
        }
        return entry.Address;
    }

    void Remember(DisplayKind kind, const SessionStamp &stamp, std::optional<uint64_t> dtb, uint64_t address)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_[static_cast<size_t>(kind)] = {stamp, dtb, address};
    }

    static bool SameContext(const SessionStamp &left, const SessionStamp &right)
    {
        // Loading symbols does not move a display cursor. Execution and context changes do.
        return !left.SessionId.empty() && left.SessionId == right.SessionId && left.TargetGeneration == right.TargetGeneration &&
               left.StopEpoch == right.StopEpoch && left.ContextGeneration == right.ContextGeneration && left.Context == right.Context;
    }

  private:
    struct Entry
    {
        SessionStamp Stamp;
        std::optional<uint64_t> Dtb;
        std::optional<uint64_t> Address;
    };
    std::mutex mutex_;
    std::array<Entry, 3> entries_;
};

inline DisplayCursorStore &DisplayCursors()
{
    static DisplayCursorStore cursors;
    return cursors;
}
} // namespace kncore
