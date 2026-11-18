#pragma once

#include "Architecture.h"
#include "Result.h"
#include <functional>
#include <set>
#include <chrono>

namespace kncore
{
enum class VisitDecision
{
    Continue,
    Stop,
    Failed
};

class WalkBudget
{
  public:
    uint64_t MaxNodes = 65536;
    std::chrono::steady_clock::time_point Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::function<bool()> Cancelled;
    Result Report;
    std::set<uint64_t> Seen;
    bool Stopped = false;

    void StartTraversal(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
                        std::chrono::steady_clock::duration timeout = std::chrono::seconds(5))
    {
        // Symbol discovery and processor mapping can outlast the walk budget.
        // Start once at the first usable node; later CPUs must not renew it.
        if (!traversalStarted_ && !Stopped)
        {
            Deadline = now + timeout;
            traversalStarted_ = true;
        }
    }

    bool Stop(Status state, const wchar_t *reason)
    {
        Stopped = true;
        Report.State = state;
        Report.Collected.StopReason = reason;
        Report.Collected.Complete = false;
        return false;
    }

    bool CanRead()
    {
        if (!Stopped && Cancelled && Cancelled())
        {
            return Stop(Status::Cancelled, L"Cancelled");
        }
        // Profile discovery may precede the traversal clock.
        if (!Stopped && traversalStarted_ && std::chrono::steady_clock::now() >= Deadline)
        {
            return Stop(Status::Partial, L"GlobalWalkBudget");
        }
        return !Stopped;
    }

    bool Consume(uint64_t address, const TargetArchitecture &architecture)
    {
        StartTraversal();
        if (Stopped)
        {
            return false;
        }
        if (Cancelled && Cancelled())
        {
            return Stop(Status::Cancelled, L"Cancelled");
        }
        if (Report.Collected.Visited >= MaxNodes || std::chrono::steady_clock::now() >= Deadline)
        {
            return Stop(Status::Partial, L"GlobalWalkBudget");
        }
        if (!architecture.Canonical(address) || architecture.PointerBytes == 0 || address % architecture.PointerBytes != 0)
        {
            return Stop(Status::Partial, L"InvalidNodeAddress");
        }
        if (!Seen.insert(address).second)
        {
            return Stop(Status::Partial, L"CycleOrRepeatedNode");
        }
        ++Report.Collected.Visited;
        return true;
    }

    void Complete()
    {
        if (!Stopped)
        {
            Report.Collected.Complete = true;
            Report.Collected.StopReason = L"EndOfDeclaredWalk";
        }
    }

  private:
    bool traversalStarted_ = false;
};

inline bool ReadPointer(TargetReader &reader, uint64_t address, unsigned pointerBytes, uint64_t *value)
{
    bool ok = false;
    if (pointerBytes == 8)
    {
        ok = reader.ReadExact(AddressSpace::Virtual, address, value);
    }
    else if (pointerBytes == 4 && value != nullptr)
    {
        uint32_t narrow = 0;
        ok = reader.ReadExact(AddressSpace::Virtual, address, &narrow);
        if (ok)
        {
            *value = narrow;
        }
    }
    return ok;
}

template <typename Visitor>
bool WalkChain(TargetReader &reader, uint64_t first, uint64_t sentinel, uint32_t nextOffset, const TargetArchitecture &architecture,
               WalkBudget &budget, Visitor visitor, const std::function<void(uint64_t)> &prepare = {})
{
    uint64_t node = first;
    while (node != sentinel)
    {
        if (node == 0 || !budget.Consume(node, architecture))
        {
            if (!budget.Stopped)
            {
                budget.Stop(Status::Partial, L"NullBeforeListSentinel");
            }
            return false;
        }
        if (!architecture.KernelPointer(node))
        {
            return budget.Stop(Status::Partial, L"InvalidKernelNodeAddress");
        }
        if (prepare)
        {
            prepare(node);
            if (budget.Stopped)
            {
                return false;
            }
        }
        uint64_t next = 0;
        if (!ValidRange(node, static_cast<uint64_t>(nextOffset) + architecture.PointerBytes) ||
            !ReadPointer(reader, node + nextOffset, architecture.PointerBytes, &next))
        {
            if (budget.Stopped)
            {
                return false;
            }
            ++budget.Report.Collected.Unreadable;
            return budget.Stop(Status::Partial, L"UnreadableLink");
        }
        if (budget.Stopped)
        {
            return false;
        }
        ++budget.Report.Collected.Read;
        const auto decision = visitor(node);
        if (budget.Stopped)
        {
            return budget.Report.State == Status::Success;
        }
        if (decision == VisitDecision::Failed)
        {
            return budget.Stop(Status::Partial, L"VisitorDecodeFailed");
        }
        ++budget.Report.Collected.Decoded;
        if (decision == VisitDecision::Stop)
        {
            budget.Stop(Status::Success, L"VisitorStopped");
            return true;
        }
        node = next;
    }
    return !budget.Stopped;
}
} // namespace kncore
