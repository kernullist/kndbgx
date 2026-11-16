#pragma once

#include "CollectorRead.h"
#include <array>

namespace kncore
{
class QueueReadMeter final : public TargetReader
{
  public:
    explicit QueueReadMeter(TargetReader &reader) : reader_(reader)
    {
    }

    ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
    {
        ++Requests;
        Bytes += length;
        const auto start = std::chrono::steady_clock::now();
        auto result = reader_.Read(space, address, length);
        Elapsed += std::chrono::steady_clock::now() - start;
        return result;
    }

    uint64_t Requests = 0;
    uint64_t Bytes = 0;
    std::chrono::steady_clock::duration Elapsed{};

  private:
    TargetReader &reader_;
};

class QueueReadCache final : public TargetReader
{
  public:
    static constexpr size_t MaxRead = 4096;
    enum Slot : size_t
    {
        Heads,
        Timer,
        Dpc
    };

    QueueReadCache(TargetReader &reader, WalkBudget &budget, const TargetArchitecture &architecture, bool enabled)
        : reader_(reader), budget_(budget), architecture_(architecture), enabled_(enabled)
    {
    }

    void Prepare(Slot slot, uint64_t address, size_t length)
    {
        auto &cached = cached_[slot];
        cached = {};
        if (enabled_ && length != 0 && length <= MaxRead && ValidRange(address, length) &&
            architecture_.KernelPointer(address) && architecture_.KernelPointer(address + length - 1) && CheckBudget())
        {
            cached = ReadTarget(AddressSpace::Virtual, address, length);
        }
    }

    void PrepareRecord(Slot slot, uint64_t object, std::initializer_list<std::optional<FieldInfo>> fields)
    {
        cached_[slot] = {};
        uint64_t first = UINT32_MAX;
        uint64_t last = 0;
        for (const auto &field : fields)
        {
            if (field && field->ValidFor(UINT32_MAX))
            {
                first = (std::min)(first, static_cast<uint64_t>(field->Offset));
                last = (std::max)(last, static_cast<uint64_t>(field->Offset) + field->Size);
            }
        }
        // Only the observed object fields are fetched, never an entire pool page.
        if (last > first && last - first <= 256 && ValidRange(object, last))
        {
            Prepare(slot, object + first, static_cast<size_t>(last - first));
        }
    }

    ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
    {
        if (!CheckBudget())
        {
            return StoppedRead(space, address, length);
        }
        if (space == AddressSpace::Virtual && length != 0)
        {
            for (const auto &cached : cached_)
            {
                if (cached.Requested != 0 && ExactBytes(cached, cached.Requested) && address >= cached.Address &&
                    address - cached.Address <= cached.Requested && length <= cached.Requested - (address - cached.Address))
                {
                    ReadResult result;
                    result.Space = space;
                    result.Address = address;
                    result.Requested = result.Transferred = length;
                    result.State = Status::Success;
                    const auto first = cached.Bytes.begin() + static_cast<size_t>(address - cached.Address);
                    result.Bytes.assign(first, first + length);
                    result.Valid.assign(length, 1);
                    ++CacheHits;
                    return result;
                }
            }
        }
        // Unreadable padding in a speculative block must not hide valid fields.
        return ReadTarget(space, address, length);
    }

    uint64_t CacheHits = 0;

  private:
    bool CheckBudget()
    {
        if (!budget_.Stopped && budget_.Cancelled && budget_.Cancelled())
        {
            budget_.Stop(Status::Cancelled, L"Cancelled");
        }
        if (!budget_.Stopped && std::chrono::steady_clock::now() >= budget_.Deadline)
        {
            budget_.Stop(Status::Partial, L"CollectionBudget");
        }
        return !budget_.Stopped;
    }

    ReadResult StoppedRead(AddressSpace space, uint64_t address, size_t length) const
    {
        ReadResult result;
        result.Space = space;
        result.Address = address;
        result.Requested = length;
        result.State = budget_.Report.State;
        return result;
    }

    ReadResult ReadTarget(AddressSpace space, uint64_t address, size_t length)
    {
        auto result = reader_.Read(space, address, length);
        if (result.State == Status::Cancelled || result.State == Status::StaleContext || result.State == Status::InternalFault)
        {
            budget_.Stop(result.State, L"QueueReadStopped");
        }
        return CheckBudget() ? result : StoppedRead(space, address, length);
    }

    TargetReader &reader_;
    WalkBudget &budget_;
    TargetArchitecture architecture_;
    bool enabled_ = false;
    std::array<ReadResult, 3> cached_;
};
} // namespace kncore
