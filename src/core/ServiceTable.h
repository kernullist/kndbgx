#pragma once

#include "ScannerRules.h"
#include <array>

namespace kncore
{
inline bool CheckWalkDeadline(WalkBudget &budget)
{
    if (!budget.Stopped && budget.Cancelled && budget.Cancelled())
    {
        budget.Stop(Status::Cancelled, L"Cancelled");
    }
    if (!budget.Stopped && std::chrono::steady_clock::now() >= budget.Deadline)
    {
        budget.Stop(Status::Partial, L"GlobalWalkBudget");
    }
    return !budget.Stopped;
}

inline std::optional<uint64_t> BlockValue(const ReadResult &read, size_t offset, size_t size)
{
    if (size == 0 || size > 8 || offset > read.Bytes.size() || size > read.Bytes.size() - offset || offset > read.Valid.size() ||
        size > read.Valid.size() - offset || (read.State != Status::Success && read.State != Status::Partial))
    {
        return {};
    }
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i)
    {
        if (!read.Valid[offset + i])
        {
            return {};
        }
        value |= uint64_t(read.Bytes[offset + i]) << (i * 8);
    }
    return value;
}

struct ServiceDescriptor
{
    uint64_t Table = 0;
    uint64_t Counter = 0;
    uint32_t Limit = 0;
    uint64_t Arguments = 0;
    bool operator==(const ServiceDescriptor &) const = default;
};

inline std::optional<ServiceDescriptor> ReadServiceDescriptor(TargetReader &reader, uint64_t address)
{
    if (!ValidRange(address, 32))
    {
        return {};
    }
    const auto block = reader.Read(AddressSpace::Virtual, address, 32);
    if (!ExactBytes(block, 32))
    {
        return {};
    }
    return ServiceDescriptor{*BlockValue(block, 0, 8), *BlockValue(block, 8, 8), static_cast<uint32_t>(*BlockValue(block, 16, 4)),
                             *BlockValue(block, 24, 8)};
}

inline bool ServiceDescriptorMatches(const ServiceDescriptor &descriptor, uint64_t table, uint32_t limit, uint64_t arguments)
{
    return descriptor.Table == table && descriptor.Limit == limit && descriptor.Arguments == arguments && limit > 0 && limit <= 4096;
}

inline bool RecheckServiceDescriptor(TargetReader &reader, uint64_t address, const ServiceDescriptor &expected, WalkBudget &budget)
{
    if (!CheckWalkDeadline(budget))
    {
        return false;
    }
    const auto observed = ReadServiceDescriptor(reader, address);
    return CheckWalkDeadline(budget) && (observed == expected || budget.Stop(Status::StaleContext, L"ServiceDescriptorsChanged"));
}

template <typename Emit>
void CollectServiceEntries(TargetReader &reader, const TargetArchitecture &architecture, const OwnershipIndex &owners, uint64_t table,
                           uint32_t count, const wchar_t *family, uint32_t serviceBase, const std::wstring &profile, WalkBudget &budget,
                           Emit emit)
{
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    if (count == 0 || count > 4096 || !architecture.KernelPointer(table) || !ValidRange(table, uint64_t(count) * 4) ||
        !architecture.KernelPointer(table + uint64_t(count) * 4 - 1))
    {
        budget.Stop(Status::Unavailable, L"InvalidServiceTableExtent");
        return;
    }
    budget.Report.Collected.Expected += count;
    for (uint32_t first = 0; first < count && CheckWalkDeadline(budget); first += 256)
    {
        const auto length = std::min<uint32_t>(256, count - first);
        const auto block = reader.Read(AddressSpace::Virtual, table + uint64_t(first) * 4, length * 4);
        for (uint32_t i = 0; i < length && CheckWalkDeadline(budget); ++i)
        {
            if (budget.Report.Collected.Visited >= budget.MaxNodes)
            {
                budget.Stop(Status::Partial, L"GlobalWalkBudget");
                break;
            }
            const auto index = first + i;
            const auto slot = table + uint64_t(index) * 4;
            ++budget.Report.Collected.Visited;
            auto raw = BlockValue(block, i * 4, 4);
            if (!raw)
            {
                uint32_t retry = 0;
                if (reader.ReadExact(AddressSpace::Virtual, slot, &retry))
                {
                    raw = retry;
                }
                if (!CheckWalkDeadline(budget))
                {
                    break;
                }
            }
            std::optional<uint64_t> routine;
            if (raw)
            {
                ++budget.Report.Collected.Read;
                routine = DecodeServiceEntry(table, static_cast<int32_t>(static_cast<uint32_t>(*raw)));
                ++budget.Report.Collected.Decoded;
            }
            else
            {
                ++budget.Report.Collected.Unreadable;
            }
            auto row = RoutineObservation(budget.Report, architecture, owners, family, slot, routine);
            row.Set(L"index", knjson::Value(std::to_wstring(index)));
            row.Set(L"serviceId", knjson::Value(Hex(serviceBase + index)));
            row.Set(L"serviceTable", knjson::Value(Hex(table)));
            row.Set(L"encodedEntry", OptionalNumber(raw, true));
            row.Set(L"profile", knjson::Value(profile));
            row.Set(L"encoding", knjson::Value(L"x64SignedRelativeShift4"));
            emit(row);
        }
    }
    CheckWalkDeadline(budget);
}
} // namespace kncore
