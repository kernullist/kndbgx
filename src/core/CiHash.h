#pragma once

#include "CollectorRead.h"

namespace kncore
{
inline bool CheckRecordBudget(WalkBudget &budget)
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

inline bool KernelRecordRange(const TargetArchitecture &architecture, uint64_t address, size_t size)
{
    return size != 0 && ValidRange(address, size) && architecture.KernelPointer(address) &&
           architecture.KernelPointer(address + size - 1);
}

// The caller must verify the exact CI image, PDB, root storage and code windows.
inline void CollectCiHashEntries(TargetReader &source, const TargetArchitecture &architecture, uint64_t root, WalkBudget &budget)
{
    CollectionReadGuard reader(source, budget);
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    if (!CheckRecordBudget(budget))
    {
        return;
    }
    if (!KernelRecordRange(architecture, root, 8))
    {
        budget.Stop(Status::Unavailable, L"InvalidCiHashRoot");
        return;
    }
    uint64_t first = 0;
    const bool headRead = reader.ReadExact(AddressSpace::Virtual, root, &first);
    if (!CheckRecordBudget(budget))
    {
        return;
    }
    if (!headRead)
    {
        ++budget.Report.Collected.Unreadable;
        budget.Stop(Status::Unavailable, L"UnreadableCiHashRoot");
        return;
    }
    const auto value = [](const ReadResult &bytes, size_t offset, size_t size)
    {
        uint64_t result = 0;
        std::memcpy(&result, bytes.Bytes.data() + offset, size);
        return result;
    };
    uint64_t node = first;
    while (node != 0 && CheckRecordBudget(budget))
    {
        if (!KernelRecordRange(architecture, node, 0x48))
        {
            budget.Stop(Status::Partial, L"InvalidCiHashEntry");
            break;
        }
        if (!budget.Consume(node, architecture))
        {
            break;
        }
        const auto bytes = reader.Read(AddressSpace::Virtual, node, 0x48);
        if (!CheckRecordBudget(budget))
        {
            break;
        }
        if (!ExactBytes(bytes, 0x48))
        {
            ++budget.Report.Collected.Unreadable;
            budget.Stop(Status::Partial, L"UnreadableCiHashEntry");
            break;
        }
        ++budget.Report.Collected.Read;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"CiHashEntry"));
        row.Set(L"entry", knjson::Value(Hex(node)));
        row.Set(L"name", knjson::Value());
        row.Set(L"cacheStatusRaw", knjson::Value(L"0x" + Hex(value(bytes, 0x40, 4)).substr(10)));
        for (const auto &[label, offset] : {std::pair(L"hash", 0x18u), std::pair(L"secondaryHash", 0x2cu)})
        {
            constexpr wchar_t digits[] = L"0123456789abcdef";
            std::wstring hash;
            for (size_t i = 0; i < 20; ++i)
            {
                hash += digits[bytes.Bytes[offset + i] >> 4];
                hash += digits[bytes.Bytes[offset + i] & 15];
            }
            row.Set(label, knjson::Value(hash));
        }
        const auto length = value(bytes, 8, 2);
        const auto maximum = value(bytes, 0xa, 2);
        const auto buffer = value(bytes, 0x10, 8);
        bool named = length == 0 && maximum % 2 == 0;
        if (named)
        {
            row.Set(L"name", knjson::Value(L""));
        }
        if (length != 0 && length <= maximum && length <= 2048 && length % 2 == 0 && maximum % 2 == 0 && buffer % 2 == 0 &&
            KernelRecordRange(architecture, buffer, static_cast<size_t>(length)))
        {
            const auto nameBytes = reader.Read(AddressSpace::Virtual, buffer, static_cast<size_t>(length));
            if (!CheckRecordBudget(budget))
            {
                break;
            }
            if (ExactBytes(nameBytes, static_cast<size_t>(length)))
            {
                std::wstring name(static_cast<size_t>(length / 2), L'\0');
                std::memcpy(name.data(), nameBytes.Bytes.data(), static_cast<size_t>(length));
                named = ValidUtf16(name, false);
                if (named)
                {
                    row.Set(L"name", knjson::Value(name));
                }
            }
            else
            {
                ++budget.Report.Collected.Unreadable;
            }
        }
        if (named)
        {
            ++budget.Report.Collected.Decoded;
        }
        else
        {
            ++budget.Report.Collected.Unknown;
            row.Set(L"reason", knjson::Value(L"CiHashNameUnavailable"));
        }
        auto topology = knjson::Value::MakeObject();
        topology.Set(L"kind", knjson::Value(L"CiHashLink"));
        node = value(bytes, 0, 8);
        topology.Set(L"next", knjson::Value(Hex(node)));
        row.Set(L"topology", topology);
        budget.Report.Rows.Push(row);
    }
    if (CheckRecordBudget(budget))
    {
        uint64_t current = 0;
        const bool read = reader.ReadExact(AddressSpace::Virtual, root, &current);
        if (!CheckRecordBudget(budget))
        {
            return;
        }
        if (!read)
        {
            ++budget.Report.Collected.Unreadable;
            budget.Stop(Status::Partial, L"UnreadableCiHashRootAfterWalk");
        }
        else if (current != first)
        {
            budget.Stop(Status::Partial, L"CiHashRootChangedDuringWalk");
        }
        else if (budget.Report.Collected.Unknown != 0 || budget.Report.Collected.Unreadable != 0)
        {
            budget.Stop(Status::Partial, L"CiHashFieldsUnavailable");
        }
    }
}
} // namespace kncore
