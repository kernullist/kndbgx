#pragma once

#include "CollectorRead.h"

namespace kncore
{
inline bool PiddbFieldMatches(const std::optional<FieldInfo> &field, uint32_t offset, uint32_t size, FieldKind kind)
{
    return field && field->Offset == offset && field->Size == size && field->Kind == kind &&
           !field->BitOffset && !field->BitWidth && field->ValidFor(offset + size);
}

inline std::wstring PiddbHex32(uint32_t value)
{
    return L"0x" + Hex(value).substr(10);
}

inline const wchar_t *PiddbStatusClass(uint32_t value)
{
    constexpr const wchar_t *classes[] = {L"Success", L"Informational", L"Warning", L"Error"};
    return value == 0 ? L"STATUS_SUCCESS" : classes[value >> 30];
}

inline bool PiddbKernelRange(const TargetArchitecture &architecture, uint64_t address, size_t length)
{
    return length != 0 && ValidRange(address, length) && architecture.KernelPointer(address) &&
           architecture.KernelPointer(address + length - 1);
}

// Call only after the exact image, code windows and PDB field shapes are verified.
inline void CollectPiddbEntries(TargetReader &reader, const TargetArchitecture &architecture, uint64_t table,
                               uint64_t compareRoutine, WalkBudget &budget)
{
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    const auto checkBudget = [&]()
    {
        if (budget.Stopped)
        {
            return false;
        }
        if (budget.Cancelled && budget.Cancelled())
        {
            return budget.Stop(Status::Cancelled, L"Cancelled");
        }
        if (std::chrono::steady_clock::now() >= budget.Deadline)
        {
            return budget.Stop(Status::Partial, L"GlobalWalkBudget");
        }
        return true;
    };
    if (!checkBudget())
    {
        return;
    }
    if (!PiddbKernelRange(architecture, table, 0x50) || !architecture.KernelPointer(compareRoutine))
    {
        budget.Stop(Status::Unavailable, L"InvalidPiDDBTableAddress");
        return;
    }
    const auto header = reader.Read(AddressSpace::Virtual, table, 0x50);
    if (!checkBudget())
    {
        return;
    }
    if (!ExactBytes(header, 0x50))
    {
        ++budget.Report.Collected.Unreadable;
        budget.Stop(Status::Unavailable, L"UnreadablePiDDBTable");
        return;
    }
    const auto value = [](const ReadResult &read, size_t offset, size_t size)
    {
        uint64_t result = 0;
        std::memcpy(&result, read.Bytes.data() + offset, size);
        return result;
    };
    const auto root = value(header, 0x10, 8);
    const auto count = value(header, 0x2c, 4);
    budget.Report.Collected.Expected = count;
    if (value(header, 0x48, 8) != compareRoutine || (root == 0) != (count == 0) || count > budget.MaxNodes)
    {
        budget.Stop(Status::Partial, L"InvalidPiDDBTableHeader");
        return;
    }
    std::vector<std::pair<uint64_t, uint64_t>> pending;
    if (root != 0)
    {
        pending.emplace_back(root, table);
    }
    while (!pending.empty())
    {
        if (!checkBudget())
        {
            break;
        }
        const auto [node, parent] = pending.back();
        pending.pop_back();
        if (!PiddbKernelRange(architecture, node, 0x48))
        {
            budget.Stop(Status::Partial, L"InvalidPiDDBNodeAddress");
            break;
        }
        if (!budget.Consume(node, architecture))
        {
            break;
        }
        if (budget.Report.Collected.Visited > count)
        {
            budget.Stop(Status::Partial, L"PiDDBElementCountMismatch");
            break;
        }
        const auto bytes = reader.Read(AddressSpace::Virtual, node, 0x48);
        if (!ExactBytes(bytes, 0x48))
        {
            ++budget.Report.Collected.Unreadable;
            continue;
        }
        ++budget.Report.Collected.Read;
        if (value(bytes, 0, 8) != parent)
        {
            budget.Stop(Status::Partial, L"PiDDBParentMismatch");
            break;
        }
        const auto left = value(bytes, 8, 8);
        const auto right = value(bytes, 0x10, 8);
        if (right != 0)
        {
            pending.emplace_back(right, node);
        }
        if (left != 0)
        {
            pending.emplace_back(left, node);
        }

        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"PiDDBEntry"));
        row.Set(L"entry", knjson::Value(Hex(node + 0x20)));
        row.Set(L"name", knjson::Value());
        row.Set(L"timeDateStamp", knjson::Value(PiddbHex32(static_cast<uint32_t>(value(bytes, 0x40, 4)))));
        const auto status = static_cast<uint32_t>(value(bytes, 0x44, 4));
        row.Set(L"loadStatus", knjson::Value(PiddbHex32(status)));
        row.Set(L"loadStatusClass", knjson::Value(PiddbStatusClass(status)));
        auto topology = knjson::Value::MakeObject();
        topology.Set(L"kind", knjson::Value(L"PiDDBAvlNode"));
        topology.Set(L"address", knjson::Value(Hex(node)));
        topology.Set(L"parent", knjson::Value(Hex(parent)));
        topology.Set(L"left", knjson::Value(Hex(left)));
        topology.Set(L"right", knjson::Value(Hex(right)));
        row.Set(L"topology", topology);

        const auto length = value(bytes, 0x30, 2);
        const auto maximum = value(bytes, 0x32, 2);
        const auto buffer = value(bytes, 0x38, 8);
        const wchar_t *reason = L"InvalidDriverName";
        bool named = false;
        if (length != 0 && length <= maximum && length <= 2048 && length % 2 == 0 && maximum % 2 == 0 &&
            buffer % 2 == 0 && PiddbKernelRange(architecture, buffer, static_cast<size_t>(length)))
        {
            const auto nameBytes = reader.Read(AddressSpace::Virtual, buffer, static_cast<size_t>(length));
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
                reason = L"UnreadableDriverName";
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
            row.Set(L"reason", knjson::Value(reason));
        }
        budget.Report.Rows.Push(row);
    }
    if (!budget.Stopped)
    {
        if (!checkBudget())
        {
            return;
        }
        const auto finalHeader = reader.Read(AddressSpace::Virtual, table, 0x50);
        // A blocking final read can outlast the budget or receive cancellation.
        if (!checkBudget())
        {
            return;
        }
        if (!ExactBytes(finalHeader, 0x50))
        {
            ++budget.Report.Collected.Unreadable;
            budget.Stop(Status::Partial, L"UnreadablePiDDBTableAfterWalk");
        }
        else if (value(finalHeader, 0x10, 8) != root || value(finalHeader, 0x2c, 4) != count ||
                 value(finalHeader, 0x40, 4) != value(header, 0x40, 4) || value(finalHeader, 0x48, 8) != compareRoutine)
        {
            budget.Stop(Status::Partial, L"PiDDBTableChangedDuringWalk");
        }
        else if (budget.Report.Collected.Visited != count || budget.Report.Rows.Items().size() != count)
        {
            budget.Stop(Status::Partial, L"PiDDBElementCountMismatch");
        }
        else if (budget.Report.Collected.Unknown != 0 || budget.Report.Collected.Unreadable != 0)
        {
            budget.Stop(Status::Partial, L"PiDDBFieldsUnavailable");
        }
    }
}
} // namespace kncore
