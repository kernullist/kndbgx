#pragma once

#include "Result.h"
#include <algorithm>
#include <set>
#include <vector>

namespace kncore
{
inline bool ResultHasTargetAddresses(const Result &source)
{
    return !source.Consistency.starts_with(L"immutable-file") && source.Source != L"HostDumpMetadata" &&
        !source.Source.starts_with(L"host-file:") && !source.Source.starts_with(L"HostFiles:") &&
        source.Source != L"SnapshotArtifacts" && source.Source != L"LegacyTextImport";
}

inline bool AddressPathPart(const std::wstring &part)
{
    return !part.empty() && part.size() <= 64 && std::all_of(part.begin(), part.end(),
        [](wchar_t c)
        {
            return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'_';
        });
}

inline std::optional<std::wstring> AddressFieldSpace(const knjson::Value &row, const std::wstring &field,
                                                    const std::wstring &inheritedSpace)
{
    const auto &explicitSpace = row.Get(L"addressSpace");
    if (!explicitSpace.IsNull() && (!explicitSpace.IsString() ||
        (explicitSpace.AsString(L"") != L"virtual" && explicitSpace.AsString(L"") != L"physical")))
    {
        return std::nullopt;
    }
    const auto kind = row.Get(L"kind").AsString(L"");
    if ((kind == L"RoutineObservation" && field == L"routine") ||
        (kind == L"ObjectCallbackRegistration" && (field == L"preRoutine" || field == L"postRoutine")))
    {
        const auto space = explicitSpace.IsString() ? explicitSpace.AsString(L"") : inheritedSpace;
        return space == L"virtual" ? std::optional<std::wstring>(space) : std::nullopt;
    }
    if (field == L"pa" || field == L"physical" || field == L"physicalAddress" || field == L"physicalSlot" || field == L"dtb")
    {
        return L"physical";
    }
    if (field == L"va")
    {
        return L"virtual";
    }
    static const std::set<std::wstring> virtualFields = {
        L"address", L"symbolAddress", L"routine", L"handler", L"pointer", L"slot", L"base", L"baseAddress", L"moduleBase",
        L"start", L"end", L"eprocess", L"ethread", L"object", L"device", L"driverObject", L"DriverObject",
        L"firstDevice", L"attachedTo", L"ownerProcess", L"connectionPort", L"filter", L"frame", L"stack", L"return",
        L"entry", L"listEntry", L"readAddress", L"nextAddress", L"instructionPointer", L"win32Start", L"context",
        L"preRoutine", L"postRoutine", L"CompletionRoutine", L"CancelRoutine", L"DispatchRoutine", L"StartAddress", L"EndAddress",
        L"MdlAddress", L"UserBuffer", L"SystemBuffer", L"Thread", L"CurrentStackLocation", L"DeviceObject", L"FileObject",
        L"Context", L"type3InputBuffer", L"hive", L"deferredContext", L"record", L"attachedFrom", L"dpc", L"serviceTable", L"descriptor",
        L"communicationInfo", L"serverPort", L"clientPort", L"peerPort", L"entryRoutine", L"dispatchSlot", L"sessionState",
        L"sessionApi", L"filterPredicate", L"filterHandler", L"filterImport", L"conditionalFallback", L"filterBitmap", L"userSessionState"};
    if (virtualFields.contains(field))
    {
        return explicitSpace.IsString() ? explicitSpace.AsString(L"") : inheritedSpace;
    }
    if (kind == L"PiDDBAvlNode" && (field == L"parent" || field == L"left" || field == L"right"))
    {
        return L"virtual";
    }
    if (kind == L"CiHashLink" && field == L"next")
    {
        return L"virtual";
    }
    if (field == L"value")
    {
        const auto name = row.Get(L"name").AsString(L"");
        const auto reg = row.Get(L"register").AsString(L"");
        if (kind == L"ExpressionValue" || (kind == L"Register" &&
            (name == L"rip" || name == L"eip" || name == L"rsp" || name == L"esp" || name == L"rbp" || name == L"ebp" ||
             name == L"pc" || name == L"sp" || name == L"fp")) ||
            (kind == L"ProcessorRegister" && (reg == L"LSTAR" || reg == L"CSTAR" || reg == L"SYSENTER_EIP")))
        {
            return L"virtual";
        }
    }
    return std::nullopt;
}

// This projection does not change stored rows, exports, or snapshot comparisons.
inline knjson::Value ResultAddressFields(const knjson::Value &row, const Result *source = nullptr)
{
    auto fields = knjson::Value::MakeArray();
    const auto kind = row.Get(L"kind").AsString(L"");
    if ((source != nullptr && !ResultHasTargetAddresses(*source)) || !row.IsObject() ||
        kind == L"SnapshotDifference" || kind == L"RecordReference")
    {
        return fields;
    }
    size_t visited = 0;
    const auto visit = [&](const auto &self, const knjson::Value &object, const knjson::Value &path,
                           const std::wstring &inheritedSpace) -> void
    {
        if (!object.IsObject() || path.Items().size() >= 4 || (!path.Items().empty() && object.Get(L"historical").AsBool(false)))
        {
            return;
        }
        const auto &explicitSpace = object.Get(L"addressSpace");
        const auto spaceName = explicitSpace.IsNull() ? inheritedSpace : explicitSpace.AsString(L"");
        if (spaceName != L"virtual" && spaceName != L"physical")
        {
            return;
        }
        for (const auto &[key, value] : object.Fields())
        {
            if (++visited > 512 || fields.Items().size() >= 32)
            {
                break;
            }
            if (!AddressPathPart(key) || key == L"target" || key == L"contextIdentity" || key == L"provenance" ||
                key == L"before" || key == L"after")
            {
                continue;
            }
            auto child = path;
            child.Push(knjson::Value(key));
            if (value.IsObject())
            {
                self(self, value, child, spaceName);
                continue;
            }
            const auto space = AddressFieldSpace(object, key, spaceName);
            if (!space || (!value.IsString() && !value.IsNull()))
            {
                continue;
            }
            if (value.IsString())
            {
                const auto text = value.AsString(L"");
                uint64_t address = 0;
                if (!(text.starts_with(L"0x") || text.starts_with(L"0X")) || text.size() > 18 || !ParseUnsigned(text, 16, &address))
                {
                    continue;
                }
            }
            auto descriptor = knjson::Value::MakeObject();
            descriptor.Set(L"path", child);
            descriptor.Set(L"space", knjson::Value(*space));
            descriptor.Set(L"allowZero", knjson::Value(*space == L"physical" ||
                (key == L"address" && object.Get(L"addressSpace").IsString())));
            const auto &process = row.Get(L"process");
            if (*space == L"virtual" && process.IsObject())
            {
                uint64_t address = 0;
                ParseUnsigned(process.Get(L"eprocess").AsString(L""), 16, &address);
                descriptor.Set(L"process", knjson::Value(Hex(address)));
            }
            fields.Push(std::move(descriptor));
        }
    };
    visit(visit, row, knjson::Value::MakeArray(), L"virtual");
    return fields;
}

inline const knjson::Value &AddressPathValue(const knjson::Value &row, const knjson::Value &path)
{
    const auto *value = &row;
    for (const auto &part : path.Items())
    {
        value = &value->Get(part.AsString(L""));
    }
    return *value;
}
} // namespace kncore
