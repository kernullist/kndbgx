#pragma once

#include "KernelAnalysis.h"
#include "CollectorRead.h"
#include <map>

namespace kncore
{
struct IrpLayout
{
    uint32_t HeaderBytes = 0;
    uint32_t StackBytes = 0;
    std::map<std::wstring, FieldInfo> Header;
    std::map<std::wstring, FieldInfo> Stack;
};

inline std::optional<uint64_t> BufferField(std::span<const unsigned char> bytes, const std::map<std::wstring, FieldInfo> &fields,
                                           const wchar_t *name, unsigned width)
{
    const auto found = fields.find(name);
    if (found == fields.end() || found->second.Size != width || !found->second.ValidFor(static_cast<uint32_t>(bytes.size())) ||
        found->second.BitOffset || found->second.BitWidth || (width != 1 && width != 2 && width != 4 && width != 8))
    {
        return {};
    }
    uint64_t value = 0;
    std::memcpy(&value, bytes.data() + found->second.Offset, width);
    return value;
}

inline Result InspectIrpBytes(uint64_t address, std::span<const unsigned char> bytes, const IrpLayout &layout)
{
    Result result;
    result.Source = L"target-memory";
    result.Consistency = L"single-read-best-effort";
    if (layout.HeaderBytes > bytes.size())
    {
        result.State = Status::Unavailable;
        result.Error.Message = L"IRP header unavailable";
        return result;
    }
    const auto header = bytes.first(layout.HeaderBytes);
    const auto type = BufferField(header, layout.Header, L"Type", 2);
    const auto size = BufferField(header, layout.Header, L"Size", 2);
    const auto count = BufferField(header, layout.Header, L"StackCount", 1);
    const auto current = BufferField(header, layout.Header, L"CurrentLocation", 1);
    if (!type || !size || !count || !current ||
        !ValidIrpGeometry(address, *type, *size, layout.HeaderBytes, layout.StackBytes, *count, *current) || *size > bytes.size())
    {
        result.State = Status::Unavailable;
        result.Error.Message = L"IRP type, size, stack count or current location is inconsistent";
        return result;
    }
    auto value = [&](std::span<const unsigned char> buffer, const auto &fields, const wchar_t *name, unsigned width, bool hex = true)
    {
        const auto field = BufferField(buffer, fields, name, width);
        if (!field)
        {
            ++result.Collected.Unknown;
        }
        return OptionalNumber(field, hex);
    };
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"Irp"));
    row.Set(L"address", knjson::Value(Hex(address)));
    row.Set(L"addressSpace", knjson::Value(L"virtual"));
    row.Set(L"size", knjson::Value(std::to_wstring(*size)));
    row.Set(L"stackCount", knjson::Value(std::to_wstring(*count)));
    row.Set(L"currentLocation", knjson::Value(std::to_wstring(*current)));
    for (const wchar_t *name : {L"MdlAddress", L"UserBuffer", L"CancelRoutine", L"SystemBuffer", L"Thread", L"CurrentStackLocation"})
    {
        row.Set(name, value(header, layout.Header, name, 8));
    }
    row.Set(L"flags", value(header, layout.Header, L"Flags", 4));
    row.Set(L"cancel", value(header, layout.Header, L"Cancel", 1, false));
    row.Set(L"pendingReturned", value(header, layout.Header, L"PendingReturned", 1, false));
    row.Set(L"requestorMode", value(header, layout.Header, L"RequestorMode", 1, false));
    row.Set(L"status", value(header, layout.Header, L"Status", 4));
    row.Set(L"information", value(header, layout.Header, L"Information", 8));
    const auto stackPointer = BufferField(header, layout.Header, L"CurrentStackLocation", 8);
    if (stackPointer && *stackPointer != address + layout.HeaderBytes + (*current - 1) * layout.StackBytes)
    {
        ++result.Collected.Unknown;
        row.Set(L"stackPointerMismatch", knjson::Value(true));
    }
    result.Rows.Push(row);
    for (uint64_t i = 0; i < *count; ++i)
    {
        const auto stack = bytes.subspan(layout.HeaderBytes + static_cast<size_t>(i * layout.StackBytes), layout.StackBytes);
        auto item = knjson::Value::MakeObject();
        const auto major = BufferField(stack, layout.Stack, L"MajorFunction", 1);
        const auto control = BufferField(stack, layout.Stack, L"Control", 1);
        item.Set(L"kind", knjson::Value(L"IoStackLocation"));
        item.Set(L"address", knjson::Value(Hex(address + layout.HeaderBytes + i * layout.StackBytes)));
        item.Set(L"addressSpace", knjson::Value(L"virtual"));
        item.Set(L"slot", knjson::Value(std::to_wstring(i + 1)));
        item.Set(L"current", knjson::Value(i + 1 == *current));
        item.Set(L"major", value(stack, layout.Stack, L"MajorFunction", 1));
        item.Set(L"majorName", major ? knjson::Value(IrpMajorName(static_cast<unsigned>(*major))) : knjson::Value());
        item.Set(L"minor", value(stack, layout.Stack, L"MinorFunction", 1));
        item.Set(L"control", value(stack, layout.Stack, L"Control", 1));
        for (const wchar_t *name : {L"DeviceObject", L"FileObject", L"CompletionRoutine", L"Context"})
        {
            item.Set(name, value(stack, layout.Stack, name, 8));
        }
        item.Set(L"invokeOnSuccess", control ? knjson::Value((*control & 0x40) != 0) : knjson::Value());
        item.Set(L"invokeOnError", control ? knjson::Value((*control & 0x80) != 0) : knjson::Value());
        item.Set(L"invokeOnCancel", control ? knjson::Value((*control & 0x20) != 0) : knjson::Value());
        if (major && (*major == 14 || *major == 15))
        {
            const auto ioctl = BufferField(stack, layout.Stack, L"IoControlCode", 4);
            item.Set(L"ioctl", ioctl ? DecodeIoctl(static_cast<uint32_t>(*ioctl)) : knjson::Value());
            item.Set(L"inputLength", value(stack, layout.Stack, L"InputBufferLength", 4, false));
            item.Set(L"outputLength", value(stack, layout.Stack, L"OutputBufferLength", 4, false));
            item.Set(L"type3InputBuffer", value(stack, layout.Stack, L"Type3InputBuffer", 8));
            if (!ioctl)
            {
                ++result.Collected.Unknown;
            }
        }
        result.Rows.Push(item);
    }
    result.Collected.Visited = result.Rows.Items().size();
    result.Collected.Decoded = result.Collected.Visited;
    result.Collected.Complete = result.Collected.Unknown == 0;
    result.Collected.StopReason = result.Collected.Complete ? L"IrpDecoded" : L"IrpFieldsUnavailableOrInconsistent";
    result.State = result.Collected.Complete ? Status::Success : Status::Partial;
    result.Limitations.Push(knjson::Value(L"Stack slots may be unused or stale; buffer pointers are not dereferenced"));
    return result;
}
} // namespace kncore
