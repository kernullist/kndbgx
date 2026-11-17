#pragma once

#include "CollectorRead.h"

namespace kncore
{
struct DriverRecordFields
{
    knjson::Value Fields = knjson::Value::MakeObject();
    std::optional<uint64_t> FirstDevice;
    uint64_t Unknown = 0;
};

// The caller must corroborate the Driver object before reading its fields.
template <typename Resolve>
DriverRecordFields ReadDriverRecordFields(TargetReader &reader, const TargetArchitecture &architecture, uint64_t object,
                                         Resolve resolve)
{
    DriverRecordFields result;
    struct Entry
    {
        const wchar_t *Name;
        const wchar_t *Field;
        bool Pointer;
    };
    const Entry entries[] = {{L"start", L"DriverStart", true}, {L"size", L"DriverSize", false},
                             {L"firstDevice", L"DeviceObject", true}, {L"flags", L"Flags", false},
                             {L"driverInit", L"DriverInit", true}, {L"driverUnload", L"DriverUnload", true},
                             {L"driverStartIo", L"DriverStartIo", true}};
    for (const auto &entry : entries)
    {
        const auto field = resolve(entry.Field);
        std::optional<uint64_t> value;
        if (architecture.KernelPointer(object) && field && field->Size == (entry.Pointer ? architecture.PointerBytes : 4) &&
            !field->BitOffset && !field->BitWidth &&
            (entry.Pointer ? field->Kind == FieldKind::Pointer : field->Kind == FieldKind::Unsigned))
        {
            value = ReadField(reader, object, field);
            if (entry.Pointer && value && *value != 0 && !architecture.KernelPointer(*value))
            {
                value.reset();
            }
        }
        result.Fields.Set(entry.Name, OptionalNumber(value, entry.Pointer || std::wstring_view(entry.Name) == L"flags"));
        if (!value)
        {
            ++result.Unknown;
        }
        if (std::wstring_view(entry.Name) == L"firstDevice")
        {
            result.FirstDevice = value;
        }
    }
    return result;
}
} // namespace kncore
