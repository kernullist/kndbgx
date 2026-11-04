#pragma once

#include "CollectorRead.h"

namespace kncore
{
inline bool EtwPointerField(const std::optional<FieldInfo> &field, const TargetArchitecture &architecture)
{
    return field && field->Kind == FieldKind::Pointer && !field->FunctionPointer && field->Size == architecture.PointerBytes &&
           !field->BitOffset && !field->BitWidth;
}

inline bool EtwIntegerField(const std::optional<FieldInfo> &field)
{
    return field && field->Kind == FieldKind::Unsigned && field->SimpleWritable();
}

struct EtwLoggerTable
{
    uint64_t Address = 0;
    uint64_t Count = 0;
};

inline std::optional<EtwLoggerTable> ReadEtwLoggerTable(TargetReader &reader, const TargetArchitecture &architecture, uint64_t host,
                                                        const std::optional<FieldInfo> &siloField,
                                                        const std::optional<FieldInfo> &arrayField,
                                                        const std::optional<FieldInfo> &countField)
{
    std::optional<EtwLoggerTable> table;
    do
    {
        if (!architecture.KernelPointer(host) || !EtwPointerField(siloField, architecture) || !EtwPointerField(arrayField, architecture) ||
            !EtwIntegerField(countField))
        {
            break;
        }
        const auto silo = ReadField(reader, host, siloField);
        if (!silo || !architecture.KernelPointer(*silo))
        {
            break;
        }
        const auto array = ReadField(reader, *silo, arrayField);
        const auto count = ReadField(reader, *silo, countField);
        if (!array || !count || !architecture.KernelPointer(*array) || *count > 4096 ||
            (*count != 0 && !ValidRange(*array, *count * architecture.PointerBytes)))
        {
            break;
        }
        table = EtwLoggerTable{*array, *count};
    } while (false);
    return table;
}

struct EtwClockObservation
{
    std::optional<uint64_t> Raw;
    std::optional<uint64_t> Type;
    const wchar_t *Representation = L"Unknown";
    bool Known = false;
};

inline EtwClockObservation ReadEtwClock(TargetReader &reader, const TargetArchitecture &architecture, uint64_t logger,
                                        const std::optional<FieldInfo> &clockField, const std::optional<FieldInfo> &typeField,
                                        bool typeAbsent, bool verifiedSelectors)
{
    EtwClockObservation clock;
    do
    {
        if (!architecture.KernelPointer(logger) || !clockField || clockField->BitOffset || clockField->BitWidth)
        {
            break;
        }
        const bool function =
            clockField->Kind == FieldKind::Pointer && clockField->FunctionPointer && clockField->Size == architecture.PointerBytes;
        const bool integer = EtwIntegerField(clockField);
        if (!function && !integer)
        {
            break;
        }
        clock.Representation = function ? L"FunctionPointer" : verifiedSelectors ? L"IntegerSelector" : L"RawInteger";
        clock.Raw = ReadField(reader, logger, clockField);
        if (EtwIntegerField(typeField))
        {
            clock.Type = ReadField(reader, logger, typeField);
        }
        clock.Known = clock.Raw && (typeField ? clock.Type.has_value() : typeAbsent) &&
                      (function ? architecture.KernelPointer(*clock.Raw) : !verifiedSelectors || *clock.Raw <= 3) &&
                      (!verifiedSelectors || integer);
    } while (false);
    return clock;
}
} // namespace kncore
