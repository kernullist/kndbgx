#pragma once

#include "Result.h"
#include "Input.h"
#include "ResultAction.h"
#include <algorithm>

namespace kncore
{
inline knjson::Value MemoryReadAttempt(const ReadResult &read)
{
    auto value = knjson::Value::MakeObject();
    value.Set(L"address", knjson::Value(Hex(read.Address)));
    value.Set(L"requested", knjson::Value(std::to_wstring(read.Requested)));
    value.Set(L"read", knjson::Value(std::to_wstring(read.Transferred)));
    value.Set(L"status", knjson::Value(StatusName(read.State)));
    value.Set(L"nativeError", read.Error.Domain.empty() ? knjson::Value() : read.Error.ToJson());
    return value;
}

inline knjson::Value MemoryReadEvidence(uint64_t address, AddressSpace space, size_t length, size_t readable,
                                       const knjson::Value &attempts, const knjson::Value &capture)
{
    auto value = knjson::Value::MakeObject();
    value.Set(L"schema", knjson::Value(L"kndbgx.memory-read.v1"));
    value.Set(L"address", knjson::Value(Hex(address)));
    value.Set(L"addressSpace", knjson::Value(space == AddressSpace::Physical ? L"physical" : L"virtual"));
    value.Set(L"length", knjson::Value(std::to_wstring(length)));
    value.Set(L"read", knjson::Value(std::to_wstring(readable)));
    value.Set(L"attempts", attempts);
    value.Set(L"capture", capture);
    value.Set(L"mapping", knjson::Value(L"Unobserved"));
    value.Set(L"unreadableCause", knjson::Value(L"Unknown"));
    return value;
}

inline bool ViewAddressExpression(const std::wstring &expression)
{
    return !expression.empty() && expression.size() <= 1024 && expression.find_first_of(L";\"\\{}") == std::wstring::npos &&
        ValidUtf16(expression, false) && !std::all_of(expression.begin(), expression.end(),
            [](wchar_t value)
            {
                return value == L' ';
            }) && !std::any_of(expression.begin(), expression.end(),
            [](wchar_t value)
            {
                return value < 32;
            });
}

inline std::optional<std::wstring> MemoryViewCommand(const knjson::Value &parameters, const StoredResult *source = nullptr,
                                                    const SessionStamp *current = nullptr)
{
    auto expression = parameters.Get(L"expression").AsString(L"");
    const auto space = parameters.Get(L"space").AsString(L"");
    const auto &binding = parameters.Get(L"source");
    if (!binding.IsNull() && !binding.IsObject())
    {
        return std::nullopt;
    }
    if (binding.IsObject() && !binding.Fields().empty())
    {
        const auto location = source != nullptr && current != nullptr && binding.Get(L"action").AsString(L"") == L"memory" ?
            BoundResultAddress(*source, binding, *current) : std::nullopt;
        if (!location || location->Space != space)
        {
            return std::nullopt;
        }
        expression = Hex(location->Address);
    }
    uint64_t length = 0;
    if (!ViewAddressExpression(expression) || (space != L"virtual" && space != L"physical") ||
        !ParseUnsigned(parameters.Get(L"length").AsString(L""), 10, &length) || (length != 64 && length != 256 && length != 1024))
    {
        return std::nullopt;
    }
    return std::wstring(space == L"physical" ? L"!db \"" : L"db \"") + expression + L"\" L" + Hex(length);
}

inline std::optional<std::wstring> MemoryDumpCommand(const knjson::Value &parameters, const StoredResult &source,
                                                     const SessionStamp &current, bool kernelMode)
{
    const auto &binding = parameters.Get(L"source");
    if ((source.Data.CommandId != L"db" && source.Data.CommandId != L"!db") ||
        binding.Get(L"collection").AsString(L"") != L"rows" || !binding.Get(L"byteOffset").IsString())
    {
        return std::nullopt;
    }
    const auto location = ResolveStampedResultAddress(source, binding, current);
    const auto path = parameters.Get(L"path").AsString(L"");
    // Fixed byte addresses need a system and address space. User dumps often
    // have no implicit kernel objects, and a stack frame is not required.
    if (!location || !current.Context.System || (location->Space == L"virtual" &&
        (!current.Context.Process || (kernelMode && !current.Context.ImplicitProcess.value_or(0)))) ||
        path.find_first_not_of(L' ') == std::wstring::npos || path.ends_with(L'\\') || path.ends_with(L'/') || path.find(L'"') != std::wstring::npos ||
        !ValidUtf16(path, false) || std::any_of(path.begin(), path.end(), [](wchar_t ch)
        {
            return ch < 32;
        }))
    {
        return std::nullopt;
    }
    const auto operation = parameters.Get(L"operation").AsString(L"");
    const auto length = parameters.Get(L"length").AsString(L"");
    if (operation == L"dump-pe" && location->Space == L"virtual" && length.empty())
    {
        return operation + L" " + Hex(location->Address) + L" \"" + path + L"\"";
    }
    uint64_t bytes = 0;
    if (operation == L"dump-raw" && ParseUnsigned(length, 10, &bytes) && bytes <= 0x4000000 && ValidRange(location->Address, bytes))
    {
        return operation + L" " + Hex(location->Address) + L" " + Hex(bytes) + L" \"" + path + L"\"" +
               (location->Space == L"physical" ? L" /phys" : L"");
    }
    return std::nullopt;
}

inline knjson::Value MemoryByteRows(uint64_t address, AddressSpace space, std::span<const unsigned char> bytes,
                                   std::span<const unsigned char> valid)
{
    auto rows = knjson::Value::MakeArray();
    if (bytes.size() != valid.size() || bytes.size() > 65536 || !ValidRange(address, bytes.size()))
    {
        return rows;
    }
    for (size_t offset = 0; offset < bytes.size(); offset += 16)
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"MemoryBytes"));
        row.Set(L"address", knjson::Value(Hex(address + offset)));
        row.Set(L"addressSpace", knjson::Value(space == AddressSpace::Physical ? L"physical" : L"virtual"));
        auto values = knjson::Value::MakeArray();
        for (size_t index = offset; index < bytes.size() && index < offset + 16; ++index)
        {
            values.Push(valid[index] ? knjson::Value(static_cast<double>(bytes[index])) : knjson::Value());
        }
        row.Set(L"bytes", values);
        rows.Push(row);
    }
    return rows;
}

inline knjson::Value MemoryPointerRows(uint64_t address, unsigned width, std::span<const unsigned char> bytes,
                                      std::span<const unsigned char> valid)
{
    auto rows = knjson::Value::MakeArray();
    if ((width != 4 && width != 8) || bytes.size() != valid.size() || bytes.size() > 65536 || !ValidRange(address, bytes.size()))
    {
        return rows;
    }
    for (size_t offset = 0; offset < bytes.size(); offset += width)
    {
        bool readable = bytes.size() - offset >= width;
        uint64_t pointer = 0;
        for (size_t index = 0; readable && index < width; ++index)
        {
            readable = valid[offset + index] != 0;
            pointer |= static_cast<uint64_t>(bytes[offset + index]) << (index * 8);
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"MemoryPointer"));
        row.Set(L"address", knjson::Value(Hex(address + offset)));
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"pointer", readable ? knjson::Value(Hex(pointer)) : knjson::Value());
        row.Set(L"readable", knjson::Value(readable));
        row.Set(L"width", knjson::Value(std::to_wstring(width)));
        rows.Push(row);
    }
    return rows;
}
} // namespace kncore
