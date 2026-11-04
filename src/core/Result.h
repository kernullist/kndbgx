#pragma once

#include "Input.h"
#include "../util/Json.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <optional>
#include <string>

namespace kncore
{
enum class Status
{
    Success,
    Partial,
    Unavailable,
    Unsupported,
    InvalidInput,
    Cancelled,
    StaleContext,
    EngineError,
    IOError,
    InternalFault
};

inline const wchar_t *StatusName(Status status)
{
    switch (status)
    {
    case Status::Success:
        return L"Success";
    case Status::Partial:
        return L"Partial";
    case Status::Unavailable:
        return L"Unavailable";
    case Status::Unsupported:
        return L"Unsupported";
    case Status::InvalidInput:
        return L"InvalidInput";
    case Status::Cancelled:
        return L"Cancelled";
    case Status::StaleContext:
        return L"StaleContext";
    case Status::EngineError:
        return L"EngineError";
    case Status::IOError:
        return L"IOError";
    case Status::InternalFault:
        return L"InternalFault";
    }
    return L"InternalFault";
}

inline std::wstring Hex(uint64_t value)
{
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring result(18, L'0');
    result[1] = L'x';
    for (size_t i = 0; i < 16; ++i)
    {
        result[17 - i] = digits[value & 15];
        value >>= 4;
    }
    return result;
}

// Binary-prefixed size for console summaries; keeps three significant
// digits and falls back to plain bytes below a KiB.
inline std::wstring HumanBytes(uint64_t value)
{
    static const wchar_t *units[] = {L"B", L"KiB", L"MiB", L"GiB", L"TiB"};
    if (value < 1024)
    {
        return std::to_wstring(value) + L" B";
    }
    double size = static_cast<double>(value);
    size_t unit = 0;
    while (size >= 1024.0 && unit + 1 < 5)
    {
        size /= 1024.0;
        ++unit;
    }
    wchar_t text[32] = {};
    swprintf_s(text, L"%.2f %s", size, units[unit]);
    return text;
}

struct NativeError
{
    std::wstring Domain;
    uint64_t Code = 0;
    std::wstring Operation;
    std::wstring Message;

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"domain", knjson::Value(Domain));
        value.Set(L"code", knjson::Value(Hex(Code)));
        value.Set(L"operation", knjson::Value(Operation));
        value.Set(L"message", knjson::Value(Message));
        return value;
    }
};

struct ContextIdentity
{
    std::optional<uint64_t> System;
    std::optional<uint64_t> Process;
    std::optional<uint64_t> Thread;
    std::optional<uint64_t> ImplicitProcess;
    std::optional<uint64_t> ImplicitThread;
    std::optional<uint64_t> EffectiveArchitecture;
    std::optional<uint64_t> ScopeInstruction;
    std::optional<uint64_t> ScopeStack;
    std::optional<uint64_t> ScopeFrame;
    std::optional<uint64_t> ScopeIndex;
    bool operator==(const ContextIdentity &) const = default;
    bool Complete() const
    {
        return System && Process && Thread && ImplicitProcess && ImplicitThread && EffectiveArchitecture && ScopeInstruction &&
               ScopeStack && ScopeFrame && ScopeIndex;
    }
    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        const auto put = [&](const wchar_t *name, const std::optional<uint64_t> &field)
        {
            value.Set(name, field ? knjson::Value(Hex(*field)) : knjson::Value());
        };
        put(L"system", System);
        put(L"process", Process);
        put(L"thread", Thread);
        put(L"implicitProcess", ImplicitProcess);
        put(L"implicitThread", ImplicitThread);
        put(L"effectiveArchitecture", EffectiveArchitecture);
        put(L"scopeInstruction", ScopeInstruction);
        put(L"scopeStack", ScopeStack);
        put(L"scopeFrame", ScopeFrame);
        put(L"scopeIndex", ScopeIndex);
        return value;
    }
};

struct SessionStamp
{
    std::wstring SessionId;
    uint64_t TargetGeneration = 0;
    uint64_t StopEpoch = 0;
    uint64_t ContextGeneration = 0;
    uint64_t SymbolGeneration = 0;
    ContextIdentity Context;
    bool operator==(const SessionStamp &) const = default;

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"sessionId", knjson::Value(SessionId));
        value.Set(L"targetGeneration", knjson::Value(std::to_wstring(TargetGeneration)));
        value.Set(L"stopEpoch", knjson::Value(std::to_wstring(StopEpoch)));
        value.Set(L"contextGeneration", knjson::Value(std::to_wstring(ContextGeneration)));
        value.Set(L"symbolGeneration", knjson::Value(std::to_wstring(SymbolGeneration)));
        value.Set(L"contextIdentity", Context.ToJson());
        return value;
    }
};

struct Coverage
{
    uint64_t Expected = 0;
    uint64_t Visited = 0;
    uint64_t Read = 0;
    uint64_t Decoded = 0;
    uint64_t Classified = 0;
    uint64_t Unknown = 0;
    uint64_t Unreadable = 0;
    bool Complete = false;
    std::wstring StopReason = L"NotCollected";

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"expectedEntries", knjson::Value(std::to_wstring(Expected)));
        value.Set(L"visitedEntries", knjson::Value(std::to_wstring(Visited)));
        value.Set(L"readEntries", knjson::Value(std::to_wstring(Read)));
        value.Set(L"decodedEntries", knjson::Value(std::to_wstring(Decoded)));
        value.Set(L"classifiedEntries", knjson::Value(std::to_wstring(Classified)));
        value.Set(L"unknownEntries", knjson::Value(std::to_wstring(Unknown)));
        value.Set(L"unreadableEntries", knjson::Value(std::to_wstring(Unreadable)));
        value.Set(L"complete", knjson::Value(Complete));
        value.Set(L"stopReason", knjson::Value(StopReason));
        return value;
    }
};

struct Result
{
    Status State = Status::Success;
    std::wstring RequestId;
    std::wstring CommandId;
    SessionStamp Stamp;
    Coverage Collected;
    NativeError Error;
    std::wstring Source = L"unknown";
    std::wstring Consistency = L"unknown";
    std::wstring LayoutProfile;
    knjson::Value Rows = knjson::Value::MakeArray();
    knjson::Value Findings = knjson::Value::MakeArray();
    knjson::Value Limitations = knjson::Value::MakeArray();
    knjson::Value Analysis;

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"schema", knjson::Value(L"kndbgx.result.v2"));
        value.Set(L"requestId", knjson::Value(RequestId));
        value.Set(L"commandId", knjson::Value(CommandId));
        value.Set(L"status", knjson::Value(StatusName(State)));
        value.Set(L"target", Stamp.ToJson());
        value.Set(L"coverage", Collected.ToJson());
        value.Set(L"error", Error.ToJson());
        value.Set(L"rows", Rows);
        value.Set(L"findings", Findings);
        value.Set(L"limitations", Limitations);
        if (!Analysis.IsNull())
        {
            value.Set(L"analysis", Analysis);
        }
        auto provenance = knjson::Value::MakeObject();
        provenance.Set(L"source", knjson::Value(Source));
        provenance.Set(L"consistency", knjson::Value(Consistency));
        provenance.Set(L"layoutProfile", knjson::Value(LayoutProfile));
        value.Set(L"provenance", provenance);
        return value;
    }
};

enum class AddressSpace
{
    Virtual,
    Physical
};

struct TransferResult
{
    Status State = Status::Unavailable;
    size_t Requested = 0;
    size_t Transferred = 0;
    NativeError Error;
};

inline TransferResult TransferStatus(size_t requested, size_t transferred, int32_t nativeStatus)
{
    TransferResult result;
    result.Requested = requested;
    result.Transferred = transferred;
    result.Error.Domain = L"HRESULT";
    result.Error.Code = static_cast<uint32_t>(nativeStatus);
    if (transferred > requested)
    {
        result.State = Status::InternalFault;
        result.Transferred = 0;
    }
    else if (nativeStatus >= 0 && transferred == requested)
    {
        result.State = Status::Success;
    }
    else
    {
        result.State = transferred > 0 ? Status::Partial : Status::Unavailable;
    }
    return result;
}

template <typename Primary, typename Legacy> TransferResult PhysicalTransfer(size_t requested, Primary primary, Legacy legacy)
{
    size_t transferred = 0;
    int32_t status = primary(&transferred);
    if (transferred == 0 && (status == static_cast<int32_t>(0x80004001U) || status == static_cast<int32_t>(0x80004002U)))
    {
        status = legacy(&transferred);
    }
    return TransferStatus(requested, transferred, status);
}

struct ReadResult : TransferResult
{
    AddressSpace Space = AddressSpace::Virtual;
    uint64_t Address = 0;
    std::vector<unsigned char> Bytes;
    std::vector<unsigned char> Valid;
};

class TargetReader
{
  public:
    virtual ~TargetReader() = default;
    virtual ReadResult Read(AddressSpace space, uint64_t address, size_t length) = 0;

    template <typename T> bool ReadExact(AddressSpace space, uint64_t address, T *out)
    {
        const auto result = Read(space, address, sizeof(T));
        bool valid = out != nullptr && result.State == Status::Success && result.Transferred == sizeof(T) &&
                     result.Bytes.size() == sizeof(T) && result.Valid.size() == sizeof(T);
        for (const auto byte : result.Valid)
        {
            valid = valid && byte != 0;
        }
        if (valid)
        {
            std::memcpy(out, result.Bytes.data(), sizeof(T));
        }
        return valid;
    }
};
} // namespace kncore
