#pragma once

#include "Result.h"
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <objbase.h>
#include <algorithm>

namespace kncore
{
inline std::wstring GuidText(const GUID &guid)
{
    wchar_t text[40] = {};
    StringFromGUID2(guid, text, _countof(text));
    return text;
}

inline knjson::Value EtwHeaderRow(PEVENT_RECORD event)
{
    const auto &header = event->EventHeader;
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"EtwEvent"));
    row.Set(L"provider", knjson::Value(GuidText(header.ProviderId)));
    row.Set(L"activityId", knjson::Value(GuidText(header.ActivityId)));
    row.Set(L"eventId", knjson::Value(std::to_wstring(header.EventDescriptor.Id)));
    row.Set(L"version", knjson::Value(std::to_wstring(header.EventDescriptor.Version)));
    row.Set(L"opcode", knjson::Value(std::to_wstring(header.EventDescriptor.Opcode)));
    row.Set(L"task", knjson::Value(std::to_wstring(header.EventDescriptor.Task)));
    row.Set(L"level", knjson::Value(std::to_wstring(header.EventDescriptor.Level)));
    row.Set(L"keyword", knjson::Value(kncore::Hex(header.EventDescriptor.Keyword)));
    row.Set(L"flags", knjson::Value(kncore::Hex(header.Flags)));
    row.Set(L"pid", knjson::Value(std::to_wstring(header.ProcessId)));
    row.Set(L"tid", knjson::Value(std::to_wstring(header.ThreadId)));
    row.Set(L"timestampFileTime", knjson::Value(std::to_wstring(header.TimeStamp.QuadPart)));
    row.Set(L"processor", knjson::Value(std::to_wstring(GetEventProcessorIndex(event))));
    row.Set(L"payloadBytes", knjson::Value(std::to_wstring(event->UserDataLength)));
    std::wstring payload;
    const size_t preview = std::min<size_t>(event->UserDataLength, 256);
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    if (event->UserData != nullptr)
    {
        const auto *bytes = static_cast<const unsigned char *>(event->UserData);
        for (size_t i = 0; i < preview; ++i)
        {
            payload.push_back(digits[bytes[i] >> 4]);
            payload.push_back(digits[bytes[i] & 15]);
        }
    }
    row.Set(L"payloadPreviewHex", knjson::Value(payload));
    row.Set(L"payloadPreviewTruncated", knjson::Value(preview < event->UserDataLength));
    return row;
}
} // namespace kncore
