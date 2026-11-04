#pragma once

#include "../util/Json.h"
#include "../core/Result.h"
#include <dbgeng.h>
#include <wrl/client.h>

namespace kncmd
{
using Microsoft::WRL::ComPtr;
inline std::wstring BreakpointIdentity(IDebugBreakpoint2 *breakpoint)
{
    // DbgEng owns breakpoint lifetimes; RemoveBreakpoint invalidates every pointer.
    DEBUG_BREAKPOINT_PARAMETERS parameters = {};
    ComPtr<IDebugBreakpoint3> unique;
    GUID guid = {};
    wchar_t text[64] = {};
    wchar_t command[4096] = {};
    wchar_t expression[4096] = {};
    if (breakpoint->GetParameters(&parameters) != S_OK || FAILED(breakpoint->QueryInterface(IID_PPV_ARGS(&unique))) ||
        unique->GetGuid(&guid) != S_OK || StringFromGUID2(guid, text, _countof(text)) == 0 ||
        breakpoint->GetCommandWide(command, _countof(command), nullptr) != S_OK ||
        breakpoint->GetOffsetExpressionWide(expression, _countof(expression), nullptr) != S_OK)
    {
        return L"";
    }
    auto row = knjson::Value::MakeObject();
    row.Set(L"guid", knjson::Value(text));
    row.Set(L"offset", knjson::Value(kncore::Hex(parameters.Offset)));
    row.Set(L"flags", knjson::Value(kncore::Hex(parameters.Flags)));
    row.Set(L"type", knjson::Value(std::to_wstring(parameters.BreakType)));
    row.Set(L"processorType", knjson::Value(std::to_wstring(parameters.ProcType)));
    row.Set(L"dataSize", knjson::Value(std::to_wstring(parameters.DataSize)));
    row.Set(L"dataAccess", knjson::Value(std::to_wstring(parameters.DataAccessType)));
    row.Set(L"thread", knjson::Value(std::to_wstring(parameters.MatchThread)));
    row.Set(L"passCount", knjson::Value(std::to_wstring(parameters.PassCount)));
    row.Set(L"command", knjson::Value(command));
    row.Set(L"expression", knjson::Value(expression));
    return row.Write();
}

} // namespace kncmd
