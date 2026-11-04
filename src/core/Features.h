#pragma once
#include "../util/Json.h"

namespace kncore
{
inline knjson::Value FeatureStatus()
{
    auto rows = knjson::Value::MakeArray();
    for (const auto *name : {L"external-ui-process", L"ttd-replay", L"experimental-replay-sdk", L"kernel-ttd"})
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"feature", knjson::Value(name));
        row.Set(L"enabled", knjson::Value(false));
        row.Set(L"status", knjson::Value(L"Unavailable"));
        row.Set(L"reason", knjson::Value(std::wstring(name) == L"external-ui-process"
                                             ? L"Optional adapter excluded; embedded WebView2 transport is the implemented path"
                                             : L"Trace identity/position adapter and fixture gate are not enabled in this release"));
        rows.Push(row);
    }
    return rows;
}
} // namespace kncore
