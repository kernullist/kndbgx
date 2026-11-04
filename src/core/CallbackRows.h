#pragma once

#include "ScannerRules.h"
#include "ResultPresentation.h"

namespace kncore
{
inline knjson::Value ObjectCallbackRegistration(Result &report, const TargetArchitecture &architecture, const OwnershipIndex &owners,
                                                 const std::wstring &objectType, uint64_t entry, std::optional<uint64_t> preRoutine,
                                                 std::optional<uint64_t> postRoutine, std::optional<uint64_t> operations)
{
    auto row = knjson::Value::MakeObject();
    const auto family = L"Object." + objectType;
    row.Set(L"kind", knjson::Value(L"ObjectCallbackRegistration"));
    row.Set(L"callbackType", knjson::Value(family));
    row.Set(L"family", knjson::Value(family));
    row.Set(L"objectType", knjson::Value(objectType));
    row.Set(L"slot", knjson::Value(Hex(entry)));
    row.Set(L"preRoutine", OptionalNumber(preRoutine, true));
    row.Set(L"postRoutine", OptionalNumber(postRoutine, true));
    row.Set(L"operations", OptionalNumber(operations, true));
    row.Set(L"flags", OptionalNumber(operations, true));
    row.Set(L"flagsMeaning", knjson::Value(L"OB_OPERATION mask: 0x1=HandleCreate, 0x2=HandleDuplicate"));
    row.Set(L"operationMaskKnown", knjson::Value(operations && *operations != 0 && (*operations & ~uint64_t(3)) == 0));
    auto pre = RoutineObservation(report, architecture, owners, objectType + L".PreOperation", entry, preRoutine, RoutinePresence::Optional);
    auto post = RoutineObservation(report, architecture, owners, objectType + L".PostOperation", entry, postRoutine, RoutinePresence::Optional);
    row.Set(L"pre", pre);
    row.Set(L"post", post);
    if (pre.Get(L"module").IsString())
    {
        row.Set(L"preModule", pre.Get(L"module"));
    }
    if (post.Get(L"module").IsString())
    {
        row.Set(L"postModule", post.Get(L"module"));
    }
    if (preRoutine == 0 && postRoutine == 0)
    {
        ++report.Collected.Unknown;
    }
    if (!operations || *operations == 0 || (*operations & ~uint64_t(3)) != 0)
    {
        ++report.Collected.Unknown;
    }
    return row;
}

inline void SeparateCallbackDiagnostics(Result &report)
{
    SeparateResultDiagnostics(report);
}
} // namespace kncore
