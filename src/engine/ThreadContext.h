#pragma once

#include "../core/EventContext.h"
#include "LayoutResolver.h"
#include "SymbolQuery.h"
#include <dbgeng.h>

namespace knengine
{
inline knjson::Value ReadKernelThreadIdentity(DbgSession &session, ULONG64 kthread)
{
    SymbolQueryScope query;
    LayoutResolver layout(session);
    kncore::EventThreadLayout fields;
    fields.Tcb = layout.Field(L"nt", L"_ETHREAD", L"Tcb");
    const auto cid = layout.Field(L"nt", L"_ETHREAD", L"Cid");
    fields.Tid = kncore::NestedField(cid, layout.Field(L"nt", L"_CLIENT_ID", L"UniqueThread"));
    fields.OwnerPid = kncore::NestedField(cid, layout.Field(L"nt", L"_CLIENT_ID", L"UniqueProcess"));
    fields.Process = kncore::NestedField(fields.Tcb, layout.Field(L"nt", L"_KTHREAD", L"Process"));
    fields.Pcb = layout.Field(L"nt", L"_EPROCESS", L"Pcb");
    fields.Owner.Pid = layout.Field(L"nt", L"_EPROCESS", L"UniqueProcessId");
    fields.Owner.Image = layout.Field(L"nt", L"_EPROCESS", L"ImageFileName");
    // Kernel object reads are independent of the selected user address space.
    ULONG64 cr4 = 0;
    const bool la57 = session.ReadRegisterHex(L"cr4", &cr4) && (cr4 & (1ull << 12)) != 0;
    const kncore::TargetArchitecture architecture{IMAGE_FILE_MACHINE_AMD64, 8, la57 ? 57u : 48u, {}};
    return kncore::ReadEventThread(session, kthread, architecture, fields);
}

inline knjson::Value ReadSelectedThreadContext(DbgSession &session, const SessionStatus &status)
{
    auto result = knjson::Value::MakeObject();
    for (const auto *field : {L"pid", L"tid", L"image"})
    {
        result.Set(field, knjson::Value());
    }
    result.Set(L"reason", knjson::Value(L"Selected thread or owning process unavailable"));
    auto *system = session.SystemObjects();
    if (!status.Stopped || system == nullptr)
    {
        return result;
    }
    if (status.KernelMode)
    {
        ULONG64 kthread = 0;
        if (status.Architecture == IMAGE_FILE_MACHINE_AMD64 && system->GetImplicitThreadDataOffset(&kthread) == S_OK)
        {
            result = ReadKernelThreadIdentity(session, kthread);
        }
        result.Set(L"source", knjson::Value(L"SelectedImplicitThread"));
    }
    else
    {
        result.Set(L"source", knjson::Value(L"CurrentSystemIds"));
        ULONG id = 0;
        if (system->GetCurrentProcessSystemId(&id) == S_OK && id != DEBUG_ANY_ID)
        {
            result.Set(L"pid", knjson::Value(std::to_wstring(id)));
        }
        if (system->GetCurrentThreadSystemId(&id) == S_OK && id != DEBUG_ANY_ID)
        {
            result.Set(L"tid", knjson::Value(std::to_wstring(id)));
        }
        wchar_t image[4096] = {};
        if (system->GetCurrentProcessExecutableNameWide(image, _countof(image), nullptr) == S_OK)
        {
            const std::wstring path(image);
            const auto separator = path.find_last_of(L"\\/");
            const auto name = separator == std::wstring::npos ? path : path.substr(separator + 1);
            if (!name.empty())
            {
                result.Set(L"image", knjson::Value(name));
            }
        }
        if (!result.Get(L"pid").IsNull() && !result.Get(L"tid").IsNull() && !result.Get(L"image").IsNull())
        {
            result.Set(L"reason", knjson::Value(L""));
        }
    }
    return result;
}
} // namespace knengine
