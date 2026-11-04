#pragma once

#include "../core/Result.h"
#include "ThreadContext.h"
#include <dbgeng.h>
#include <wrl/client.h>
#include <algorithm>

namespace knengine
{
inline HRESULT ReadLastEvent(IDebugControl4 *control, knjson::Value &row)
{
    ULONG type = 0, process = DEBUG_ANY_ID, thread = DEBUG_ANY_ID, used = 0;
    union
    {
        DEBUG_LAST_EVENT_INFO_EXCEPTION Exception;
        DEBUG_LAST_EVENT_INFO_BREAKPOINT Breakpoint;
    } extra = {};
    wchar_t description[4096] = {};
    const HRESULT hr = control->GetLastEventInformationWide(&type, &process, &thread, &extra, sizeof(extra), &used,
                                                           description, _countof(description), nullptr);
    row = knjson::Value();
    if (FAILED(hr))
    {
        return hr;
    }
    row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"LastEvent"));
    row.Set(L"type", knjson::Value(kncore::Hex(type)));
    row.Set(L"engineProcessId", process == DEBUG_ANY_ID ? knjson::Value() : knjson::Value(std::to_wstring(process)));
    row.Set(L"engineThreadId", thread == DEBUG_ANY_ID ? knjson::Value() : knjson::Value(std::to_wstring(thread)));
    row.Set(L"description", knjson::Value(description));
    if (type == DEBUG_EVENT_BREAKPOINT && used == sizeof(extra.Breakpoint))
    {
        row.Set(L"breakpointId", extra.Breakpoint.Id == DEBUG_ANY_ID ? knjson::Value() :
                               knjson::Value(std::to_wstring(extra.Breakpoint.Id)));
        row.Set(L"id", row.Get(L"breakpointId"));
        row.Set(L"eventName", knjson::Value(L"Breakpoint hit"));
        row.Set(L"historical", knjson::Value(true));
        // Captured event code offsets can lag a remote KD breakpoint. Do not
        // present that cache or the user's current register context as hit IP.
        row.Set(L"address", knjson::Value());
        row.Set(L"addressStatus", knjson::Value(L"Event IP unverified; current breakpoint settings are shown separately"));
        row.Set(L"configuredAddress", knjson::Value());
        Microsoft::WRL::ComPtr<IDebugBreakpoint2> breakpoint;
        DEBUG_BREAKPOINT_PARAMETERS parameters = {};
        if (extra.Breakpoint.Id != DEBUG_ANY_ID &&
            control->GetBreakpointById2(extra.Breakpoint.Id, &breakpoint) == S_OK && breakpoint != nullptr &&
            breakpoint->GetParameters(&parameters) == S_OK && parameters.Id == extra.Breakpoint.Id &&
            (parameters.Flags & DEBUG_BREAKPOINT_DEFERRED) == 0 && parameters.Offset != DEBUG_INVALID_OFFSET)
        {
            row.Set(L"configuredAddress", knjson::Value(kncore::Hex(parameters.Offset)));
        }
    }
    else if (type == DEBUG_EVENT_EXCEPTION && used == sizeof(extra.Exception))
    {
        row.Set(L"code", knjson::Value(kncore::Hex(extra.Exception.ExceptionRecord.ExceptionCode)));
        row.Set(L"address", knjson::Value(kncore::Hex(extra.Exception.ExceptionRecord.ExceptionAddress)));
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"firstChance", knjson::Value(extra.Exception.FirstChance != 0));
        auto parameters = knjson::Value::MakeArray();
        for (ULONG i = 0; i < (std::min<ULONG>)(extra.Exception.ExceptionRecord.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS); ++i)
        {
            parameters.Push(knjson::Value(kncore::Hex(extra.Exception.ExceptionRecord.ExceptionInformation[i])));
        }
        row.Set(L"parameters", parameters);
    }
    return hr;
}

inline knjson::Value ReadEventContext(DbgSession &session, const knjson::Value &event)
{
    auto result = knjson::Value::MakeObject();
    result.Set(L"reason", knjson::Value(L"Event process or thread unavailable"));
    uint64_t process = 0, thread = 0, type = 0;
    SessionStatus status = {};
    session.QueryStatus(&status);
    auto *system = session.SystemObjects();
    ULONG eventSystem = DEBUG_ANY_ID, currentSystem = DEBUG_ANY_ID;
    if (!status.Stopped || system == nullptr ||
        !kncore::ParseUnsigned(event.Get(L"type").AsString(L""), 16, &type) || type == 0 ||
        !kncore::ParseUnsigned(event.Get(L"engineProcessId").AsString(L""), 10, &process) || process >= DEBUG_ANY_ID ||
        !kncore::ParseUnsigned(event.Get(L"engineThreadId").AsString(L""), 10, &thread) || thread >= DEBUG_ANY_ID ||
        system->GetEventSystem(&eventSystem) != S_OK || system->GetCurrentSystemId(&currentSystem) != S_OK ||
        eventSystem != currentSystem)
    {
        return result;
    }
    SymbolQueryScope query;
    if (status.KernelMode)
    {
        ULONG count = 0;
        if (status.Architecture != IMAGE_FILE_MACHINE_AMD64 ||
            session.Control()->GetNumberProcessors(&count) != S_OK || count > 4096)
        {
            return result;
        }
        for (ULONG processor = 0; processor < count && !session.Cancelled(); ++processor)
        {
            ULONG engineThread = DEBUG_ANY_ID;
            if (system->GetThreadIdByProcessor(processor, &engineThread) != S_OK || engineThread != thread)
            {
                continue;
            }
            result.Set(L"processor", knjson::Value(std::to_wstring(processor)));
            result.Set(L"source", knjson::Value(L"StoppedEventProcessor"));
            Microsoft::WRL::ComPtr<IDebugDataSpaces4> spaces;
            ULONG64 kthread = 0;
            ULONG used = 0;
            if (FAILED(session.Client()->QueryInterface(IID_PPV_ARGS(&spaces))) ||
                spaces->ReadProcessorSystemData(processor, DEBUG_DATA_KTHREAD_OFFSET, &kthread, sizeof(kthread), &used) != S_OK ||
                used != sizeof(kthread))
            {
                break;
            }
            const auto identity = ReadKernelThreadIdentity(session, kthread);
            for (const auto &[name, value] : identity.Fields())
            {
                result.Set(name, value);
            }
            break;
        }
    }
    else
    {
        result.Set(L"source", knjson::Value(L"EventSystemIds"));
        ULONG count = 0;
        if (system->GetNumberProcesses(&count) == S_OK && count <= 4096)
        {
            std::vector<ULONG> ids(count), systemIds(count);
            if (count != 0 && system->GetProcessIdsByIndex(0, count, ids.data(), systemIds.data()) == S_OK)
            {
                for (ULONG i = 0; i < count; ++i)
                {
                    if (ids[i] == process)
                    {
                        result.Set(L"pid", knjson::Value(std::to_wstring(systemIds[i])));
                    }
                }
            }
        }
        ULONG currentProcess = DEBUG_ANY_ID;
        if (system->GetCurrentProcessId(&currentProcess) == S_OK && currentProcess == process)
        {
            wchar_t image[4096] = {};
            if (system->GetCurrentProcessExecutableNameWide(image, _countof(image), nullptr) == S_OK)
            {
                result.Set(L"image", knjson::Value(image));
            }
            if (system->GetNumberThreads(&count) == S_OK && count <= 65536)
            {
                std::vector<ULONG> ids(count), systemIds(count);
                if (count != 0 && system->GetThreadIdsByIndex(0, count, ids.data(), systemIds.data()) == S_OK)
                {
                    for (ULONG i = 0; i < count; ++i)
                    {
                        if (ids[i] == thread)
                        {
                            result.Set(L"tid", knjson::Value(std::to_wstring(systemIds[i])));
                        }
                    }
                }
            }
        }
        if (!result.Get(L"pid").IsNull() && !result.Get(L"tid").IsNull())
        {
            result.Set(L"reason", knjson::Value(L""));
        }
    }
    return result;
}
} // namespace knengine
