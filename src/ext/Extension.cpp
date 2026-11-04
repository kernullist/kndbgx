#include <windows.h>
#include <dbgeng.h>
#include <string>
#include <wrl/client.h>

#include "../engine/EngineCore.h"
#include "../cmd/Dispatcher.h"
#include "../cmd/Jobs.h"
#include "../cmd/WriteGate.h"
#include "../ui/UiApp.h"
#include "../util/Text.h"

namespace
{
void Print(IDebugClient *client, const std::wstring &text)
{
    Microsoft::WRL::ComPtr<IDebugControl4> control;
    if (client != nullptr && SUCCEEDED(client->QueryInterface(IID_PPV_ARGS(&control))))
    {
        for (size_t offset = 0; offset < text.size();)
        {
            const auto count = knutil::Utf16PrefixUnits(std::wstring_view(text).substr(offset), 2048);
            if (count == 0)
            {
                break;
            }
            const auto chunk = text.substr(offset, count);
            control->OutputWide(DEBUG_OUTPUT_NORMAL, L"%s", chunk.c_str());
            offset += count;
        }
        control->OutputWide(DEBUG_OUTPUT_NORMAL, L"\n");
    }
}

HRESULT SubmitCliJob(IDebugClient *client, const std::wstring &command)
{
    std::optional<kncore::SessionStamp> stamp;
    {
        kncore::ExecutionLease lease(knengine::Coordinator());
        if (lease)
        {
            knengine::DbgSession session;
            if (session.Initialize(client, false))
            {
                stamp = session.RefreshStamp();
            }
        }
    }
    if (!stamp)
    {
        Print(client, L"EngineBusyOrUnavailable: retry after the active request finishes");
        return E_FAIL;
    }
    const auto submitted = kncmd::SubmitJob(command, true, &*stamp);
    HRESULT status = E_FAIL;
    if (submitted.State == kncore::Status::Success)
    {
        const auto id = submitted.Rows.Items()[0].Get(L"jobId").AsString(L"");
        Print(client, L"[job] " + id);
        kncmd::ActivateJob(id);
        status = S_OK;
    }
    else
    {
        Print(client, submitted.Error.Message);
    }
    return status;
}

HRESULT Run(IDebugClient *client, const std::wstring &line)
{
    HRESULT status = S_OK;
    do
    {
        if (line.empty())
        {
            knui::ShowWindowAsyncSafe();
            break;
        }
        if (_wcsicmp(line.c_str(), L"cancel") == 0)
        {
            Print(client, knengine::RequestCancellation() ? L"CancelRequested" : L"Idle");
            break;
        }
        if (_wcsicmp(line.c_str(), L"shutdown") == 0)
        {
            knui::ShutdownAsyncSafe();
            Print(client, L"Closing requested");
            break;
        }
        kncmd::ParsedCommand parsed;
        const bool parsedOk = kncmd::ParseCommand(line, &parsed);
        if (parsedOk && parsed.Spec != nullptr && std::wstring(parsed.Spec->Name) == L"submit")
        {
            status = SubmitCliJob(client, parsed.RawArguments);
            break;
        }
        if (kncmd::DetachedCommand(parsed.Spec))
        {
            knengine::DbgSession detached;
            const auto result = kncmd::DispatchCommand(detached, line);
            Print(client, result.Output.empty() ? result.Error : result.Output);
            status = result.Ok ? S_OK : E_FAIL;
            break;
        }
        if (parsed.Spec != nullptr &&
            (std::wstring(parsed.Spec->Name) == L"raw" ||
             (std::wstring(parsed.Spec->Group) == L"Kernel" && kncmd::HasEffect(parsed.Spec->Effects, kncmd::Effect::TargetRead) &&
              !kncmd::HasEffect(parsed.Spec->Effects, kncmd::Effect::SessionContextChange))))
        {
            status = SubmitCliJob(client, line);
            break;
        }
        kncore::ExecutionLease lease(knengine::Coordinator());
        if (!lease)
        {
            Print(client, L"EngineBusy: retry after the active request finishes");
            status = HRESULT_FROM_WIN32(ERROR_BUSY);
            break;
        }
        knengine::DbgSession session;
        session.Initialize(client, false);
        const auto result = kncmd::DispatchCommand(session, line);
        if (!result.ResultId.empty())
        {
            Print(client, L"[result] " + result.ResultId);
        }
        if (!result.Ok)
        {
            // The dispatcher echoes the output text to the host only when the
            // session is ready; suppress the duplicate print solely in that case.
            const std::wstring message = result.Error.empty() ? kncore::StatusName(result.Data.State) : result.Error;
            if (!session.IsReady() || result.Output.find(message) == std::wstring::npos)
            {
                Print(client, message);
            }
            status = E_FAIL;
        }
    } while (false);
    return status;
}
} // namespace

extern "C" __declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags)
{
    if (version == nullptr || flags == nullptr)
    {
        return E_POINTER;
    }
    kncmd::InitializeJobs();
    knengine::StartSessionObserver();
    kncmd::DiscardChangePlans();
    *version = DEBUG_EXTENSION_VERSION(0, 2);
    *flags = 0;
    return S_OK;
}

extern "C" __declspec(dllexport) void CALLBACK DebugExtensionUninitialize()
{
    kncmd::StopJobs();
    knengine::StopSessionObserver();
    knui::ShutdownAsyncSafe();
}

extern "C" __declspec(dllexport) HRESULT CALLBACK kndbgx(PDEBUG_CLIENT client, PCSTR arguments)
{
    HRESULT status = E_FAIL;
    try
    {
        status = Run(client, knutil::Trim(knutil::Utf8ToWide(arguments != nullptr ? arguments : "")));
    }
    catch (const std::exception &)
    {
        Print(client, L"InternalFault: extension request failed");
    }
    catch (...)
    {
        Print(client, L"InternalFault: unknown exception");
    }
    return status;
}

extern "C" __declspec(dllexport) void CALLBACK DebugExtensionNotify(ULONG notify, ULONG64)
{
    if (notify == DEBUG_NOTIFY_SESSION_ACTIVE || notify == DEBUG_NOTIFY_SESSION_INACTIVE)
    {
        knengine::Epochs().TargetChanged();
    }
    else if (knengine::Epochs().WalksInFlight() == 0)
    {
        // Engine notifications also arrive for transient operations inside
        // guarded walks (thread switches during per-processor collection);
        // those belong to the walk and must not invalidate its restore.
        knengine::Epochs().ExecutionChanged();
    }
}
