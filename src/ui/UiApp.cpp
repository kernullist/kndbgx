#include "UiApp.h"

#include "Bridge.h"
#include "../core/Rpc.h"
#include "../core/UiLifecycle.h"
#include "../core/UiOperations.h"
#include "../core/ResultStore.h"
#include "../core/DebugAction.h"
#include "../cmd/WriteGate.h"
#include "../cmd/MutationService.h"

#include <windows.h>
#include <objbase.h>
#include <WebView2.h>
#include <wrl/client.h>
#ifdef _DEBUG
#include <wrl/event.h>
#include <cstdio>
#endif

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <cwctype>
#include <iterator>
#include <mutex>
#include <map>
#include <deque>
#include <new>
#include <objbase.h>
#include <string>
#include <thread>
#include <vector>

#include "../engine/EngineCore.h"
#include "../res/resource.h"
#include "../util/Json.h"
#include "../util/Text.h"
#include "../util/Token.h"

using Microsoft::WRL::ComPtr;

namespace knui
{
namespace
{
constexpr UINT WM_APP_SHOW = WM_APP + 1;
constexpr UINT WM_APP_SHUTDOWN = WM_APP + 2;
constexpr UINT WM_APP_BRIDGE_REPLY = WM_APP + 3;
constexpr UINT WM_APP_UI_FAILED = WM_APP + 4;
constexpr UINT WM_APP_DRAIN_UI = WM_APP + 5;
constexpr UINT WM_APP_CLOSE_INSPECTION = WM_APP + 6;
constexpr UINT_PTR kBootWatchdog = 1;
#ifdef _DEBUG
constexpr UINT WM_APP_TEST_REINIT = WM_APP + 100;
constexpr UINT WM_APP_TEST_PROCESS = WM_APP + 101;
constexpr UINT WM_APP_TEST_READ = WM_APP + 102;
constexpr UINT WM_APP_TEST_BOUND = WM_APP + 103;
constexpr UINT WM_APP_TEST_DELIVERY = WM_APP + 104;
constexpr UINT WM_APP_TEST_RESOURCE = WM_APP + 105;
constexpr UINT WM_APP_TEST_CONSOLE = WM_APP + 106;
constexpr UINT WM_APP_TEST_EXECUTION = WM_APP + 107;
constexpr UINT WM_APP_TEST_WORKSPACE = WM_APP + 108;
constexpr UINT WM_APP_TEST_VISIBILITY = WM_APP + 109;
constexpr UINT WM_APP_TEST_INSPECTION = WM_APP + 110;
std::atomic<bool> g_testHoldBound{false};
std::atomic<unsigned> g_testDeliveryFault{0};
#endif

const wchar_t kWindowClassName[] = L"KNDbgX_UiHost";
const wchar_t kInspectionClassName[] = L"KNDbgX_InspectHost";
const wchar_t kWindowTitle[] = L"KNDbgX";
const wchar_t kVirtualOrigin[] = L"https://app.kndbgx.local";

bool StartsWithIgnoreCase(const wchar_t *text, const wchar_t *prefix)
{
    if (text == nullptr || prefix == nullptr)
    {
        return false;
    }

    return _wcsnicmp(text, prefix, wcslen(prefix)) == 0;
}

bool IsOurOrigin(const wchar_t *uri)
{
    if (uri == nullptr)
    {
        return false;
    }

    const size_t originLen = wcslen(kVirtualOrigin);

    if (_wcsnicmp(uri, kVirtualOrigin, originLen) != 0)
    {
        return false;
    }

    const wchar_t next = uri[originLen];
    return next == L'\0' || next == L'/' || next == L'?' || next == L'#';
}

std::wstring AssetPathFromUri(const wchar_t *uri)
{
    if (!IsOurOrigin(uri))
    {
        return std::wstring();
    }

    std::wstring path(uri + wcslen(kVirtualOrigin));
    const size_t cut = path.find_first_of(L"?#");

    if (cut != std::wstring::npos)
    {
        path.resize(cut);
    }

    if (path.empty() || path == L"/")
    {
        path = L"/index.html";
    }

    return path;
}

HMODULE ThisModule()
{
    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&StartsWithIgnoreCase), &module);

    if (module == nullptr)
    {
        module = GetModuleHandleW(L"kndbgx.dll");
    }

    return module;
}

std::atomic<long> g_threadState{0}; // Idle, Running, Closing.
std::atomic<HWND> g_hwnd{nullptr};
std::atomic<uint64_t> g_windowGeneration{0};
std::atomic<bool> g_closeRequested{false};
std::atomic<uint64_t> g_navigationGeneration{0};
std::atomic<uint64_t> g_webviewGeneration{0};
unsigned g_uiOperationDepth = 0;
bool g_deferredFailure = false;
bool g_deferredBoot = false;
bool g_deferredClose = false;
bool g_deferredInspectionClose = false;

// COM calls can pump sent window messages. Never tear down an active callback.
class UiOperation
{
  public:
    UiOperation()
    {
        ++g_uiOperationDepth;
    }
    ~UiOperation()
    {
        if (--g_uiOperationDepth == 0 && (g_deferredFailure || g_deferredBoot || g_deferredClose || g_deferredInspectionClose))
        {
            PostMessageW(g_hwnd.load(), WM_APP_DRAIN_UI, 0, 0);
        }
    }
};
kncore::RpcGate g_rpcGate;
std::atomic<unsigned> g_liveHandlers{0};
std::atomic<unsigned> g_workerState{0};
std::atomic<unsigned> g_cleanupStage{0};

HMODULE AcquireModuleLease()
{
    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&AcquireModuleLease), &module);
    return module;
}

struct BridgeWorkItem
{
    knjson::Value Request;
    uint64_t Generation = 0;
    uint64_t Navigation = 0;
    kncore::UiOperations::State Operation;
};

std::mutex g_workMutex;
std::condition_variable g_workCv;
std::deque<BridgeWorkItem> g_workQueue;
std::map<uint64_t, std::wstring> g_replies;
uint64_t g_nextReply = 0;
kncore::UiOperations g_operations;
kncore::UiOperations::State g_activeUiRequest;
std::atomic<bool> g_workStop{false};
HANDLE g_workThread = nullptr;

void PostBridgeReply(const knjson::Value &reply, uint64_t generation, uint64_t navigation)
{
    const std::wstring payload = reply.Write();
    std::lock_guard<std::mutex> lock(g_workMutex);
    const HWND hwnd = g_hwnd.load();
#ifdef _DEBUG
    if (reply.Get(L"type").AsString(L"") == L"completed" && g_testDeliveryFault.load() == 2)
    {
        g_testDeliveryFault.store(0);
        g_operations.Delivery(reply.Get(L"operationId").AsString(L""), E_FAIL);
        SetPropW(hwnd, L"KNDbgX.DeliveryFault", reinterpret_cast<HANDLE>(2));
        return;
    }
#endif
    if (hwnd == nullptr || generation != g_windowGeneration.load() || navigation != g_navigationGeneration.load() ||
        g_closeRequested.load() || g_replies.size() >= 64)
    {
        g_operations.Delivery(reply.Get(L"operationId").AsString(L""), E_ABORT,
                              generation != g_windowGeneration.load() || navigation != g_navigationGeneration.load());
        return;
    }
    const uint64_t id = ++g_nextReply;
    g_replies.emplace(id, payload);
    if (!PostMessageW(hwnd, WM_APP_BRIDGE_REPLY, static_cast<WPARAM>(id), 0))
    {
        g_replies.erase(id);
        g_operations.Delivery(reply.Get(L"operationId").AsString(L""), E_FAIL);
    }
}

void CancelOperation(const kncore::UiOperations::State &operation)
{
    if (operation)
    {
        operation->Cancelled.store(true);
        const auto serial = operation->Serial.load();
        if (serial != 0)
        {
            knengine::Coordinator().Cancel(kncore::ExecutionDomain::Ui, serial);
        }
    }
}

// Requires g_workMutex. Record queued cancellation before discarding queue entries.
void DrainQueuedOperations()
{
    for (const auto &item : g_workQueue)
    {
        CancelOperation(item.Operation);
        auto reply = knjson::Value::MakeObject();
        reply.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
        reply.Set(L"requestId", item.Request.Get(L"requestId"));
        reply.Set(L"uiGeneration", knjson::Value(std::to_wstring(item.Navigation)));
        reply.Set(L"type", knjson::Value(L"completed"));
        reply.Set(L"ok", knjson::Value(false));
        reply.Set(L"error", knjson::Value(L"CancelledBeforeStartOrStaleNavigation"));
        g_operations.Complete(item.Operation, std::move(reply));
        g_operations.Delivery(item.Operation->Id, E_ABORT, true);
    }
    g_workQueue.clear();
    CancelOperation(g_activeUiRequest);
}

void RunBridgeWorker()
{
    g_workerState.store(1);
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    {
        knengine::DbgSession session;
        for (;;)
        {
            BridgeWorkItem item;
            {
                std::unique_lock<std::mutex> lock(g_workMutex);
                g_workCv.wait(lock,
                              []()
                              {
                                  return g_workStop.load() || !g_workQueue.empty();
                              });
                if (g_workStop.load())
                {
                    DrainQueuedOperations();
                    break;
                }
                item = std::move(g_workQueue.front());
                g_workQueue.pop_front();
                g_activeUiRequest = item.Operation;
            }
#ifdef _DEBUG
            if (item.Request.Get(L"method").AsString(L"") == L"navigateResult" && g_testHoldBound.load())
            {
                std::unique_lock<std::mutex> lock(g_workMutex);
                SetPropW(g_hwnd.load(), L"KNDbgX.BoundHeld", reinterpret_cast<HANDLE>(1));
                g_workCv.wait(lock,
                              []()
                              {
                                  return !g_testHoldBound.load() || g_workStop.load();
                              });
                RemovePropW(g_hwnd.load(), L"KNDbgX.BoundHeld");
            }
#endif
            knjson::Value reply = knjson::Value::MakeObject();
            reply.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
            reply.Set(L"requestId", item.Request.Get(L"requestId"));
            reply.Set(L"uiGeneration", knjson::Value(std::to_wstring(item.Navigation)));
            reply.Set(L"type", knjson::Value(L"completed"));
            const bool cancelled = item.Operation->Cancelled.load() || item.Navigation != g_navigationGeneration.load();
            try
            {
                if (cancelled || FAILED(com))
                {
                    reply.Set(L"ok", knjson::Value(false));
                    reply.Set(L"error", knjson::Value(FAILED(com) ? L"ComInitializationFailed" : L"CancelledBeforeStartOrStaleNavigation"));
                }
                else
                {
                    g_operations.Running(item.Operation);
#ifdef _DEBUG
                    const auto starts = reinterpret_cast<ULONG_PTR>(GetPropW(g_hwnd.load(), L"KNDbgX.WorkerStarts"));
                    SetPropW(g_hwnd.load(), L"KNDbgX.WorkerStarts", reinterpret_cast<HANDLE>(starts + 1));
#endif
                    auto progress = reply;
                    progress.Set(L"operationId", knjson::Value(item.Operation->Id));
                    progress.Set(L"type", knjson::Value(L"progress"));
                    progress.Set(L"phase", knjson::Value(L"Running"));
                    PostBridgeReply(progress, item.Generation, item.Navigation);
                    const kncore::OperationProgressSink observer = [&](kncore::OperationStage stage)
                    {
                        g_operations.Observe(item.Operation, stage);
                    };
                    const kncore::OperationProgressScope observed(observer);
                    reply = knbridge::HandleRequest(
                        item.Request, &session,
                        [&]()
                        {
                            return g_workStop.load() || item.Generation != g_windowGeneration.load() ||
                                   item.Navigation != g_navigationGeneration.load() || item.Operation->Cancelled.load();
                        },
                        [&](uint64_t serial)
                        {
                            item.Operation->Serial.store(serial);
                            if (item.Operation->Cancelled.load())
                            {
                                knengine::Coordinator().Cancel(kncore::ExecutionDomain::Ui, serial);
                            }
                        });
                }
            }
            catch (...)
            {
                reply.Set(L"ok", knjson::Value(false));
                reply.Set(L"error", knjson::Value(L"InternalFault"));
            }
            {
                std::lock_guard<std::mutex> lock(g_workMutex);
                g_activeUiRequest.reset();
            }
            reply = g_operations.Complete(item.Operation, std::move(reply));
#ifdef _DEBUG
            if (item.Request.Get(L"method").AsString(L"") == L"debuggerAction")
            {
                const auto &result = reply.Get(L"result");
                const bool passed = reply.Get(L"ok").AsBool(false) && result.Get(L"ok").AsBool(false) &&
                    result.Get(L"operation").AsString(L"") == item.Request.Get(L"params").Get(L"operation").AsString(L"");
                std::printf("test.execution: operation=%s passed=%d error=%s\n",
                    knutil::WideToUtf8(item.Request.Get(L"params").Get(L"operation").AsString(L"")).c_str(), passed ? 1 : 0,
                    knutil::WideToUtf8(reply.Get(L"error").AsString(result.Get(L"error").AsString(L"").c_str())).c_str());
                std::fflush(stdout);
                SetPropW(g_hwnd.load(), L"KNDbgX.ExecutionReply", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
            }
            if (item.Request.Get(L"method").AsString(L"") == L"execute" &&
                item.Request.Get(L"params").Get(L"command").AsString(L"").starts_with(L".echo KNDBGX_UI_HOST_FIRST"))
            {
                const auto &result = reply.Get(L"result");
                const auto retained = kncore::Results().Find(result.Get(L"resultId").AsString(L""));
                const bool passed = reply.Get(L"ok").AsBool(false) && result.Get(L"ok").AsBool(false) && retained &&
                                    retained->Data.Source == L"windbg" && retained->Data.Consistency == L"UnverifiedEffects" &&
                                    retained->Data.Analysis.Get(L"hostCommandLine").AsString(L"") ==
                                        item.Request.Get(L"params").Get(L"command").AsString(L"") &&
                                    !result.Get(L"currentTarget").Get(L"targetGeneration").AsString(L"").empty() &&
                                    result.Get(L"currentTarget").Get(L"targetGeneration").AsString(L"") !=
                                        result.Get(L"data").Get(L"target").Get(L"targetGeneration").AsString(L"") &&
                                    retained->Text.find(L"KNDBGX_UI_HOST_FIRST") != std::wstring::npos &&
                                    retained->Text.find(L"KNDBGX_UI_HOST_SECOND:42") != std::wstring::npos;
                SetPropW(g_hwnd.load(), L"KNDbgX.ConsoleReply", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
            }
            if (item.Request.Get(L"method").AsString(L"") == L"navigateResult")
            {
                const bool stale = reply.Get(L"error").AsString(L"").starts_with(L"StaleResultOrInvalidNavigation");
                const bool succeeded =
                    reply.Get(L"ok").AsBool(false) && reply.Get(L"result").Get(L"data").Get(L"status").AsString(L"") == L"Success";
                SetPropW(g_hwnd.load(), L"KNDbgX.BoundReply",
                         reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(stale       ? 1
                                                                         : succeeded ? 2
                                                                                     : 3)));
            }
#endif
            PostBridgeReply(reply, item.Generation, item.Navigation);
        }
    }
    if (SUCCEEDED(com))
    {
        CoUninitialize();
    }
    g_workerState.store(3);
}

DWORD WINAPI BridgeWorkerProc(LPVOID parameter)
{
    RunBridgeWorker();
    FreeLibraryAndExitThread(static_cast<HMODULE>(parameter), 0);
}

bool EnsureBridgeWorker()
{
    if (g_workThread != nullptr)
    {
        return true;
    }
    HMODULE lease = AcquireModuleLease();
    if (lease == nullptr)
    {
        return false;
    }
    g_workStop.store(false);
    g_workThread = CreateThread(nullptr, 0, BridgeWorkerProc, lease, 0, nullptr);
    if (g_workThread == nullptr)
    {
        FreeLibrary(lease);
    }
    return g_workThread != nullptr;
}

kncore::UiOperations::State EnqueueBridgeWork(const knjson::Value &request)
{
    kncore::UiOperations::State accepted;
    if (EnsureBridgeWorker())
    {
        std::lock_guard<std::mutex> lock(g_workMutex);
        if (!g_workStop.load() && !g_closeRequested.load() && g_workQueue.size() < 32)
        {
            accepted =
                g_operations.Admit({g_windowGeneration.load(), g_navigationGeneration.load(), request.Get(L"requestId").AsString(L"")},
                                   request.Get(L"method").AsString(L""));
            if (accepted)
            {
                g_workQueue.push_back({request, g_windowGeneration.load(), g_navigationGeneration.load(), accepted});
            }
        }
    }
    g_workCv.notify_one();
    return accepted;
}

void StopBridgeWorker()
{
    g_workerState.store(2);
    {
        std::lock_guard<std::mutex> lock(g_workMutex);
        g_workStop.store(true);
        DrainQueuedOperations();
        g_replies.clear();
    }
    g_workCv.notify_all();
}

void PumpClosingMessages()
{
    MSG message = {};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
    {
        if (message.message != WM_QUIT)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

struct AssetEntry
{
    const wchar_t *Path;
    unsigned int ResourceId;
    const wchar_t *ContentType;
};

const AssetEntry kAssets[] = {
    {L"/index.html", IDR_KNDX_HTML, L"text/html; charset=utf-8"},
    {L"/app.css", IDR_KNDX_CSS, L"text/css; charset=utf-8"},
    {L"/app.js", IDR_KNDX_JS, L"application/javascript; charset=utf-8"},
};

std::wstring ExpandLocalAppData(const wchar_t *suffix)
{
    wchar_t rawPath[MAX_PATH * 2] = L"%LOCALAPPDATA%\\kndbgx";
    wchar_t expanded[MAX_PATH * 2] = L"";

    wcscat_s(rawPath, suffix);
    ExpandEnvironmentStringsW(rawPath, expanded, MAX_PATH * 2);
    return std::wstring(expanded);
}

bool ReadEmbeddedResource(unsigned int resourceId, std::string *bytes)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr)
        {
            break;
        }

        HMODULE module = ThisModule();

        if (module == nullptr)
        {
            module = GetModuleHandleW(nullptr);
        }

        HRSRC found = FindResourceW(module, MAKEINTRESOURCEW(resourceId), RT_RCDATA);

        if (found == nullptr)
        {
            break;
        }

        HGLOBAL loaded = LoadResource(module, found);

        if (loaded == nullptr)
        {
            break;
        }

        const void *locked = LockResource(loaded);
        const DWORD size = SizeofResource(module, found);

        if (locked == nullptr || size == 0)
        {
            break;
        }

        bytes->assign(static_cast<const char *>(locked), static_cast<const char *>(locked) + size);
        ok = true;
    } while (false);

    return ok;
}

// Generic completion/event handler base with manual refcounting.
// All concrete handlers are nested inside UiApp.
template <typename TInterface> class HandlerBase : public TInterface
{
  public:
    STDMETHODIMP QueryInterface(REFIID riid, void **out) override
    {
        if (out == nullptr)
        {
            return E_POINTER;
        }

        if (riid == __uuidof(IUnknown) || riid == __uuidof(TInterface))
        {
            *out = static_cast<TInterface *>(this);
            AddRef();
            return S_OK;
        }

        *out = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override
    {
        return static_cast<ULONG>(++refCount_);
    }

    STDMETHODIMP_(ULONG) Release() override
    {
        const long remaining = --refCount_;

        if (remaining == 0)
        {
            delete this;
        }

        return static_cast<ULONG>(remaining);
    }

  protected:
    HandlerBase() : refCount_(1), generation_(g_windowGeneration.load()), webviewGeneration_(g_webviewGeneration.load())
    {
        ++g_liveHandlers;
    }
    virtual ~HandlerBase()
    {
        --g_liveHandlers;
    }
    bool Live() const
    {
        return kncore::UiCallbackCurrent(generation_, webviewGeneration_, g_windowGeneration.load(), g_webviewGeneration.load(),
                                         g_closeRequested.load());
    }

  private:
    std::atomic<long> refCount_;
    uint64_t generation_;
    uint64_t webviewGeneration_;
};
} // namespace

class UiApp
{
  public:
    static UiApp *Instance()
    {
        static UiApp instance;
        return &instance;
    }

    int Run()
    {
        int exitCode = 1;
        g_deferredClose = g_deferredBoot = g_deferredFailure = false;
        visible_ = true;
#ifdef _DEBUG
        wchar_t testMode[2] = {};
        testMode_ = GetEnvironmentVariableW(L"KNDBGX_TEST_UI", testMode, 2) == 1 && testMode[0] == L'1';
#endif

        // Pairing: every successful CoInitializeEx is balanced by the
        // CoUninitialize call at the end of this function.
        const HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        do
        {
            if (FAILED(comInit))
            {
                break;
            }

            if (!RegisterWindowClass())
            {
                break;
            }

            if (!CreateMainWindow())
            {
                break;
            }

            if (g_closeRequested.load())
            {
                DestroyWindow(g_hwnd.load());
            }
            else
            {
                BootWebView();
            }

            MSG message;

            while (GetMessageW(&message, nullptr, 0, 0) > 0)
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }

            exitCode = 0;
        } while (false);

        g_threadState.store(2);
        g_closeRequested.store(true);
        g_hwnd.store(nullptr);
        StopBridgeWorker();
        g_cleanupStage.store(1);
        TeardownWebView();
        g_cleanupStage.store(2);
        while ((g_workThread != nullptr && WaitForSingleObject(g_workThread, 0) != WAIT_OBJECT_0) || g_liveHandlers.load() != 0)
        {
            MsgWaitForMultipleObjects(0, nullptr, FALSE, 50, QS_ALLINPUT);
            PumpClosingMessages();
        }
        if (g_workThread != nullptr)
        {
            CloseHandle(g_workThread);
            g_workThread = nullptr;
        }
        UnregisterClassW(kInspectionClassName, ThisModule());
        UnregisterClassW(kWindowClassName, ThisModule());
        for (HICON *icon : {&largeIcon_, &smallIcon_})
        {
            if (*icon != nullptr)
            {
                DestroyIcon(*icon);
                *icon = nullptr;
            }
        }
        g_cleanupStage.store(3);

        if (SUCCEEDED(comInit))
        {
            CoUninitialize();
        }

        return exitCode;
    }

    void OnEnvironmentCreated(HRESULT status, ICoreWebView2Environment *environment)
    {
        if (lifecycle_.Phase != kncore::UiPhase::EnvironmentPending)
        {
            return;
        }
        if (!lifecycle_.Check(kncore::UiStep::EnvironmentComplete, Inject(kncore::UiStep::EnvironmentComplete, status),
                              environment != nullptr))
        {
            QueueFailure();
            return;
        }
        environment_ = environment;
        lifecycle_.Phase = kncore::UiPhase::ControllerPending;
        auto *handler = new (std::nothrow) ControllerCompletedHandler();
        HRESULT created = handler == nullptr ? E_OUTOFMEMORY : Inject(kncore::UiStep::ControllerRequest, S_OK);
        if (SUCCEEDED(created))
        {
            created = environment_->CreateCoreWebView2Controller(g_hwnd.load(), handler);
        }
        if (handler != nullptr)
        {
            handler->Release();
        }
        if (!lifecycle_.Check(kncore::UiStep::ControllerRequest, created))
        {
            QueueFailure();
        }
    }

    void OnControllerCreated(HRESULT status, ICoreWebView2Controller *controller)
    {
        if (lifecycle_.Phase != kncore::UiPhase::ControllerPending)
        {
            if (controller != nullptr)
            {
                controller->Close();
            }
            return;
        }
        // Own even a failed callback's non-null controller so rollback closes it.
        controller_ = controller;
        if (!lifecycle_.Check(kncore::UiStep::ControllerComplete, Inject(kncore::UiStep::ControllerComplete, status),
                              controller != nullptr))
        {
            QueueFailure();
            return;
        }
        try
        {
            lifecycle_.Install(
                [&](kncore::UiStep step)
                {
                    return InstallStep(step);
                },
                [&]()
                {
                    QueueFailure();
                });
        }
        catch (...)
        {
            lifecycle_.Check(kncore::UiStep::Settings, E_OUTOFMEMORY);
            QueueFailure();
        }
    }

  private:
    UiApp() = default;
    ~UiApp() = default;

    // WebView2 completion handlers (nested so they reach private state).
    class EnvironmentCompletedHandler : public HandlerBase<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>
    {
      public:
        STDMETHODIMP Invoke(HRESULT errorCode, ICoreWebView2Environment *createdEnvironment) override
        {
            UiOperation operation;
            if (Live())
            {
                UiApp::Instance()->OnEnvironmentCreated(errorCode, createdEnvironment);
            }
            return S_OK;
        }
    };

    class ControllerCompletedHandler : public HandlerBase<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>
    {
      public:
        STDMETHODIMP Invoke(HRESULT errorCode, ICoreWebView2Controller *createdController) override
        {
            UiOperation operation;
            if (Live())
            {
                UiApp::Instance()->OnControllerCreated(errorCode, createdController);
            }
            else if (createdController != nullptr)
            {
                createdController->Close();
            }
            return S_OK;
        }
    };

    struct InspectionWindow
    {
        std::wstring Name;
        HWND Window = nullptr;
        bool Visible = false;
        bool Closing = false;
        uint64_t Generation = 0;
        uint64_t VisibilityEpoch = 0;
        std::wstring Token;
        std::wstring Uri;
        ComPtr<ICoreWebView2Controller> Controller;
        ComPtr<ICoreWebView2> View;
        ComPtr<ICoreWebView2NewWindowRequestedEventArgs> Args;
        ComPtr<ICoreWebView2Deferral> Deferral;
    };

    struct InspectionDockTarget
    {
        HWND Window = nullptr;
        std::wstring Name;
        std::wstring Token;
        uint64_t Epoch = 0;
    };

    struct InspectionDrag
    {
        HWND Window = nullptr;
        std::wstring Token;
        uint64_t Generation = 0;
        uint64_t Epoch = 0;
        uint64_t Document = 0;
        uint64_t Serial = 0;
        RECT Original = {};
        bool Moving = false;
        InspectionDockTarget Target;
    };

    InspectionWindow *FindInspection(uint64_t generation)
    {
        for (auto &[name, inspection] : inspections_)
        {
            if (inspection.Generation == generation && inspection.Window != nullptr)
            {
                return &inspection;
            }
        }
        return nullptr;
    }

    InspectionWindow *FindInspectionWindow(HWND window)
    {
        for (auto &[name, inspection] : inspections_)
        {
            if (window != nullptr && inspection.Window == window)
            {
                return &inspection;
            }
        }
        return nullptr;
    }

    std::wstring InspectionProperty(const InspectionWindow &inspection)
    {
        return L"KNDbgX.InspectWindow" + (inspection.Name.empty() ? L"" : L"." + inspection.Name);
    }

    void NotifyInspectionDrag(const wchar_t *phase)
    {
        if (webview_ == nullptr || inspectionDrag_.Window == nullptr)
        {
            return;
        }
        auto notice = knjson::Value::MakeObject();
        notice.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
        notice.Set(L"requestId", knjson::Value(L""));
        notice.Set(L"type", knjson::Value(L"inspectionDockDrag"));
        notice.Set(L"uiGeneration", knjson::Value(std::to_wstring(inspectionDrag_.Document)));
        notice.Set(L"token", knjson::Value(inspectionDrag_.Token));
        notice.Set(L"visibilityEpoch", knjson::Value(std::to_wstring(inspectionDrag_.Epoch)));
        notice.Set(L"dragId", knjson::Value(std::to_wstring(inspectionDrag_.Serial)));
        notice.Set(L"phase", knjson::Value(phase));
        notice.Set(L"destination", knjson::Value(inspectionDrag_.Target.Name));
        notice.Set(L"destinationToken", knjson::Value(inspectionDrag_.Target.Token));
        notice.Set(L"destinationEpoch", knjson::Value(std::to_wstring(inspectionDrag_.Target.Epoch)));
        webview_->PostWebMessageAsJson(notice.Write().c_str());
    }

    void CancelInspectionDrag()
    {
        NotifyInspectionDrag(L"cancel");
        inspectionDrag_ = {};
    }

    void BeginInspectionDrag(InspectionWindow &inspection)
    {
        CancelInspectionDrag();
        if (inspectionMouseMove_ != inspection.Window || !inspection.Visible || inspection.Closing || !visible_ ||
            !GetWindowRect(inspection.Window, &inspectionDrag_.Original))
        {
            return;
        }
        inspectionDrag_.Window = inspection.Window;
        inspectionDrag_.Token = inspection.Token;
        inspectionDrag_.Generation = inspection.Generation;
        inspectionDrag_.Epoch = inspection.VisibilityEpoch;
        inspectionDrag_.Document = g_navigationGeneration.load();
        inspectionDrag_.Serial = ++inspectionDragSerial_;
    }

    InspectionDockTarget InspectionDropAt(POINT point, HWND source)
    {
        InspectionDockTarget target;
        if (!visible_ || g_closeRequested.load())
        {
            return target;
        }
        // Match the percentage-based guides in app.css without mixing DPI units.
        const auto inZone = [&](HWND window, bool group)
        {
            RECT client = {};
            POINT origin = {};
            if (!IsWindowVisible(window) || IsIconic(window) || !IsWindowEnabled(window) ||
                !GetClientRect(window, &client) || !ClientToScreen(window, &origin))
            {
                return false;
            }
            const RECT zone = {origin.x + client.right * (group ? 8 : 55) / 100,
                               origin.y + client.bottom * (group ? 14 : 15) / 100,
                               origin.x + client.right * (group ? 92 : 96) / 100,
                               origin.y + client.bottom * 88 / 100};
            return PtInRect(&zone, point) != FALSE;
        };
        // Ignore the dragged frame, but never dock through another covering app.
        HWND under = nullptr;
        unsigned visited = 0;
        for (HWND window = GetTopWindow(nullptr); window != nullptr && ++visited <= 4096; window = GetWindow(window, GW_HWNDNEXT))
        {
            RECT bounds = {};
            const auto style = GetWindowLongPtrW(window, GWL_EXSTYLE);
            const auto passThrough = WS_EX_LAYERED | WS_EX_TRANSPARENT;
            if (window != source && IsWindowVisible(window) && !IsIconic(window) && GetWindowRect(window, &bounds) &&
                PtInRect(&bounds, point) && (style & passThrough) != passThrough)
            {
                under = window;
                break;
            }
        }
        const auto &group = inspections_.at(L"");
        if (under == g_hwnd.load() && inZone(under, false))
        {
            target.Window = under;
            target.Name = L"main";
        }
        else if (under != nullptr && under != source && under == group.Window && group.Visible && !group.Closing && inZone(under, true))
        {
            target.Window = under;
            target.Name = L"group";
            target.Token = group.Token;
            target.Epoch = group.VisibilityEpoch;
        }
        return target;
    }

    void MoveInspectionDrag(HWND window)
    {
        POINT point = {};
        if (inspectionDrag_.Window != window || !GetCursorPos(&point))
        {
            return;
        }
        const auto target = InspectionDropAt(point, window);
        const bool changed = !inspectionDrag_.Moving || target.Window != inspectionDrag_.Target.Window ||
                             target.Token != inspectionDrag_.Target.Token || target.Epoch != inspectionDrag_.Target.Epoch;
        inspectionDrag_.Moving = true;
        inspectionDrag_.Target = target;
        if (changed)
        {
            NotifyInspectionDrag(L"preview");
        }
    }

    void EndInspectionDrag(HWND window)
    {
        if (inspectionDrag_.Window != window)
        {
            return;
        }
        auto *source = FindInspectionWindow(window);
        POINT point = {};
        RECT bounds = {};
        const bool valid = source != nullptr && source->Visible && !source->Closing &&
                           source->Generation == inspectionDrag_.Generation && source->VisibilityEpoch == inspectionDrag_.Epoch &&
                           inspectionDrag_.Document == g_navigationGeneration.load() && inspectionDrag_.Moving &&
                           (GetAsyncKeyState(VK_ESCAPE) & 0x8000) == 0 && GetWindowRect(window, &bounds) &&
                           !EqualRect(&bounds, &inspectionDrag_.Original) && GetCursorPos(&point);
        inspectionDrag_.Target = valid ? InspectionDropAt(point, window) : InspectionDockTarget{};
        NotifyInspectionDrag(inspectionDrag_.Target.Window != nullptr ? L"drop" : L"cancel");
        inspectionDrag_ = {};
    }

    bool RegisterWindowClass()
    {
        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.style = CS_HREDRAW | CS_VREDRAW;
        windowClass.lpfnWndProc = WindowProcThunk;
        windowClass.hInstance = ThisModule();
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        // The registered class owns this brush and deletes it on unregister.
        HBRUSH backgroundBrush = CreateSolidBrush(RGB(0x14, 0x16, 0x1a));
        if (backgroundBrush == nullptr)
        {
            OutputDebugStringW(L"KNDbgX: window background brush allocation failed.\n");
            return false;
        }
        windowClass.hbrBackground = backgroundBrush;
        windowClass.lpszClassName = kWindowClassName;
        // Keep the nonshared icons alive until the window class is unregistered.
        largeIcon_ = static_cast<HICON>(LoadImageW(windowClass.hInstance, MAKEINTRESOURCEW(IDI_KNDX_APP), IMAGE_ICON,
                                                 GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR));
        smallIcon_ = static_cast<HICON>(LoadImageW(windowClass.hInstance, MAKEINTRESOURCEW(IDI_KNDX_APP), IMAGE_ICON,
                                                 GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR));
        windowClass.hIcon = largeIcon_;
        windowClass.hIconSm = smallIcon_;

        const bool registered = RegisterClassExW(&windowClass) != 0;
        const DWORD error = registered ? ERROR_SUCCESS : GetLastError();
        if (!registered)
        {
            DeleteObject(backgroundBrush);
            if (error != ERROR_CLASS_ALREADY_EXISTS)
            {
                wchar_t message[128] = {};
                swprintf_s(message, L"KNDbgX: window class registration failed (Win32 %lu).\n", error);
                OutputDebugStringW(message);
            }
        }
        if (!registered && error != ERROR_CLASS_ALREADY_EXISTS)
        {
            return false;
        }
        windowClass.lpfnWndProc = InspectionWindowProc;
        windowClass.lpszClassName = kInspectionClassName;
        windowClass.hbrBackground = CreateSolidBrush(RGB(0x0d, 0x15, 0x1f));
        if (windowClass.hbrBackground == nullptr)
        {
            return false;
        }
        const bool inspectionRegistered = RegisterClassExW(&windowClass) != 0;
        const DWORD inspectionError = inspectionRegistered ? ERROR_SUCCESS : GetLastError();
        if (!inspectionRegistered)
        {
            DeleteObject(windowClass.hbrBackground);
        }
        return inspectionRegistered || inspectionError == ERROR_CLASS_ALREADY_EXISTS;
    }

    bool CreateMainWindow()
    {
        RECT workArea;
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);

        const int width = 1280;
        const int height = 860;
        const int x = workArea.left + ((workArea.right - workArea.left) - width) / 2;
        const int y = workArea.top + ((workArea.bottom - workArea.top) - height) / 2;

        g_hwnd.store(CreateWindowExW(0, kWindowClassName, kWindowTitle, WS_OVERLAPPEDWINDOW, x, y, width, height, nullptr, nullptr,
                                     ThisModule(), this));

        if (g_hwnd.load() == nullptr)
        {
            return false;
        }

        ShowWindow(g_hwnd.load(), SW_SHOW);
        UpdateWindow(g_hwnd.load());
        return true;
    }

    void SetVisible(bool visible)
    {
        UiOperation operation;
        if (g_closeRequested.load())
        {
            return;
        }
        if (!visible)
        {
            CancelInspectionDrag();
        }
        const bool retryFailed = visible && lifecycle_.Phase == kncore::UiPhase::Failed;
        visible_ = visible;
        const HWND window = g_hwnd.load();
        ShowWindow(window, visible ? (IsIconic(window) ? SW_RESTORE : SW_SHOW) : SW_HIDE);
        if (controller_ != nullptr && !g_closeRequested.load() && lifecycle_.Phase != kncore::UiPhase::Failed)
        {
            HRESULT status = Inject(kncore::UiStep::Visible, S_OK);
            if (SUCCEEDED(status))
            {
                status = controller_->put_IsVisible(visible_ ? TRUE : FALSE);
            }
            if (FAILED(status) && !g_closeRequested.load() && lifecycle_.Phase != kncore::UiPhase::Failed)
            {
                lifecycle_.Check(kncore::UiStep::Visible, status);
                QueueFailure();
            }
        }
        if (visible_ && !g_closeRequested.load())
        {
            SetForegroundWindow(window);
            if (retryFailed && lifecycle_.Phase == kncore::UiPhase::Failed)
            {
                g_deferredBoot = true;
                PostMessageW(window, WM_APP_DRAIN_UI, 0, 0);
            }
        }
        for (auto &[name, inspection] : inspections_)
        {
            if (inspection.Controller == nullptr || inspection.Closing)
            {
                continue;
            }
            const HRESULT status = SetInspectionVisible(inspection, inspection.Visible, false);
            if (FAILED(status) && lifecycle_.Phase != kncore::UiPhase::Failed && !g_closeRequested.load())
            {
                lifecycle_.Check(kncore::UiStep::Visible, status);
                QueueFailure();
            }
        }
    }

    void CloseInspection(InspectionWindow &inspection)
    {
        if (inspectionDrag_.Window == inspection.Window || inspectionDrag_.Target.Window == inspection.Window)
        {
            CancelInspectionDrag();
        }
        inspection.Closing = false;
        inspection.Generation = ++inspectionGeneration_;
        inspection.Token.clear();
        inspection.VisibilityEpoch = 0;
        inspection.Visible = false;
        inspection.View.Reset();
        auto controller = std::move(inspection.Controller);
        if (controller != nullptr)
        {
            controller->Close();
        }
        inspection.Args.Reset();
        if (inspection.Deferral != nullptr)
        {
            auto deferral = std::move(inspection.Deferral);
            deferral->Complete();
        }
        const HWND window = inspection.Window;
        inspection.Window = nullptr;
        RemovePropW(g_hwnd.load(), InspectionProperty(inspection).c_str());
        if (window != nullptr)
        {
            DestroyWindow(window);
        }
    }

    void QueueInspectionClose(InspectionWindow &inspection)
    {
        PostMessageW(g_hwnd.load(), WM_APP_CLOSE_INSPECTION, static_cast<WPARAM>(inspection.Generation), 0);
    }

    HRESULT SetInspectionVisible(InspectionWindow &inspection, bool visible, bool activate)
    {
        if (!visible && (inspectionDrag_.Window == inspection.Window || inspectionDrag_.Target.Window == inspection.Window))
        {
            CancelInspectionDrag();
        }
        if (inspection.Controller == nullptr || inspection.Window == nullptr)
        {
            return E_PENDING;
        }
        const HRESULT status = inspection.Controller->put_IsVisible(visible && visible_ ? TRUE : FALSE);
        if (SUCCEEDED(status))
        {
            inspection.Visible = visible;
            const int show = visible && visible_ ? (activate && IsIconic(inspection.Window) ? SW_RESTORE : SW_SHOWNOACTIVATE) : SW_HIDE;
            ShowWindow(inspection.Window, show);
            if (visible && visible_ && activate)
            {
                SetForegroundWindow(inspection.Window);
                inspection.Controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
            }
        }
        return status;
    }

    void HideInspectionFromFrame(InspectionWindow &inspection)
    {
        const HRESULT status = SetInspectionVisible(inspection, false, false);
        if ((SUCCEEDED(status) || status == E_PENDING) && webview_ != nullptr)
        {
            const auto previousEpoch = inspection.VisibilityEpoch++;
            auto notice = knjson::Value::MakeObject();
            notice.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
            notice.Set(L"requestId", knjson::Value(L""));
            notice.Set(L"uiGeneration", knjson::Value(std::to_wstring(g_navigationGeneration.load())));
            notice.Set(L"type", knjson::Value(L"inspectionHidden"));
            notice.Set(L"token", knjson::Value(inspection.Token));
            notice.Set(L"visibilityEpoch", knjson::Value(std::to_wstring(inspection.VisibilityEpoch)));
            if (FAILED(webview_->PostWebMessageAsJson(notice.Write().c_str())))
            {
                inspection.VisibilityEpoch = previousEpoch;
                if (SUCCEEDED(status))
                {
                    SetInspectionVisible(inspection, true, false);
                }
            }
        }
    }

    HRESULT RecoverInspection(InspectionWindow &inspection)
    {
        HRESULT status = E_PENDING;
        do
        {
            if (inspection.Window == nullptr || inspection.Controller == nullptr)
            {
                break;
            }
            MONITORINFO monitor{sizeof(MONITORINFO)};
            RECT bounds{};
            if (!GetMonitorInfoW(MonitorFromWindow(g_hwnd.load(), MONITOR_DEFAULTTONEAREST), &monitor))
            {
                status = E_FAIL;
                break;
            }
            if (IsIconic(inspection.Window) || IsZoomed(inspection.Window))
            {
                ShowWindow(inspection.Window, SW_RESTORE);
            }
            if (!GetWindowRect(inspection.Window, &bounds))
            {
                status = E_FAIL;
                break;
            }
            const LONG width = (std::max)(1L, (std::min)(bounds.right - bounds.left, monitor.rcWork.right - monitor.rcWork.left));
            const LONG height = (std::max)(1L, (std::min)(bounds.bottom - bounds.top, monitor.rcWork.bottom - monitor.rcWork.top));
            const LONG left = (std::clamp)(bounds.left, monitor.rcWork.left, monitor.rcWork.right - width);
            const LONG top = (std::clamp)(bounds.top, monitor.rcWork.top, monitor.rcWork.bottom - height);
            if (!SetWindowPos(inspection.Window, nullptr, left, top, width, height, SWP_NOZORDER | SWP_NOACTIVATE))
            {
                status = E_FAIL;
                break;
            }
            status = SetInspectionVisible(inspection, true, true);
        }
        while (false);
        return status;
    }

    knjson::Value ControlInspection(const knjson::Value &params)
    {
        const auto action = params.Get(L"action").AsString(L"");
        const auto token = params.Get(L"token").AsString(L"");
        HRESULT status = E_INVALIDARG;
        auto reply = knjson::Value::MakeObject();
        InspectionWindow *matched = nullptr;
        for (auto &[name, candidate] : inspections_)
        {
            if (!token.empty() && candidate.Token == token && candidate.Window != nullptr && !candidate.Closing)
            {
                matched = &candidate;
                break;
            }
        }
        if (matched != nullptr)
        {
            auto &inspection = *matched;
            if (action == L"show" || action == L"restore" || action == L"hide" || action == L"recover")
            {
                if (params.Get(L"visibilityEpoch").AsString(L"") != std::to_wstring(inspection.VisibilityEpoch))
                {
                    reply.Set(L"ok", knjson::Value(false));
                    reply.Set(L"error", knjson::Value(L"InspectionVisibilityChanged"));
                    auto result = knjson::Value::MakeObject();
                    result.Set(L"visibilityEpoch", knjson::Value(std::to_wstring(inspection.VisibilityEpoch)));
                    result.Set(L"visible", knjson::Value(inspection.Visible));
                    reply.Set(L"result", result);
                    return reply;
                }
                status = action == L"recover" ? RecoverInspection(inspection) :
                    SetInspectionVisible(inspection, action != L"hide", action == L"show");
            }
            else if (action == L"close")
            {
                QueueInspectionClose(inspection);
                status = S_OK;
            }
            else if (action == L"focus-main" && visible_ && controller_ != nullptr)
            {
                SetForegroundWindow(g_hwnd.load());
                status = controller_->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
            }
        }
        reply.Set(L"ok", knjson::Value(SUCCEEDED(status)));
        if (FAILED(status))
        {
            reply.Set(L"error", knjson::Value(L"InspectionWindowUnavailable"));
        }
        return reply;
    }

    void OpenInspection(ICoreWebView2 *sender, ICoreWebView2NewWindowRequestedEventArgs *args)
    {
        if (args == nullptr)
        {
            return;
        }
        args->put_Handled(TRUE);
        if (sender != webview_.Get() || !lifecycle_.MessagesAllowed() || environment_ == nullptr || !visible_)
        {
            return;
        }
        LPWSTR raw = nullptr;
        if (FAILED(args->get_Uri(&raw)))
        {
            return;
        }
        const std::wstring uri = raw != nullptr ? raw : L"";
        CoTaskMemFree(raw);
        const std::wstring prefix = L"about:blank#kndbgx-inspect-";
        if (!uri.starts_with(prefix))
        {
            return;
        }
        std::wstring suffix = uri.substr(prefix.size());
        std::wstring name;
        const auto separator = suffix.find(L'-');
        if (separator != std::wstring::npos)
        {
            name = suffix.substr(0, separator);
            suffix = suffix.substr(separator + 1);
        }
        const auto slot = inspections_.find(name);
        uint64_t token = 0;
        if (slot == inspections_.end() || slot->second.Window != nullptr || !kncore::ParseUnsigned(suffix, 10, &token) || token == 0 ||
            token > 9007199254740991ULL || suffix != std::to_wstring(token))
        {
            return;
        }
        for (const auto &[existingName, existing] : inspections_)
        {
            if (!existing.Token.empty() && existing.Token == suffix)
            {
                return;
            }
        }
        auto &inspection = slot->second;
        inspection.Name = name;
        inspection.Uri = uri;
        inspection.Closing = false;
        ComPtr<ICoreWebView2Deferral> deferral;
        if (FAILED(args->GetDeferral(&deferral)) || deferral == nullptr)
        {
            return;
        }
        inspection.Token = std::to_wstring(token);
        inspection.VisibilityEpoch = 0;
        inspection.Args = args;
        inspection.Deferral = deferral;
        RECT parent = {};
        GetWindowRect(g_hwnd.load(), &parent);
        MONITORINFO monitor = {sizeof(MONITORINFO)};
        const LONG cascade = name.empty() ? 0 : static_cast<LONG>(std::distance(inspections_.begin(), slot)) * 28;
        RECT bounds = {parent.left + 80 + cascade, parent.top + 80 + cascade, parent.left + 640 + cascade, parent.top + 820 + cascade};
        if (GetMonitorInfoW(MonitorFromWindow(g_hwnd.load(), MONITOR_DEFAULTTONEAREST), &monitor))
        {
            const LONG width = (std::min)(560L, monitor.rcWork.right - monitor.rcWork.left);
            const LONG height = (std::min)(740L, monitor.rcWork.bottom - monitor.rcWork.top);
            bounds.left = (std::clamp)(bounds.left, monitor.rcWork.left, monitor.rcWork.right - width);
            bounds.top = (std::clamp)(bounds.top, monitor.rcWork.top, monitor.rcWork.bottom - height);
            bounds.right = bounds.left + width;
            bounds.bottom = bounds.top + height;
        }
        std::wstring title = name.empty() ? L"Inspect" : name;
        title.front() = static_cast<wchar_t>(towupper(title.front()));
        inspection.Window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_WINDOWEDGE, kInspectionClassName,
                                            (L"KNDbgX - " + title).c_str(), WS_OVERLAPPEDWINDOW,
                                            bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, g_hwnd.load(),
                                            nullptr, ThisModule(), nullptr);
        if (inspection.Window == nullptr)
        {
            CloseInspection(inspection);
            return;
        }
        SetPropW(g_hwnd.load(), InspectionProperty(inspection).c_str(), inspection.Window);
        const auto generation = inspection.Generation = ++inspectionGeneration_;
        auto *callback = new (std::nothrow) InspectionControllerHandler(generation);
        const HRESULT status =
            callback != nullptr ? environment_->CreateCoreWebView2Controller(inspection.Window, callback) : E_OUTOFMEMORY;
        if (callback != nullptr)
        {
            callback->Release();
        }
        if (FAILED(status))
        {
            CloseInspection(inspection);
        }
    }

    void InspectionCreated(uint64_t generation, HRESULT status, ICoreWebView2Controller *controller)
    {
        auto *matched = FindInspection(generation);
        if (matched == nullptr || matched->Closing || matched->Args == nullptr)
        {
            if (controller != nullptr)
            {
                controller->Close();
            }
            return;
        }
        auto &inspection = *matched;
        inspection.Controller = controller;
        if (SUCCEEDED(status) && controller == nullptr)
        {
            status = E_POINTER;
        }
        do
        {
            if (FAILED(status) || controller == nullptr)
            {
                break;
            }
            status = controller->get_CoreWebView2(&inspection.View);
            if (SUCCEEDED(status) && inspection.View == nullptr)
            {
                status = E_POINTER;
            }
            if (FAILED(status) || inspection.View == nullptr)
            {
                break;
            }
            RECT bounds = {};
            GetClientRect(inspection.Window, &bounds);
            status = controller->put_Bounds(bounds);
            ComPtr<ICoreWebView2Settings> settings;
            if (SUCCEEDED(status))
            {
                status = inspection.View->get_Settings(&settings);
            }
            if (SUCCEEDED(status) && settings == nullptr)
            {
                status = E_POINTER;
            }
            if (FAILED(status) || settings == nullptr)
            {
                break;
            }
            for (const auto configured : {settings->put_IsWebMessageEnabled(FALSE), settings->put_AreHostObjectsAllowed(FALSE),
                                          settings->put_AreDefaultScriptDialogsEnabled(FALSE),
                                          settings->put_AreDefaultContextMenusEnabled(FALSE), settings->put_IsStatusBarEnabled(FALSE),
                                          settings->put_AreDevToolsEnabled(FALSE)})
            {
                if (FAILED(configured))
                {
                    status = configured;
                    break;
                }
            }
            if (FAILED(status))
            {
                break;
            }
            ComPtr<ICoreWebView2_22> sourceKinds;
            const HRESULT capability = inspection.View.As(&sourceKinds);
            status =
                capability == E_NOINTERFACE ? inspection.View->AddWebResourceRequestedFilter(L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)
                : FAILED(capability)        ? capability
                                            : sourceKinds->AddWebResourceRequestedFilterWithRequestSourceKinds(
                                           L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL, COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL);
            if (FAILED(status))
            {
                break;
            }
            EventRegistrationToken event = {};
            const auto install = [&](auto *handler, auto add)
            {
                HRESULT added = handler != nullptr ? add(handler, &event) : E_OUTOFMEMORY;
                if (handler != nullptr)
                {
                    handler->Release();
                }
                return added;
            };
            status = install(new (std::nothrow) InspectionResourceHandler(generation),
                             [&](auto *handler, auto *registered)
                             {
                                 return inspection.View->add_WebResourceRequested(handler, registered);
                             });
            if (SUCCEEDED(status))
            {
                status = install(new (std::nothrow) InspectionNavigationHandler(generation),
                                 [&](auto *handler, auto *registered)
                                 {
                                     return inspection.View->add_NavigationStarting(handler, registered);
                                 });
            }
            if (SUCCEEDED(status))
            {
                status = install(new (std::nothrow) FrameNavigationHandler(),
                                 [&](auto *handler, auto *registered)
                                 {
                                     return inspection.View->add_FrameNavigationStarting(handler, registered);
                                 });
            }
            if (SUCCEEDED(status))
            {
                status = install(new (std::nothrow) NewWindowHandler(),
                                 [&](auto *handler, auto *registered)
                                 {
                                     return inspection.View->add_NewWindowRequested(handler, registered);
                                 });
            }
            if (SUCCEEDED(status))
            {
                status = install(new (std::nothrow) PermissionHandler(),
                                 [&](auto *handler, auto *registered)
                                 {
                                     return inspection.View->add_PermissionRequested(handler, registered);
                                 });
            }
            if (SUCCEEDED(status))
            {
                status = install(new (std::nothrow) InspectionCloseHandler(generation),
                                 [&](auto *handler, auto *registered)
                                 {
                                     return inspection.View->add_WindowCloseRequested(handler, registered);
                                 });
            }
            ComPtr<ICoreWebView2_4> downloads;
            if (SUCCEEDED(status))
            {
                status = inspection.View.As(&downloads);
            }
            if (SUCCEEDED(status))
            {
                status = install(new (std::nothrow) DownloadHandler(), [&](auto *handler, auto *registered)
                {
                    return downloads->add_DownloadStarting(handler, registered);
                });
            }
            if (SUCCEEDED(status))
            {
                status = inspection.Args->put_NewWindow(inspection.View.Get());
            }
            if (FAILED(status))
            {
                break;
            }
            auto deferral = std::move(inspection.Deferral);
            inspection.Args.Reset();
            status = deferral->Complete();
            if (SUCCEEDED(status))
            {
                status = SetInspectionVisible(inspection, true, true);
            }
        } while (false);
        if (FAILED(status))
        {
            QueueInspectionClose(inspection);
        }
    }

    void CloseInspection()
    {
        g_deferredInspectionClose = false;
        for (auto &[name, inspection] : inspections_)
        {
            CloseInspection(inspection);
        }
    }

    void CloseQueuedInspections()
    {
        g_deferredInspectionClose = false;
        for (auto &[name, inspection] : inspections_)
        {
            if (inspection.Closing)
            {
                CloseInspection(inspection);
            }
        }
    }

    HRESULT Inject(kncore::UiStep step, HRESULT status)
    {
#ifdef _DEBUG
        if (testFailure_ == static_cast<unsigned>(step) + 1)
        {
            testFailure_ = 0;
            return E_FAIL;
        }
#else
        UNREFERENCED_PARAMETER(step);
#endif
        return status;
    }

    void InvalidateDocument()
    {
        for (auto &[name, inspection] : inspections_)
        {
            if (inspection.Window != nullptr)
            {
                QueueInspectionClose(inspection);
            }
        }
        kncore::Results().SetUiPins({});
        documentToken_ = knutil::NewToken();
        g_rpcGate.Navigate(++g_navigationGeneration, documentToken_);
        SetPropW(g_hwnd.load(), L"KNDbgX.NavigationGeneration", reinterpret_cast<HANDLE>(g_navigationGeneration.load()));
        RemovePropW(g_hwnd.load(), L"KNDbgX.Ready");
        RemovePropW(g_hwnd.load(), L"KNDbgX.StartupRpcMask");
        RemovePropW(g_hwnd.load(), L"KNDbgX.WorkerReplyPosted");
        RemovePropW(g_hwnd.load(), L"KNDbgX.WorkerReplyAcknowledged");
        {
            std::lock_guard<std::mutex> lock(g_workMutex);
            DrainQueuedOperations();
            g_replies.clear();
        }
        g_operations.DocumentChanged(g_windowGeneration.load(), g_navigationGeneration.load());
    }

    void QueueFailure()
    {
        ++g_webviewGeneration;
        InvalidateDocument();
        kncmd::DiscardChangePlans();
        SetPropW(g_hwnd.load(), L"KNDbgX.FailedStage", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(lifecycle_.FailedStep) + 1));
        // Close COM objects after returning from the current WebView2 callback.
        if (!PostMessageW(g_hwnd.load(), WM_APP_UI_FAILED, 0, 0))
        {
            // Keep callbacks inert if the window is already disappearing.
            g_closeRequested.store(true);
            PostQuitMessage(1);
        }
    }

    void DisplayFailure()
    {
        UiOperation operation;
        if (lifecycle_.Phase != kncore::UiPhase::Failed || g_closeRequested.load())
        {
            return;
        }
        TeardownWebView();
        wchar_t text[512] = {};
        swprintf_s(text,
                   L"WebView2 failed at %s (HRESULT 0x%08x).\nRetry UI or close and reopen it.\nCommands are never replayed. Inspect "
                   L"stored results before approving another change.",
                   kncore::UiStepName(lifecycle_.FailedStep), static_cast<unsigned>(lifecycle_.Error));
        OutputDebugStringW(text);
        SetWindowTextW(g_hwnd.load(), L"KNDbgX - UI unavailable; retry or reopen");
        if (failureText_ != nullptr)
        {
            DestroyWindow(failureText_);
        }
        if (retryButton_ != nullptr)
        {
            DestroyWindow(retryButton_);
        }
        failureText_ =
            CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE, 24, 24, 880, 100, g_hwnd.load(), nullptr, ThisModule(), nullptr);
        retryButton_ = CreateWindowExW(0, L"BUTTON", L"Retry UI", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 24, 140, 120, 32, g_hwnd.load(),
                                       reinterpret_cast<HMENU>(1), ThisModule(), nullptr);
    }

    void BootWebView()
    {
        UiOperation operation;
        if (g_closeRequested.load() || g_hwnd.load() == nullptr)
        {
            return;
        }
        g_deferredFailure = false;
        try
        {
            StartWebView();
        }
        catch (...)
        {
            lifecycle_.Check(kncore::UiStep::EnvironmentRequest, E_OUTOFMEMORY);
            QueueFailure();
        }
    }

    void StartWebView()
    {
        TeardownWebView();
        lifecycle_.Begin();
        InvalidateDocument();
        if (documentToken_.empty())
        {
            lifecycle_.Check(kncore::UiStep::ResourceStream, E_UNEXPECTED);
            QueueFailure();
            return;
        }
        ArmBootWatchdog();
        RemovePropW(g_hwnd.load(), L"KNDbgX.FailedStage");
        RemovePropW(g_hwnd.load(), L"KNDbgX.NavigateCalls");
        if (failureText_ != nullptr)
        {
            DestroyWindow(failureText_);
            failureText_ = nullptr;
        }
        if (retryButton_ != nullptr)
        {
            DestroyWindow(retryButton_);
            retryButton_ = nullptr;
        }
        SetWindowTextW(g_hwnd.load(), kWindowTitle);
        std::wstring userDataFolder = ExpandLocalAppData(L"\\WebView2");
#ifdef _DEBUG
        // Isolate the owned test runtime from release debugger windows.
        userDataFolder += L"-Debug-" + std::to_wstring(GetCurrentProcessId());
#endif
        auto *handler = new (std::nothrow) EnvironmentCompletedHandler();
        HRESULT status = handler == nullptr ? E_OUTOFMEMORY : Inject(kncore::UiStep::EnvironmentRequest, S_OK);
        if (SUCCEEDED(status))
        {
            status = CreateCoreWebView2EnvironmentWithOptions(nullptr, userDataFolder.c_str(), nullptr, handler);
        }
        if (handler != nullptr)
        {
            handler->Release();
        }
        if (!lifecycle_.Check(kncore::UiStep::EnvironmentRequest, status))
        {
            QueueFailure();
        }
    }

    template <typename Handler, typename Add> HRESULT Register(Add add, EventRegistrationToken &token, unsigned bit)
    {
        auto *handler = new (std::nothrow) Handler();
        if (handler == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        const HRESULT status = add(handler, &token);
        handler->Release();
        if (SUCCEEDED(status))
        {
            registered_ |= bit;
        }
        return status;
    }

    HRESULT InstallStep(kncore::UiStep step)
    {
        if (g_closeRequested.load())
        {
            return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }
        const HRESULT injected = Inject(step, S_OK);
        if (FAILED(injected))
        {
            return injected;
        }
        using kncore::UiStep;
        switch (step)
        {
        case UiStep::CoreView:
        {
            const auto status = controller_->get_CoreWebView2(webview_.ReleaseAndGetAddressOf());
            return FAILED(status) ? status : webview_ != nullptr ? S_OK : E_POINTER;
        }
        case UiStep::Bounds:
        {
            RECT bounds = {};
            if (!GetClientRect(g_hwnd.load(), &bounds))
            {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            return controller_->put_Bounds(bounds);
        }
        case UiStep::Settings:
        {
            const auto status = webview_->get_Settings(settings_.ReleaseAndGetAddressOf());
            return FAILED(status) ? status : settings_ != nullptr ? S_OK : E_POINTER;
        }
        case UiStep::WebMessages:
            return settings_->put_IsWebMessageEnabled(TRUE);
        case UiStep::HostObjects:
            return settings_->put_AreHostObjectsAllowed(FALSE);
        case UiStep::ScriptDialogs:
            return settings_->put_AreDefaultScriptDialogsEnabled(FALSE);
        case UiStep::ContextMenus:
            return settings_->put_AreDefaultContextMenusEnabled(FALSE);
        case UiStep::StatusBar:
            return settings_->put_IsStatusBarEnabled(FALSE);
        case UiStep::DevTools:
#ifdef _DEBUG
            return settings_->put_AreDevToolsEnabled(TRUE);
#else
            return settings_->put_AreDevToolsEnabled(FALSE);
#endif
        case UiStep::ResourceFilter:
        {
            ComPtr<ICoreWebView2_22> sourceKinds;
            HRESULT capability = webview_.As(&sourceKinds);
#ifdef _DEBUG
            if (testResource_ == 5)
            {
                capability = E_NOINTERFACE;
            }
#endif
            if (SUCCEEDED(capability))
            {
                SetPropW(g_hwnd.load(), L"KNDbgX.ResourceFilterKind", reinterpret_cast<HANDLE>(1));
                return sourceKinds->AddWebResourceRequestedFilterWithRequestSourceKinds(L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                                                                                        COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL);
            }
            SetPropW(g_hwnd.load(), L"KNDbgX.ResourceFilterKind", reinterpret_cast<HANDLE>(2));
            return capability == E_NOINTERFACE ? webview_->AddWebResourceRequestedFilter(L"*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)
                                               : capability;
        }
        case UiStep::ResourceHandler:
            return Register<WebResourceRequestedHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_WebResourceRequested(handler, token);
                },
                resourceToken_, 1);
        case UiStep::MessageHandler:
            return Register<WebMessageReceivedHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_WebMessageReceived(handler, token);
                },
                messageToken_, 2);
        case UiStep::NavigationHandler:
            return Register<NavigationStartingHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_NavigationStarting(handler, token);
                },
                navigationToken_, 4);
        case UiStep::FrameHandler:
            return Register<FrameNavigationHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_FrameNavigationStarting(handler, token);
                },
                frameToken_, 8);
        case UiStep::NewWindowHandler:
            return Register<NewWindowHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_NewWindowRequested(handler, token);
                },
                newWindowToken_, 16);
        case UiStep::PermissionHandler:
            return Register<PermissionHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_PermissionRequested(handler, token);
                },
                permissionToken_, 32);
        case UiStep::ProcessHandler:
            return Register<ProcessFailedHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_ProcessFailed(handler, token);
                },
                processFailedToken_, 64);
        case UiStep::NavigationCompleteHandler:
            return Register<NavigationCompletedHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview_->add_NavigationCompleted(handler, token);
                },
                navigationCompletedToken_, 128);
        case UiStep::BrowserExitHandler:
        {
            const auto status = environment_.As(&environment5_);
            if (FAILED(status))
            {
                return status;
            }
            return Register<BrowserExitedHandler>(
                [&](auto *handler, auto *token)
                {
                    return environment5_->add_BrowserProcessExited(handler, token);
                },
                browserExitedToken_, 256);
        }
        case UiStep::DownloadHandler:
        {
            const auto status = webview_.As(&webview4_);
            if (FAILED(status))
            {
                return status;
            }
            return Register<DownloadHandler>(
                [&](auto *handler, auto *token)
                {
                    return webview4_->add_DownloadStarting(handler, token);
                },
                downloadToken_, 512);
        }
        case UiStep::Visible:
            return controller_->put_IsVisible(visible_ ? TRUE : FALSE);
        case UiStep::Navigate:
            SetPropW(g_hwnd.load(), L"KNDbgX.NavigateCalls", reinterpret_cast<HANDLE>(1));
            return webview_->Navigate(L"https://app.kndbgx.local/index.html");
        default:
            return E_INVALIDARG;
        }
    }

    void HandleWebResourceRequested(ICoreWebView2WebResourceRequestedEventArgs *args)
    {
        do
        {
            if (environment_ == nullptr || args == nullptr)
            {
                break;
            }

            ComPtr<ICoreWebView2WebResourceRequest> request;

            if (FAILED(args->get_Request(&request)) || request.Get() == nullptr)
            {
                break;
            }

            LPWSTR uri = nullptr;

            if (FAILED(request->get_Uri(&uri)) || uri == nullptr)
            {
                break;
            }

            const std::wstring path = AssetPathFromUri(uri);
            CoTaskMemFree(uri);

            if (path.empty())
            {
                RespondWithStatus(args, 403, L"Forbidden");
                break;
            }

            const AssetEntry *asset = nullptr;

            for (const AssetEntry &entry : kAssets)
            {
                if (_wcsicmp(path.c_str(), entry.Path) == 0)
                {
                    asset = &entry;
                    break;
                }
            }

            if (asset != nullptr)
            {
                RespondWithAsset(asset, args);
            }
            else
            {
                RespondWithStatus(args, 404, L"Not Found");
            }
        } while (false);
    }

    void RespondWithAsset(const AssetEntry *asset, ICoreWebView2WebResourceRequestedEventArgs *args, bool isolated = false)
    {
        auto step = kncore::UiStep::ResourceStream;
        HRESULT status = E_FAIL;
        do
        {
            std::string bytes;

            if (!ReadEmbeddedResource(asset->ResourceId, &bytes))
            {
                RespondWithStatus(args, 500, L"Resource Error");
                break;
            }

            if (bytes.empty())
            {
                RespondWithStatus(args, 500, L"Resource Error");
                break;
            }

            if (asset->ResourceId == IDR_KNDX_JS)
            {
                bytes = "window.knDbgXDocumentToken = " + knutil::WideToUtf8(knjson::Value(documentToken_).Write()) + ";\n" + bytes;
#ifdef _DEBUG
                if (testResource_ == 4)
                {
                    bytes = "// Injected missing frontend.\n";
                }
                if (testResource_ == 1)
                {
                    status = E_OUTOFMEMORY;
                    break;
                }
#endif
            }

            HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes.size());

            if (memory == nullptr)
            {
                break;
            }

            void *lockedMemory = GlobalLock(memory);

            if (lockedMemory == nullptr)
            {
                GlobalFree(memory);
                break;
            }

            memcpy(lockedMemory, bytes.data(), bytes.size());
            GlobalUnlock(memory);

            ComPtr<IStream> stream;
            HRESULT hr = CreateStreamOnHGlobal(memory, TRUE, &stream);

            if (FAILED(hr))
            {
                GlobalFree(memory);
                break;
            }

            ComPtr<ICoreWebView2WebResourceResponse> response;
            const std::wstring headers = std::wstring(L"Content-Type: ") + asset->ContentType + L"\r\nCache-Control: no-store";
            step = kncore::UiStep::ResourceResponse;
            hr = environment_->CreateWebResourceResponse(stream.Get(), 200, L"OK", headers.c_str(), &response);
#ifdef _DEBUG
            if (asset->ResourceId == IDR_KNDX_JS && testResource_ == 2)
            {
                hr = E_FAIL;
            }
#endif
            status = hr;
            if (SUCCEEDED(hr))
            {
                step = kncore::UiStep::ResourceDelivery;
                status = args->put_Response(response.Get());
#ifdef _DEBUG
                if (asset->ResourceId == IDR_KNDX_JS && testResource_ == 3)
                {
                    status = E_FAIL;
                }
#endif
            }
        } while (false);
        if (FAILED(status) && !isolated && lifecycle_.Phase != kncore::UiPhase::Failed)
        {
            lifecycle_.Check(step, status);
            QueueFailure();
        }
    }

    void RespondWithStatus(ICoreWebView2WebResourceRequestedEventArgs *args, int statusCode, const wchar_t *reason)
    {
        do
        {
            if (environment_ == nullptr || args == nullptr)
            {
                break;
            }

            ComPtr<ICoreWebView2WebResourceResponse> response;
            HRESULT hr = environment_->CreateWebResourceResponse(nullptr, statusCode, reason, L"", &response);

            if (SUCCEEDED(hr))
            {
                args->put_Response(response.Get());
            }
        } while (false);
    }

    void SendReply(knjson::Value reply, const knjson::Value &request)
    {
        reply.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
        reply.Set(L"requestId", request.Get(L"requestId"));
        reply.Set(L"uiGeneration", knjson::Value(std::to_wstring(g_navigationGeneration.load())));
        if (reply.Get(L"type").IsNull())
        {
            reply.Set(L"type", knjson::Value(L"completed"));
        }
        const HRESULT posted = webview_->PostWebMessageAsJson(reply.Write().c_str());
        if (FAILED(posted))
        {
            OutputDebugStringW(L"KNDbgX control reply transport failed; worker outcomes remain queryable.\n");
        }
    }

    void HandleWebMessageReceived(ICoreWebView2WebMessageReceivedEventArgs *args)
    {
        if (args == nullptr || webview_ == nullptr || !lifecycle_.MessagesAllowed())
        {
            return;
        }
        LPWSTR rawSource = nullptr;
        if (FAILED(args->get_Source(&rawSource)))
        {
            return;
        }
        const std::wstring source = rawSource != nullptr ? rawSource : L"";
        CoTaskMemFree(rawSource);
        if (!kncore::AppDocument(source))
        {
            return;
        }
        LPWSTR message = nullptr;
        if (FAILED(args->get_WebMessageAsJson(&message)) || message == nullptr)
        {
            return;
        }
        const size_t count = wcsnlen_s(message, 65537);
        const std::wstring json = count <= 65536 ? std::wstring(message, count) : L"";
        CoTaskMemFree(message);
        knjson::Value request;
        knjson::ParseLimits limits;
        limits.MaxInputUnits = 65536;
        limits.MaxStringUnits = 16384;
        limits.MaxNodes = 4096;
        std::wstring reason;
        if (!knjson::Parse(json, &request, limits) || !g_rpcGate.Accept(request, source, knutil::WideToUtf8(json).size(), reason))
        {
            auto reply = knjson::Value::MakeObject();
            reply.Set(L"ok", knjson::Value(false));
            reply.Set(L"error", knjson::Value(reason.empty() ? L"MalformedOrOversizedRpc" : reason));
            SendReply(reply, request);
            return;
        }
        const auto method = request.Get(L"method").AsString(L"");
        if (method == L"hello")
        {
            lifecycle_.AcceptedHandshake();
            PublishReady();
        }
        const HWND host = g_hwnd.load();
        const ULONG_PTR bit = method == L"catalog" ? 1 : method == L"status" ? 2 : 0;
        if (host != nullptr && bit != 0)
        {
            const auto mask = reinterpret_cast<ULONG_PTR>(GetPropW(host, L"KNDbgX.StartupRpcMask"));
            SetPropW(host, L"KNDbgX.StartupRpcMask", reinterpret_cast<HANDLE>(mask | bit));
        }
        if (method == L"inspectionWindow")
        {
            SendReply(ControlInspection(request.Get(L"params")), request);
            return;
        }
        if (method == L"interrupt")
        {
            const auto id = request.Get(L"params").Get(L"requestId").AsString(L"");
            const auto cancelled = g_operations.Cancel({g_windowGeneration.load(), g_navigationGeneration.load(), id});
            CancelOperation(cancelled);
            auto reply = knjson::Value::MakeObject();
            reply.Set(L"ok", knjson::Value(true));
            auto result = knjson::Value::MakeObject();
            result.Set(L"requested", knjson::Value(cancelled != nullptr));
            result.Set(L"completed", knjson::Value(false));
            reply.Set(L"result", result);
            SendReply(reply, request);
            return;
        }
        if (method == L"operationStatus" || method == L"operationAck" || method == L"operations")
        {
            const auto &params = request.Get(L"params");
            uint64_t cursor = 0;
            const bool validCursor = method != L"operations" || kncore::ParseUnsigned(params.Get(L"cursor").AsString(L""), 10, &cursor);
            auto result = method == L"operations"     ? (validCursor ? g_operations.Page(cursor) : knjson::Value())
                          : method == L"operationAck" ? knjson::Value(g_operations.Ack(params.Get(L"operationId").AsString(L"")))
                                                      : g_operations.Status({g_windowGeneration.load(), g_navigationGeneration.load(),
                                                                             params.Get(L"requestId").AsString(L"")},
                                                                            params.Get(L"operationId").AsString(L""));
            auto reply = knjson::Value::MakeObject();
            reply.Set(L"ok", knjson::Value(!result.IsNull()));
            reply.Set(L"result", result);
            if (result.IsNull())
            {
                reply.Set(L"error", knjson::Value(L"OperationUnknownOrExpired"));
            }
            if (method == L"operationAck" && result.AsBool(false) &&
                g_operations.Status({}, params.Get(L"operationId").AsString(L"")).Get(L"uiGeneration").AsString(L"") ==
                    std::to_wstring(g_navigationGeneration.load()))
            {
                SetPropW(host, L"KNDbgX.WorkerReplyAcknowledged", reinterpret_cast<HANDLE>(1));
            }
            SendReply(reply, request);
            return;
        }
        if (kncore::RpcNeedsWorker(method))
        {
            const auto accepted = EnqueueBridgeWork(request);
            auto reply = knjson::Value::MakeObject();
            reply.Set(L"ok", knjson::Value(accepted != nullptr));
            reply.Set(L"type", knjson::Value(accepted ? L"accepted" : L"completed"));
            if (!accepted)
            {
                reply.Set(L"error", knjson::Value(L"QueueFullOrClosing"));
            }
            else
            {
                reply.Set(L"operationId", knjson::Value(accepted->Id));
            }
            SendReply(reply, request);
            return;
        }
        const auto reply = knbridge::HandleRequest(request);
#ifdef _DEBUG
        if (method == L"breakExecution")
        {
            const bool requested = reply.Get(L"ok").AsBool(false) && reply.Get(L"result").Get(L"requested").AsBool(false);
            SetPropW(host, L"KNDbgX.BreakReply", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(requested ? 1 : 2)));
        }
#endif
        SendReply(reply, request);
    }

    void HandleNavigationStarting(ICoreWebView2NavigationStartingEventArgs *args)
    {
        if (args == nullptr)
        {
            return;
        }
        LPWSTR uri = nullptr;
        const bool read = SUCCEEDED(args->get_Uri(&uri));
        const bool allowed = read && uri != nullptr && kncore::AppDocument(uri);
        CoTaskMemFree(uri);
        if (!allowed)
        {
            args->put_Cancel(TRUE);
            return;
        }
        lifecycle_.NewDocument();
        InvalidateDocument();
        if (documentToken_.empty())
        {
            lifecycle_.Check(kncore::UiStep::ResourceStream, E_UNEXPECTED);
            QueueFailure();
            return;
        }
        ArmBootWatchdog();
    }

    void ArmBootWatchdog()
    {
        bootControl_ = g_webviewGeneration.load();
        bootDocument_ = g_navigationGeneration.load();
        bootDeadline_ = GetTickCount64() + 15000;
#ifdef _DEBUG
        if (testResource_ == 4)
        {
            bootDeadline_ = GetTickCount64() + 2000;
        }
#endif
        if (!SetTimer(g_hwnd.load(), kBootWatchdog, 250, nullptr))
        {
            lifecycle_.Check(kncore::UiStep::HandshakeTimeout, E_FAIL);
            QueueFailure();
        }
    }

    void CheckBootWatchdog()
    {
        if (g_closeRequested.load() || bootControl_ != g_webviewGeneration.load() || bootDocument_ != g_navigationGeneration.load() ||
            lifecycle_.Phase == kncore::UiPhase::Ready || lifecycle_.Phase == kncore::UiPhase::Failed)
        {
            KillTimer(g_hwnd.load(), kBootWatchdog);
        }
        else if (GetTickCount64() >= bootDeadline_)
        {
            KillTimer(g_hwnd.load(), kBootWatchdog);
            lifecycle_.Check(kncore::UiStep::HandshakeTimeout, HRESULT_FROM_WIN32(ERROR_TIMEOUT));
            QueueFailure();
        }
    }

    void PublishReady()
    {
        if (lifecycle_.Phase == kncore::UiPhase::Ready)
        {
            KillTimer(g_hwnd.load(), kBootWatchdog);
            SetPropW(g_hwnd.load(), L"KNDbgX.Ready", reinterpret_cast<HANDLE>(1));
            SetWindowTextW(g_hwnd.load(), kWindowTitle);
        }
    }

    void ProcessFailure(kncore::UiProcessFailure failure)
    {
        if (lifecycle_.Phase == kncore::UiPhase::Failed || lifecycle_.Phase == kncore::UiPhase::Closing)
        {
            return;
        }
        const HWND window = g_hwnd.load();
        SetPropW(window, L"KNDbgX.ProcessFailure", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(failure) + 1));
        const auto recovery = kncore::ProcessRecovery(failure);
        if (recovery == kncore::UiRecovery::RecreateControl)
        {
            lifecycle_.Check(kncore::UiStep::ProcessHandler, HRESULT_FROM_WIN32(ERROR_PROCESS_ABORTED));
            QueueFailure();
        }
        else if (recovery == kncore::UiRecovery::WaitForRenderer)
        {
            SetWindowTextW(window, L"KNDbgX - renderer unresponsive; requests are not replayed");
        }
        else
        {
            // The document and its JS request IDs survive these runtime failures.
            SetWindowTextW(window, L"KNDbgX - browser component recovering");
        }
    }

#ifdef _DEBUG
    LRESULT TestInspection(unsigned mode)
    {
        UiOperation operation;
        if (!testMode_ || webview_ == nullptr || lifecycle_.Phase != kncore::UiPhase::Ready)
        {
            return 0;
        }
        const HWND window = g_hwnd.load();
        const auto generation = g_navigationGeneration.load();
        RemovePropW(window, L"KNDbgX.InspectionChecked");
        if (mode == 22)
        {
            RECT client = {};
            POINT point = {};
            bool passed = false;
            HWND covering = nullptr;
            do
            {
                if (!GetClientRect(window, &client))
                {
                    break;
                }
                point = {client.right * 80 / 100, client.bottom / 2};
                if (!ClientToScreen(window, &point))
                {
                    break;
                }
                covering = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TRANSPARENT, kInspectionClassName, L"Dock occlusion probe",
                                           WS_POPUP, point.x - 20, point.y - 20, 80, 80, window, nullptr, ThisModule(), nullptr);
                if (covering == nullptr)
                {
                    break;
                }
                ShowWindow(covering, SW_SHOWNOACTIVATE);
                const HWND source = inspections_.at(L"").Window;
                const bool blocks = WindowFromPoint(point) == covering && InspectionDropAt(point, source).Window == nullptr;
                SetWindowLongPtrW(covering, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED);
                const bool layered = SetLayeredWindowAttributes(covering, 0, 128, LWA_ALPHA) != FALSE;
                passed = blocks && layered && WindowFromPoint(point) != covering && InspectionDropAt(point, source).Window == window;
            } while (false);
            if (covering != nullptr)
            {
                DestroyWindow(covering);
            }
            SetPropW(window, L"KNDbgX.InspectionChecked", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
            return 1;
        }
        if (mode == 7)
        {
            auto params = knjson::Value::MakeObject();
            params.Set(L"action", knjson::Value(L"show"));
            params.Set(L"token", knjson::Value(inspections_.at(L"").Token));
            params.Set(L"visibilityEpoch", knjson::Value(std::to_wstring(inspections_.at(L"").VisibilityEpoch)));
            HideInspectionFromFrame(inspections_.at(L""));
            const auto result = ControlInspection(params);
            const bool passed = !result.Get(L"ok").AsBool(true) && result.Get(L"error").AsString(L"") == L"InspectionVisibilityChanged" &&
                                !IsWindowVisible(inspections_.at(L"").Window);
            SetPropW(window, L"KNDbgX.InspectionChecked", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
            return 1;
        }
        const auto script = L"(() =>\n{\n    const mode = " + std::to_wstring(mode) + LR"(;
    if (mode >= 13)
    {
        const views = ['processes', 'memory', 'disassembly', 'registers'];
        if (mode === 13)
        {
            const nodes = ['processes', 'memory-view', 'disassembly-view', 'registers-view'].map(id => document.getElementById(id));
            const memory = document.getElementById('memory-address');
            window.knMixedInspectionProbe = { panel: document.getElementById('memory'), nodes, memory, value: memory.value,
                tab: document.querySelector('#inspection-tabs [aria-selected="true"]').id };
            memory.value = 'sample!PreservedMixedDraft';
            document.getElementById('btn-inspection-float').click();
            return true;
        }
        const saved = window.knMixedInspectionProbe;
        if (!saved)
        {
            return false;
        }
        const group = saved.panel.ownerDocument;
        if (mode === 14)
        {
            views.forEach(view => group.getElementById('btn-float-' + view).click());
            return true;
        }
        if (mode === 15)
        {
            return group !== document && new Set(saved.nodes.map(node => node.ownerDocument)).size === 4 &&
                saved.nodes.every(node => node.ownerDocument !== group && node.ownerDocument !== document) &&
                saved.memory.value === 'sample!PreservedMixedDraft' && !group.getElementById('btn-inspection-float').disabled;
        }
        if (mode === 16)
        {
            saved.memory.ownerDocument.getElementById('btn-float-memory').click();
            return true;
        }
        if (mode === 17)
        {
            return group !== document && saved.memory.ownerDocument === group &&
                saved.memory.value === 'sample!PreservedMixedDraft' && group.getElementById('tab-memory-view').getAttribute('aria-selected') === 'true';
        }
        if (mode === 18)
        {
            group.getElementById('btn-inspection-float').click();
            return true;
        }
        if (mode === 19)
        {
            return group === document && saved.nodes[1].ownerDocument === document &&
                saved.nodes.filter((_, index) => index !== 1).every(node => node.ownerDocument !== document);
        }
        if (mode === 20)
        {
            document.getElementById('btn-inspection-dock').click();
            return true;
        }
        if (document.getElementById('btn-stack').disabled || !saved.nodes.every(node => node.ownerDocument === document))
        {
            return false;
        }
        const passed = saved.memory.value === 'sample!PreservedMixedDraft';
        saved.memory.value = saved.value;
        document.getElementById(saved.tab).click();
        delete window.knMixedInspectionProbe;
        return passed;
    }
    if (mode >= 8)
    {
        const views = ['processes', 'memory', 'disassembly', 'registers'];
        const ids = ['processes', 'memory-view', 'disassembly-view', 'registers-view'];
        if (mode === 8)
        {
            const nodes = ids.map(id => document.getElementById(id));
            const memory = document.getElementById('memory-address');
            const code = document.getElementById('disassembly-address');
            window.knIndependentProbe = { nodes, memory, code, values: [memory.value, code.value],
                tab: document.querySelector('#inspection-tabs [aria-selected="true"]').id };
            memory.value = 'nt!KeBugCheckEx+10';
            code.value = 'nt!NtCreateFile';
            views.forEach(view => document.getElementById('btn-float-' + view).click());
            return true;
        }
        const saved = window.knIndependentProbe;
        if (!saved)
        {
            return false;
        }
        if (mode === 9 || mode === 10)
        {
            return saved.nodes.every((node, index) =>
            {
                const docked = mode === 10 && index === 1;
                return (node.ownerDocument === document) === docked &&
                    (docked || node.ownerDocument.defaultView.getComputedStyle(node.ownerDocument.body).display === 'flex');
            }) && saved.nodes[3].querySelector('#registers-rows').children.length > 0 &&
                new Set(saved.nodes.filter((_, index) => mode !== 10 || index !== 1).map(node => node.ownerDocument)).size === (mode === 9 ? 4 : 3) &&
                saved.memory.value === 'nt!KeBugCheckEx+10' && saved.code.value === 'nt!NtCreateFile';
        }
        if (mode === 11)
        {
            document.getElementById('btn-inspection-dock').click();
            return true;
        }
        const passed = !document.getElementById('btn-stack').disabled &&
            saved.nodes.every((node, index) => node === document.getElementById(ids[index])) &&
            saved.memory.value === 'nt!KeBugCheckEx+10' && saved.code.value === 'nt!NtCreateFile';
        if (!passed)
        {
            return false;
        }
        saved.memory.value = saved.values[0];
        saved.code.value = saved.values[1];
        document.getElementById(saved.tab).click();
        delete window.knIndependentProbe;
        return passed;
    }
    if (mode === 1)
    {
        const panel = document.getElementById('memory');
        const memory = document.getElementById('memory-address');
        const code = document.getElementById('disassembly-address');
        if (!panel || document.getElementById('btn-inspection-float').disabled)
        {
            return false;
        }
        window.knInspectionProbe = { panel, memory, code, values: [memory.value, code.value] };
        memory.value = 'nt!KeBugCheckEx+10';
        code.value = 'nt!NtCreateFile';
        document.getElementById('btn-inspection-float').click();
        return true;
    }
    const saved = window.knInspectionProbe;
    if (!saved)
    {
        return false;
    }
    const child = saved.panel.ownerDocument;
    if (mode === 2 || mode === 3)
    {
        return child !== document && child.getElementById('memory') === saved.panel &&
            child.getElementById('memory-address') === saved.memory &&
            child.getElementById('disassembly-address') === saved.code &&
            saved.memory.value === 'nt!KeBugCheckEx+10' && saved.code.value === 'nt!NtCreateFile' &&
            child.getElementById('btn-inspection-float').textContent === 'Dock' &&
            saved.panel.classList.contains('hidden') === (mode === 3) &&
            child.defaultView.getComputedStyle(child.body).display === 'flex';
    }
    if (mode === 4)
    {
        document.getElementById('btn-memory-panel').click();
        return true;
    }
    if (mode === 5)
    {
        child.getElementById('btn-inspection-float').click();
        return true;
    }
    const passed = document.getElementById('memory') === saved.panel &&
        document.getElementById('memory-address') === saved.memory &&
        document.getElementById('disassembly-address') === saved.code &&
        saved.memory.value === 'nt!KeBugCheckEx+10' && saved.code.value === 'nt!NtCreateFile' &&
        document.getElementById('btn-inspection-float').textContent === 'Float group';
    saved.memory.value = saved.values[0];
    saved.code.value = saved.values[1];
    delete window.knInspectionProbe;
    return passed;
})())";
        auto callback = Microsoft::WRL::Callback<ICoreWebView2ExecuteScriptCompletedHandler>(
            [window, generation](HRESULT status, LPCWSTR value)
            {
                if (g_hwnd.load() == window && g_navigationGeneration.load() == generation)
                {
                    const bool passed = SUCCEEDED(status) && value != nullptr && wcscmp(value, L"true") == 0;
                    SetPropW(window, L"KNDbgX.InspectionChecked", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
                }
                return S_OK;
            });
        return SUCCEEDED(webview_->ExecuteScript(script.c_str(), callback.Get()));
    }

    LRESULT TestWorkspace(unsigned mode)
    {
        UiOperation operation;
        if (!testMode_ || webview_ == nullptr || lifecycle_.Phase != kncore::UiPhase::Ready)
        {
            return 0;
        }
        const HWND window = g_hwnd.load();
        const auto generation = g_navigationGeneration.load();
        RemovePropW(window, L"KNDbgX.WorkspaceChecked");
        const auto script = L"(() =>\n{\n    const mode = " + std::to_wstring(mode) + LR"(;
    const tabs = document.getElementById('result-tabs');
    const rows = document.getElementById('result-rows');
    const view = document.getElementById('result-view');
    const capture = () => JSON.stringify([tabs.innerHTML, rows.innerHTML,
        document.getElementById('table-head').innerHTML,
        document.getElementById('result-table').getAttribute('aria-activedescendant'),
        view.scrollTop, view.scrollLeft]);
    if (mode === 1)
    {
        const active = tabs.querySelector('[role="tab"][aria-selected="true"]');
        if (!active || tabs.querySelectorAll('[role="tab"]').length < 2)
        {
            return false;
        }
        active.dispatchEvent(new KeyboardEvent('keydown', { key: 'F2', bubbles: true }));
        const editor = tabs.querySelector('.result-tab-name');
        if (!editor)
        {
            return false;
        }
        editor.value = 'Retained workspace';
        editor.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
        active.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', ctrlKey: true, shiftKey: true, bubbles: true }));
        window.knWorkspaceProbe = { document, tabs, rows, value: capture() };
        return !document.hidden;
    }
    const saved = window.knWorkspaceProbe;
    const current = capture();
    const sameDocument = !!saved && saved.document === document && saved.tabs === tabs && saved.rows === rows;
    const passed = sameDocument && saved.value === current && document.hidden === (mode === 2);
    if (passed)
    {
        return true;
    }
    const previousValues = saved ? JSON.parse(saved.value) : [];
    const currentValues = JSON.parse(current);
    const fields = ['tabs', 'rows', 'head', 'activeDescendant', 'scrollTop', 'scrollLeft'];
    return { passed: false, mode, sameDocument, hidden: document.hidden,
        changedFields: fields.filter((field, index) => previousValues[index] !== currentValues[index]),
        previousScroll: previousValues.slice(4), currentScroll: currentValues.slice(4) };
})())";
        auto callback = Microsoft::WRL::Callback<ICoreWebView2ExecuteScriptCompletedHandler>(
            [window, generation](HRESULT status, LPCWSTR value)
            {
                if (g_hwnd.load() == window && g_navigationGeneration.load() == generation)
                {
                    const bool passed = SUCCEEDED(status) && value != nullptr && wcscmp(value, L"true") == 0;
                    if (!passed && value != nullptr)
                    {
                        std::printf("test.workspace: %s\n", knutil::WideToUtf8(value).c_str());
                        std::fflush(stdout);
                    }
                    SetPropW(window, L"KNDbgX.WorkspaceChecked", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
                }
                return S_OK;
            });
        return SUCCEEDED(webview_->ExecuteScript(script.c_str(), callback.Get()));
    }

    LRESULT TestExecution(ULONG64 mode)
    {
        UiOperation operation;
        if (!testMode_ || webview_ == nullptr || lifecycle_.Phase != kncore::UiPhase::Ready)
        {
            return 0;
        }
        const HWND window = g_hwnd.load();
        if (mode > 5)
        {
            RemovePropW(window, L"KNDbgX.FollowChecked");
            const auto expected = knjson::Value(kncore::Hex(mode)).Write();
            const auto script = LR"((() =>
{
    const row = document.querySelector('#disassembly-rows .current-ip');
    const expected = )" + expected + LR"(;
    const passed = !!row && row.children[1].textContent === 'IP ' + expected && document.getElementById('btn-cancel').disabled &&
        !document.getElementById('btn-debug-over').disabled &&
        !document.getElementById('disassembly-summary').textContent.includes('previous snapshot');
    return { passed, address: row && row.children[1].textContent, expected,
        busy: !document.getElementById('btn-cancel').disabled,
        stepDisabled: document.getElementById('btn-debug-over').disabled,
        summary: document.getElementById('disassembly-summary').textContent,
        notice: document.getElementById('disassembly-notice').textContent,
        status: document.getElementById('status').textContent,
        follow: document.getElementById('btn-disassembly-follow').textContent };
})())";
            const auto generation = g_navigationGeneration.load();
            auto callback = Microsoft::WRL::Callback<ICoreWebView2ExecuteScriptCompletedHandler>(
                [window, generation](HRESULT status, LPCWSTR value)
                {
                    if (g_hwnd.load() == window && g_navigationGeneration.load() == generation)
                    {
                        knjson::Value observation;
                        const bool passed = SUCCEEDED(status) && value != nullptr && knjson::Parse(value, &observation) &&
                            observation.Get(L"passed").AsBool(false);
                        static std::wstring previous;
                        if (value != nullptr && previous != value)
                        {
                            previous = value;
                            std::printf("test.follow: %s\n", knutil::WideToUtf8(previous).c_str());
                            std::fflush(stdout);
                        }
                        SetPropW(window, L"KNDbgX.FollowChecked", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(passed ? 1 : 2)));
                    }
                    return S_OK;
                });
            return SUCCEEDED(webview_->ExecuteScript(script.c_str(), callback.Get()));
        }
        if (mode == 0)
        {
            return 0;
        }
        RemovePropW(window, L"KNDbgX.ExecutionReply");
        const std::wstring button = mode >= 4 ? L"btn-execution-toggle" :
                                    mode == 1 ? L"btn-debug-over" : mode == 2 ? L"btn-debug-into" : L"btn-debug-continue";
        const std::wstring action = mode == 4 ? L"continue" : mode == 5 ? L"break" : L"";
        const auto script = LR"((() =>
{
    const action = )" + knjson::Value(action).Write() + LR"(;
    if (action === 'continue')
    {
        document.getElementById('tab-memory-view').click();
    }
    let refreshed = action !== 'break';
    const statusObserver = new MutationObserver(() =>
    {
        refreshed = true;
    });
    if (!refreshed)
    {
        // A host wait publishes a new execution epoch after Continue was acknowledged.
        statusObserver.observe(document.getElementById('status'), { childList: true });
        document.getElementById('btn-refresh-status').click();
    }
    const follow = document.getElementById('btn-disassembly-follow');
    if (follow.getAttribute('aria-pressed') !== 'true')
    {
        follow.click();
    }
    let attempts = 0;
    const timer = setInterval(() =>
    {
        const button = document.getElementById()" + knjson::Value(button).Write() + LR"();
        if (++attempts > 500)
        {
            clearInterval(timer);
            statusObserver.disconnect();
            return;
        }
        if (refreshed && !button.disabled && (!action || button.dataset.action === action))
        {
            clearInterval(timer);
            statusObserver.disconnect();
            button.click();
        }
    }, 20);
})())";
        return SUCCEEDED(webview_->ExecuteScript(script.c_str(), nullptr));
    }

    LRESULT TestConsole()
    {
        UiOperation operation;
        if (!testMode_ || webview_ == nullptr || lifecycle_.Phase != kncore::UiPhase::Ready)
        {
            return 0;
        }
        RemovePropW(g_hwnd.load(), L"KNDbgX.ConsoleReply");
        const auto command = knjson::Value(L".echo KNDBGX_UI_HOST_FIRST; .printf \"KNDBGX_UI_HOST_SECOND:%d\\n\", 0n42").Write();
        const auto script = L"(() =>\n{\n    const command = " + command + LR"(;
    let attempts = 0;
    const timer = setInterval(() =>
    {
        if (++attempts > 500)
        {
            clearInterval(timer);
            return;
        }
        const prompt = document.getElementById('prompt');
        prompt.value = command;
        prompt.dispatchEvent(new Event('input'));
        const run = document.getElementById('btn-run');
        if (!run.disabled)
        {
            clearInterval(timer);
            run.click();
        }
    }, 20);
})())";
        return SUCCEEDED(webview_->ExecuteScript(script.c_str(), nullptr));
    }

    LRESULT TestBound(unsigned mode)
    {
        UiOperation operation;
        if (!testMode_ || webview_ == nullptr || lifecycle_.Phase != kncore::UiPhase::Ready)
        {
            return 0;
        }
        if (mode == 0)
        {
            g_testHoldBound.store(false);
            g_workCv.notify_all();
            return 1;
        }
        const auto results = kncore::Results().List();
        for (auto it = results.rbegin(); it != results.rend(); ++it)
        {
            if ((*it)->Data.CommandId != L"navigate")
            {
                continue;
            }
            g_testHoldBound.store(mode == 1);
            RemovePropW(g_hwnd.load(), L"KNDbgX.BoundReply");
            const auto script =
                L"(()=>{const id=" + knjson::Value((*it)->Id).Write() +
                LR"(;document.getElementById('result-id-input').value=id;document.getElementById('btn-result-load').click();let n=0;const t=setInterval(()=>{if(++n>250){clearInterval(t);return;}const rows=document.querySelector('#result-rows');if(!document.getElementById('result-summary').title.startsWith(id)||!rows.firstElementChild){return;}rows.firstElementChild.click();const b=document.getElementById('btn-navigate');if(!b.disabled){clearInterval(t);b.click();}},20);})())";
            return SUCCEEDED(webview_->ExecuteScript(script.c_str(), nullptr));
        }
        return 0;
    }

    LRESULT TestProcess(unsigned kind)
    {
        UiOperation operation;
        if (!testMode_ || environment_ == nullptr || webview_ == nullptr)
        {
            return 0;
        }
        RemovePropW(g_hwnd.load(), L"KNDbgX.ProcessFailure");
        if (kind == 100)
        {
            return SUCCEEDED(webview_->ExecuteScript(L"while (true) {}", nullptr));
        }
        ComPtr<ICoreWebView2Environment8> environment8;
        ComPtr<ICoreWebView2ProcessInfoCollection> processes;
        UINT count = 0;
        if (FAILED(environment_.As(&environment8)) || FAILED(environment8->GetProcessInfos(&processes)) || processes == nullptr ||
            FAILED(processes->get_Count(&count)))
        {
            return 0;
        }
        for (UINT i = 0; i < count; ++i)
        {
            ComPtr<ICoreWebView2ProcessInfo> process;
            INT32 id = 0;
            COREWEBVIEW2_PROCESS_KIND found = COREWEBVIEW2_PROCESS_KIND_BROWSER;
            if (FAILED(processes->GetValueAtIndex(i, &process)) || process == nullptr || FAILED(process->get_Kind(&found)) ||
                static_cast<unsigned>(found) != kind || FAILED(process->get_ProcessId(&id)) || id <= 0)
            {
                continue;
            }
            // Only an enumerated child of this process-isolated Debug environment.
            HANDLE owned = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(id));
            if (owned != nullptr)
            {
                const bool ended = TerminateProcess(owned, 37) != FALSE;
                CloseHandle(owned);
                return ended;
            }
        }
        return 0;
    }
#endif

    void TeardownWebView()
    {
        kncore::Results().SetUiPins({});
        ++g_webviewGeneration;
        CloseInspection();
        if (webview_ != nullptr)
        {
            if (registered_ & 1)
            {
                webview_->remove_WebResourceRequested(resourceToken_);
            }
            if (registered_ & 2)
            {
                webview_->remove_WebMessageReceived(messageToken_);
            }
            if (registered_ & 4)
            {
                webview_->remove_NavigationStarting(navigationToken_);
            }
            if (registered_ & 8)
            {
                webview_->remove_FrameNavigationStarting(frameToken_);
            }
            if (registered_ & 16)
            {
                webview_->remove_NewWindowRequested(newWindowToken_);
            }
            if (registered_ & 32)
            {
                webview_->remove_PermissionRequested(permissionToken_);
            }
            if (registered_ & 64)
            {
                webview_->remove_ProcessFailed(processFailedToken_);
            }
            if (registered_ & 128)
            {
                webview_->remove_NavigationCompleted(navigationCompletedToken_);
            }
        }
        if (environment5_ != nullptr && (registered_ & 256))
        {
            environment5_->remove_BrowserProcessExited(browserExitedToken_);
        }
        if (webview4_ != nullptr && (registered_ & 512))
        {
            webview4_->remove_DownloadStarting(downloadToken_);
        }
        registered_ = 0;
        settings_.Reset();
        webview4_.Reset();
        webview_.Reset();
        if (controller_ != nullptr)
        {
            controller_->Close();
        }
        controller_.Reset();
        environment5_.Reset();
        environment_.Reset();
    }

    static LRESULT CALLBACK InspectionWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        auto *app = Instance();
        auto *inspection = app->FindInspectionWindow(hwnd);
        switch (message)
        {
        case WM_NCLBUTTONDOWN:
        {
            UiOperation operation;
            if (wParam != HTCAPTION)
            {
                return DefWindowProcW(hwnd, message, wParam, lParam);
            }
            // Track the initiating message; a fast release can precede WM_MOVING dispatch.
            app->inspectionMouseMove_ = hwnd;
            const LRESULT result = DefWindowProcW(hwnd, message, wParam, lParam);
            if (app->inspectionMouseMove_ == hwnd)
            {
                app->inspectionMouseMove_ = nullptr;
            }
            return result;
        }
        case WM_ENTERSIZEMOVE:
        {
            UiOperation operation;
            if (inspection != nullptr)
            {
                app->BeginInspectionDrag(*inspection);
            }
            return 0;
        }
        case WM_MOVING:
        {
            UiOperation operation;
            app->MoveInspectionDrag(hwnd);
            return TRUE;
        }
        case WM_EXITSIZEMOVE:
        {
            UiOperation operation;
            app->EndInspectionDrag(hwnd);
            return 0;
        }
        case WM_CANCELMODE:
        {
            UiOperation operation;
            if (app->inspectionDrag_.Window == hwnd)
            {
                app->CancelInspectionDrag();
            }
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }
        case WM_CLOSE:
        {
            UiOperation operation;
            if (inspection != nullptr)
            {
                app->HideInspectionFromFrame(*inspection);
            }
            return 0;
        }
        case WM_SIZE:
        {
            UiOperation operation;
            if (inspection != nullptr && inspection->Controller != nullptr)
            {
                RECT bounds = {};
                GetClientRect(hwnd, &bounds);
                inspection->Controller->put_Bounds(bounds);
            }
            return 0;
        }
        case WM_GETMINMAXINFO:
        {
            auto *limits = reinterpret_cast<MINMAXINFO *>(lParam);
            limits->ptMinTrackSize.x = 360;
            limits->ptMinTrackSize.y = 280;
            return 0;
        }
        case WM_SETFOCUS:
        {
            UiOperation operation;
            if (inspection != nullptr && inspection->Controller != nullptr)
            {
                inspection->Controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
            }
            return 0;
        }
        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }
    }

    static LRESULT CALLBACK WindowProcThunk(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_APP_SHOW:
            Instance()->SetVisible(true);
            return 0;

        case WM_APP_UI_FAILED:
            g_deferredFailure = true;
            if (g_uiOperationDepth == 0)
            {
                g_deferredFailure = false;
                Instance()->DisplayFailure();
            }
            return 0;

        case WM_TIMER:
            if (wParam == kBootWatchdog)
            {
                Instance()->CheckBootWatchdog();
            }
            return 0;

        case WM_APP_CLOSE_INSPECTION:
            if (auto *inspection = Instance()->FindInspection(static_cast<uint64_t>(wParam)))
            {
                inspection->Closing = true;
                g_deferredInspectionClose = true;
                if (g_uiOperationDepth == 0)
                {
                    Instance()->CloseQueuedInspections();
                }
            }
            return 0;

        case WM_APP_DRAIN_UI:
            if (g_uiOperationDepth != 0)
            {
                return 0;
            }
            if (g_deferredClose)
            {
                g_deferredClose = g_deferredBoot = g_deferredFailure = false;
                DestroyWindow(hwnd);
                g_hwnd.store(nullptr);
            }
            else if (g_deferredBoot)
            {
                g_deferredBoot = false;
                Instance()->BootWebView();
            }
            else if (g_deferredFailure)
            {
                g_deferredFailure = false;
                Instance()->DisplayFailure();
            }
            if (g_deferredInspectionClose)
            {
                Instance()->CloseQueuedInspections();
            }
            return 0;

        case WM_COMMAND:
            if (LOWORD(wParam) == 1 && Instance()->lifecycle_.Phase == kncore::UiPhase::Failed)
            {
                g_deferredBoot = true;
                PostMessageW(hwnd, WM_APP_DRAIN_UI, 0, 0);
            }
            return 0;
#ifdef _DEBUG
        case WM_APP_TEST_DELIVERY:
            if (Instance()->testMode_ && Instance()->webview_ != nullptr && Instance()->lifecycle_.Phase == kncore::UiPhase::Ready)
            {
                UiOperation operation;
                g_testDeliveryFault.store(static_cast<unsigned>(wParam));
                RemovePropW(hwnd, L"KNDbgX.WorkerReplyAcknowledged");
                RemovePropW(hwnd, L"KNDbgX.DeliveryFault");
                RemovePropW(hwnd, L"KNDbgX.WorkerStarts");
                return SUCCEEDED(Instance()->webview_->ExecuteScript(L"document.getElementById('btn-refresh-status').click()", nullptr));
            }
            return 0;
        case WM_APP_TEST_RESOURCE:
            if (Instance()->testMode_)
            {
                Instance()->testResource_ = static_cast<unsigned>(wParam);
                g_deferredBoot = true;
                PostMessageW(hwnd, WM_APP_DRAIN_UI, 0, 0);
                return 1;
            }
            return 0;
        case WM_APP_TEST_REINIT:
            if (Instance()->testMode_)
            {
                Instance()->testFailure_ = static_cast<unsigned>(wParam);
                g_deferredBoot = true;
                PostMessageW(hwnd, WM_APP_DRAIN_UI, 0, 0);
                return 1;
            }
            return 0;
        case WM_APP_TEST_PROCESS:
            return Instance()->TestProcess(static_cast<unsigned>(wParam));
        case WM_APP_TEST_BOUND:
            return Instance()->TestBound(static_cast<unsigned>(wParam));
        case WM_APP_TEST_CONSOLE:
            return Instance()->TestConsole();
        case WM_APP_TEST_EXECUTION:
            return Instance()->TestExecution(static_cast<ULONG64>(wParam));
        case WM_APP_TEST_WORKSPACE:
            return Instance()->TestWorkspace(static_cast<unsigned>(wParam));
        case WM_APP_TEST_VISIBILITY:
            if (Instance()->testMode_ && Instance()->controller_ != nullptr && Instance()->lifecycle_.Phase == kncore::UiPhase::Ready)
            {
                Instance()->testFailure_ = static_cast<unsigned>(kncore::UiStep::Visible) + 1;
                Instance()->SetVisible(wParam != 0);
                return 1;
            }
            return 0;
        case WM_APP_TEST_INSPECTION:
            return Instance()->TestInspection(static_cast<unsigned>(wParam));
        case WM_APP_TEST_READ:
        {
            UiOperation operation;
            if (Instance()->testMode_ && Instance()->webview_ != nullptr && Instance()->lifecycle_.Phase == kncore::UiPhase::Ready)
            {
                RemovePropW(hwnd, L"KNDbgX.WorkerReplyPosted");
                RemovePropW(hwnd, L"KNDbgX.WorkerReplyAcknowledged");
                return SUCCEEDED(Instance()->webview_->ExecuteScript(L"document.getElementById('btn-refresh-status').click()", nullptr));
            }
            return 0;
        }
#endif
        case WM_CLOSE:
            Instance()->SetVisible(false);
            return 0;

        case WM_APP_SHUTDOWN:
            Instance()->lifecycle_.Phase = kncore::UiPhase::Closing;
            g_threadState.store(2);
            g_closeRequested.store(true);
            StopBridgeWorker();
            if (g_uiOperationDepth != 0)
            {
                g_deferredClose = true;
            }
            else
            {
                g_deferredClose = g_deferredBoot = g_deferredFailure = false;
                DestroyWindow(hwnd);
                g_hwnd.store(nullptr);
            }
            return 0;

        case WM_APP_BRIDGE_REPLY:
        {
            UiOperation operation;
            std::wstring payload;
            {
                std::lock_guard<std::mutex> lock(g_workMutex);
                const auto found = g_replies.find(static_cast<uint64_t>(wParam));
                if (found != g_replies.end())
                {
                    payload = std::move(found->second);
                    g_replies.erase(found);
                }
            }
            UiApp *app = Instance();
            if (!g_closeRequested.load() && app->webview_ != nullptr && !payload.empty())
            {
                knjson::Value delivered;
                const bool terminal = knjson::Parse(payload, &delivered) && delivered.Get(L"type").AsString(L"") == L"completed";
                unsigned fault = 0;
#ifdef _DEBUG
                if (terminal)
                {
                    fault = g_testDeliveryFault.exchange(0);
                    if (fault != 0)
                    {
                        SetPropW(hwnd, L"KNDbgX.DeliveryFault", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(fault)));
                    }
                }
#endif
                const HRESULT posted = fault == 1 ? E_FAIL : fault == 3 ? S_OK : app->webview_->PostWebMessageAsJson(payload.c_str());
                if (terminal)
                {
                    g_operations.Delivery(delivered.Get(L"operationId").AsString(L""), posted);
                    if (SUCCEEDED(posted) && delivered.Get(L"ok").AsBool(false))
                    {
                        SetPropW(hwnd, L"KNDbgX.WorkerReplyPosted", reinterpret_cast<HANDLE>(1));
                    }
                }
            }
            return 0;
        }

        case WM_SIZE:
        {
            UiOperation operation;
            UiApp *app = Instance();

            if (app->controller_ != nullptr)
            {
                RECT bounds;
                GetClientRect(hwnd, &bounds);
                app->controller_->put_Bounds(bounds);
            }

            return 0;
        }

        case WM_DESTROY:
            Instance()->failureText_ = Instance()->retryButton_ = nullptr;
            RemovePropW(hwnd, L"KNDbgX.Ready");
            RemovePropW(hwnd, L"KNDbgX.FailedStage");
            RemovePropW(hwnd, L"KNDbgX.NavigateCalls");
            RemovePropW(hwnd, L"KNDbgX.NavigationGeneration");
            RemovePropW(hwnd, L"KNDbgX.ProcessFailure");
            RemovePropW(hwnd, L"KNDbgX.BoundReply");
            RemovePropW(hwnd, L"KNDbgX.ConsoleReply");
            RemovePropW(hwnd, L"KNDbgX.ExecutionReply");
            RemovePropW(hwnd, L"KNDbgX.FollowChecked");
            RemovePropW(hwnd, L"KNDbgX.BoundHeld");
            RemovePropW(hwnd, L"KNDbgX.StartupRpcMask");
            RemovePropW(hwnd, L"KNDbgX.WorkerReplyPosted");
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }
    }

    // Event handler objects registered on the WebView2.
    class WebResourceRequestedHandler : public HandlerBase<ICoreWebView2WebResourceRequestedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *sender, ICoreWebView2WebResourceRequestedEventArgs *args) override
        {
            UiOperation operation;
            UNREFERENCED_PARAMETER(sender);
            if (Live())
            {
                UiApp::Instance()->HandleWebResourceRequested(args);
            }
            return S_OK;
        }
    };

    class WebMessageReceivedHandler : public HandlerBase<ICoreWebView2WebMessageReceivedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *sender, ICoreWebView2WebMessageReceivedEventArgs *args) override
        {
            UiOperation operation;
            UNREFERENCED_PARAMETER(sender);
            if (Live())
            {
                UiApp::Instance()->HandleWebMessageReceived(args);
            }
            return S_OK;
        }
    };

    class NavigationStartingHandler : public HandlerBase<ICoreWebView2NavigationStartingEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *sender, ICoreWebView2NavigationStartingEventArgs *args) override
        {
            UiOperation operation;
            UNREFERENCED_PARAMETER(sender);
            if (Live())
            {
                UiApp::Instance()->HandleNavigationStarting(args);
            }
            return S_OK;
        }
    };

    class FrameNavigationHandler : public HandlerBase<ICoreWebView2NavigationStartingEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *, ICoreWebView2NavigationStartingEventArgs *args) override
        {
            UiOperation operation;
            if (args != nullptr)
            {
                args->put_Cancel(TRUE);
            }
            return S_OK;
        }
    };
    class InspectionControllerHandler : public HandlerBase<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>
    {
      public:
        explicit InspectionControllerHandler(uint64_t generation) : generation_(generation)
        {
        }
        STDMETHODIMP Invoke(HRESULT status, ICoreWebView2Controller *controller) override
        {
            UiOperation operation;
            if (Live())
            {
                Instance()->InspectionCreated(generation_, status, controller);
            }
            else if (controller != nullptr)
            {
                controller->Close();
            }
            return S_OK;
        }
      private:
        uint64_t generation_;
    };
    class InspectionResourceHandler : public HandlerBase<ICoreWebView2WebResourceRequestedEventHandler>
    {
      public:
        explicit InspectionResourceHandler(uint64_t generation) : generation_(generation)
        {
        }
        STDMETHODIMP Invoke(ICoreWebView2 *sender, ICoreWebView2WebResourceRequestedEventArgs *args) override
        {
            UiOperation operation;
            auto *app = Instance();
            auto *inspection = app->FindInspection(generation_);
            if (args == nullptr || !Live() || inspection == nullptr || inspection->Closing || sender != inspection->View.Get())
            {
                return S_OK;
            }
            ComPtr<ICoreWebView2WebResourceRequest> request;
            LPWSTR raw = nullptr;
            if (SUCCEEDED(args->get_Request(&request)) && request != nullptr && SUCCEEDED(request->get_Uri(&raw)))
            {
                const std::wstring path = raw != nullptr ? AssetPathFromUri(raw) : L"";
                CoTaskMemFree(raw);
                for (const auto &asset : kAssets)
                {
                    if (asset.ResourceId == IDR_KNDX_CSS && path == asset.Path)
                    {
                        app->RespondWithAsset(&asset, args, true);
                        return S_OK;
                    }
                }
            }
            app->RespondWithStatus(args, 403, L"Forbidden");
            return S_OK;
        }
      private:
        uint64_t generation_;
    };
    class InspectionNavigationHandler : public HandlerBase<ICoreWebView2NavigationStartingEventHandler>
    {
      public:
        explicit InspectionNavigationHandler(uint64_t generation) : generation_(generation)
        {
        }
        STDMETHODIMP Invoke(ICoreWebView2 *sender, ICoreWebView2NavigationStartingEventArgs *args) override
        {
            UiOperation operation;
            auto *app = Instance();
            if (args != nullptr)
            {
                LPWSTR raw = nullptr;
                const bool read = SUCCEEDED(args->get_Uri(&raw));
                const std::wstring uri = raw != nullptr ? raw : L"";
                CoTaskMemFree(raw);
                auto *inspection = app->FindInspection(generation_);
                const bool allowed = Live() && inspection != nullptr && !inspection->Closing && sender == inspection->View.Get() && read &&
                                     (uri == L"about:blank" || uri == inspection->Uri);
                args->put_Cancel(allowed ? FALSE : TRUE);
            }
            return S_OK;
        }
      private:
        uint64_t generation_;
    };
    class InspectionCloseHandler : public HandlerBase<ICoreWebView2WindowCloseRequestedEventHandler>
    {
      public:
        explicit InspectionCloseHandler(uint64_t generation) : generation_(generation)
        {
        }
        STDMETHODIMP Invoke(ICoreWebView2 *sender, IUnknown *) override
        {
            UiOperation operation;
            auto *app = Instance();
            auto *inspection = app->FindInspection(generation_);
            if (Live() && inspection != nullptr && sender == inspection->View.Get())
            {
                app->QueueInspectionClose(*inspection);
            }
            return S_OK;
        }
      private:
        uint64_t generation_;
    };
    class NewWindowHandler : public HandlerBase<ICoreWebView2NewWindowRequestedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *sender, ICoreWebView2NewWindowRequestedEventArgs *args) override
        {
            UiOperation operation;
            if (Live())
            {
                UiApp::Instance()->OpenInspection(sender, args);
            }
            else if (args != nullptr)
            {
                args->put_Handled(TRUE);
            }
            return S_OK;
        }
    };
    class PermissionHandler : public HandlerBase<ICoreWebView2PermissionRequestedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *, ICoreWebView2PermissionRequestedEventArgs *args) override
        {
            UiOperation operation;
            if (args != nullptr)
            {
                args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
            }
            return S_OK;
        }
    };
    class DownloadHandler : public HandlerBase<ICoreWebView2DownloadStartingEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *, ICoreWebView2DownloadStartingEventArgs *args) override
        {
            UiOperation operation;
            if (args != nullptr)
            {
                args->put_Cancel(TRUE);
            }
            return S_OK;
        }
    };
    class ProcessFailedHandler : public HandlerBase<ICoreWebView2ProcessFailedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *, ICoreWebView2ProcessFailedEventArgs *args) override
        {
            UiOperation operation;
            if (Live())
            {
                COREWEBVIEW2_PROCESS_FAILED_KIND kind = COREWEBVIEW2_PROCESS_FAILED_KIND_UNKNOWN_PROCESS_EXITED;
                kncore::UiProcessFailure failure = kncore::UiProcessFailure::Unknown;
                if (args != nullptr && SUCCEEDED(args->get_ProcessFailedKind(&kind)))
                {
                    using kncore::UiProcessFailure;
                    switch (kind)
                    {
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED:
                        failure = UiProcessFailure::BrowserExited;
                        break;
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED:
                        failure = UiProcessFailure::RendererExited;
                        break;
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE:
                        failure = UiProcessFailure::RendererUnresponsive;
                        break;
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_FRAME_RENDER_PROCESS_EXITED:
                        failure = UiProcessFailure::FrameExited;
                        break;
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_GPU_PROCESS_EXITED:
                        failure = UiProcessFailure::GpuExited;
                        break;
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_UTILITY_PROCESS_EXITED:
                        failure = UiProcessFailure::UtilityExited;
                        break;
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_SANDBOX_HELPER_PROCESS_EXITED:
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_PPAPI_PLUGIN_PROCESS_EXITED:
                    case COREWEBVIEW2_PROCESS_FAILED_KIND_PPAPI_BROKER_PROCESS_EXITED:
                        failure = UiProcessFailure::OtherExited;
                        break;
                    default:
                        break;
                    }
                }
                UiApp::Instance()->ProcessFailure(failure);
            }
            return S_OK;
        }
    };
    class BrowserExitedHandler : public HandlerBase<ICoreWebView2BrowserProcessExitedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2Environment *, ICoreWebView2BrowserProcessExitedEventArgs *) override
        {
            UiOperation operation;
            if (Live())
            {
                UiApp::Instance()->ProcessFailure(kncore::UiProcessFailure::BrowserExited);
            }
            return S_OK;
        }
    };
    class NavigationCompletedHandler : public HandlerBase<ICoreWebView2NavigationCompletedEventHandler>
    {
      public:
        STDMETHODIMP Invoke(ICoreWebView2 *, ICoreWebView2NavigationCompletedEventArgs *args) override
        {
            UiOperation operation;
            if (Live())
            {
                auto *app = UiApp::Instance();
                BOOL success = FALSE;
                const HRESULT status = args != nullptr ? args->get_IsSuccess(&success) : E_POINTER;
                if (app->lifecycle_.Check(kncore::UiStep::Navigate, FAILED(status) ? status : success ? S_OK : E_FAIL))
                {
                    app->lifecycle_.DocumentLoaded();
                    app->PublishReady();
                }
                else
                {
                    app->QueueFailure();
                }
            }
            return S_OK;
        }
    };

    kncore::UiLifecycle lifecycle_;
    bool visible_ = true;
    std::wstring documentToken_;
    uint64_t bootControl_ = 0;
    uint64_t bootDocument_ = 0;
    ULONGLONG bootDeadline_ = 0;
    unsigned registered_ = 0;
    HICON largeIcon_ = nullptr;
    HICON smallIcon_ = nullptr;
    HWND failureText_ = nullptr;
    HWND retryButton_ = nullptr;
#ifdef _DEBUG
    unsigned testFailure_ = 0;
    unsigned testResource_ = 0;
    bool testMode_ = false;
#endif
    ComPtr<ICoreWebView2Environment5> environment5_;
    ComPtr<ICoreWebView2Settings> settings_;
    EventRegistrationToken browserExitedToken_{};
    ComPtr<ICoreWebView2Environment> environment_;
    ComPtr<ICoreWebView2Controller> controller_;
    ComPtr<ICoreWebView2> webview_;
    std::map<std::wstring, InspectionWindow> inspections_ = {
        {L"", {}}, {L"processes", {}}, {L"memory", {}}, {L"disassembly", {}}, {L"registers", {}}};
    uint64_t inspectionGeneration_ = 0;
    InspectionDrag inspectionDrag_;
    HWND inspectionMouseMove_ = nullptr;
    uint64_t inspectionDragSerial_ = 0;

    EventRegistrationToken resourceToken_{};
    EventRegistrationToken messageToken_{};
    EventRegistrationToken navigationToken_{};
    EventRegistrationToken frameToken_{}, newWindowToken_{}, permissionToken_{}, downloadToken_{}, processFailedToken_{},
        navigationCompletedToken_{};
    ComPtr<ICoreWebView2_4> webview4_;
};

namespace
{
DWORD WINAPI UiThreadProc(LPVOID parameter)
{
    const int exitCode = UiApp::Instance()->Run();
    g_hwnd.store(nullptr);
    g_threadState.store(0);
    FreeLibraryAndExitThread(static_cast<HMODULE>(parameter), static_cast<DWORD>(exitCode));
}
} // namespace

void ShowWindowAsyncSafe()
{
    long expected = 0;
    if (g_threadState.compare_exchange_strong(expected, 1))
    {
        g_closeRequested.store(false);
        ++g_windowGeneration;
        HMODULE lease = AcquireModuleLease();
        HANDLE thread = lease != nullptr ? CreateThread(nullptr, 0, UiThreadProc, lease, 0, nullptr) : nullptr;
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
        else
        {
            g_threadState.store(0);
            if (lease != nullptr)
            {
                FreeLibrary(lease);
            }
        }
    }
    else if (expected == 1)
    {
        const HWND existing = g_hwnd.load();
        if (existing != nullptr)
        {
            PostMessageW(existing, WM_APP_SHOW, 0, 0);
        }
    }
}

void ShutdownAsyncSafe()
{
    g_closeRequested.store(true);
    knengine::RequestCancellation(kncore::ExecutionDomain::Ui);
    const HWND hwnd = g_hwnd.load();
    if (hwnd != nullptr)
    {
        PostMessageW(hwnd, WM_APP_SHUTDOWN, 0, 0);
    }
}

// Read-only integration telemetry; this export never calls the engine.
extern "C" __declspec(dllexport) ULONG64 KnDbgXLifecycleState()
{
    return static_cast<ULONG64>(g_threadState.load()) | (static_cast<ULONG64>(g_liveHandlers.load()) << 8) |
           (static_cast<ULONG64>(g_workerState.load()) << 24) | (static_cast<ULONG64>(g_cleanupStage.load()) << 32) |
           (static_cast<ULONG64>(g_closeRequested.load()) << 40);
}
} // namespace knui
