#include "EngineCore.h"
#include "ContextGuard.h"
#include "SessionEvents.h"

#include <dbgeng.h>

#include <atomic>
#include <cwctype>
#include <mutex>
#include <memory>

#include "../util/Text.h"
#include "../util/ArtifactWriter.h"
#include "../core/ReadTelemetry.h"

namespace knengine
{
namespace
{
kncore::EpochValue<ULONG64> contextDtb;
kncore::EpochValue<bool> breakCapability;
}
kncore::EpochTracker &Epochs()
{
    static kncore::EpochTracker epochs(knutil::UniqueSuffix());
    return epochs;
}

namespace
{
struct ObserverState
{
    std::atomic<bool> Stop{false};
    std::atomic<bool> Ready{false};
    std::atomic<bool> Finished{false};
    std::mutex InterruptMutex;
    IDebugControl4 *InterruptControl = nullptr;
};
class ObserverInterrupt
{
  public:
    ObserverInterrupt(ObserverState &state, IDebugControl4 *control) : state_(state)
    {
        std::lock_guard lock(state_.InterruptMutex);
        state_.InterruptControl = control;
        state_.Ready = true;
    }
    ~ObserverInterrupt()
    {
        std::lock_guard lock(state_.InterruptMutex);
        state_.Ready = false;
        state_.InterruptControl = nullptr;
    }
    ObserverInterrupt(const ObserverInterrupt &) = delete;
    ObserverInterrupt &operator=(const ObserverInterrupt &) = delete;

  private:
    ObserverState &state_;
};
struct ObserverTask
{
    std::shared_ptr<ObserverState> State;
    HMODULE Module = nullptr;
};
std::mutex observerMutex;
std::shared_ptr<ObserverState> observer;
std::atomic<uint64_t> observedBreakpointSequence{0};

DWORD WINAPI ObserveSession(void *parameter)
{
    HMODULE module = nullptr;
    {
        std::unique_ptr<ObserverTask> task(static_cast<ObserverTask *>(parameter));
        module = task->Module;
        const auto state = task->State;
        const HRESULT apartment = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        try
        {
            DbgSession session;
            if (SUCCEEDED(apartment) && !state->Stop.load() && session.Initialize(nullptr, true, &observedBreakpointSequence))
            {
                ObserverInterrupt interrupt(*state, session.Control());
                // Transient DispatchCallbacks failures (a KD connection
                // refresh is the observed live cause) must not kill the
                // observer: a dead observer permanently blocks mutations via
                // the SessionObserverReady gate. Retry with a pause and only
                // give up after sustained failure; a real session end also
                // arrives through the stop flag.
                unsigned consecutiveFailures = 0;
                while (!state->Stop.load())
                {
                    if (SUCCEEDED(session.Client()->DispatchCallbacks(100)))
                    {
                        consecutiveFailures = 0;
                        continue;
                    }
                    if (++consecutiveFailures >= 30)
                    {
                        break;
                    }
                    Sleep(1000);
                }
            }
        }
        catch (...)
        {
            // No engine call is retried after an observer failure.
            knlog::Write(L"SessionObserver: exited via exception");
        }
        state->Ready = false;
        knlog::Write(L"SessionObserver: exiting; invalidation gate closed for mutations");
        Epochs().TargetChanged();
        state->Finished = true;
        if (SUCCEEDED(apartment))
        {
            CoUninitialize();
        }
    }
    // Client destruction and C++ unwinding finish before the module pin drops.
    FreeLibraryAndExitThread(module, 0);
}
} // namespace

bool StartSessionObserver()
{
    std::lock_guard<std::mutex> lock(observerMutex);
    if (observer && !observer->Stop.load() && !observer->Finished.load())
    {
        return true;
    }
    auto task = std::make_unique<ObserverTask>();
    task->State = std::make_shared<ObserverState>();
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&ObserveSession), &task->Module))
    {
        return false;
    }
    const auto state = task->State;
    // Invalidate before the extension accepts work, not at asynchronous readiness.
    Epochs().TargetChanged();
    HANDLE thread = CreateThread(nullptr, 0, ObserveSession, task.get(), 0, nullptr);
    if (thread == nullptr)
    {
        FreeLibrary(task->Module);
        return false;
    }
    observer = state;
    task.release();
    CloseHandle(thread);
    return true;
}

void StopSessionObserver()
{
    std::lock_guard<std::mutex> lock(observerMutex);
    if (observer)
    {
        observer->Stop = true;
        observer->Ready = false;
        Epochs().TargetChanged();
    }
}

bool SessionObserverReady()
{
    std::lock_guard<std::mutex> lock(observerMutex);
    return observer && observer->Ready.load() && !observer->Stop.load();
}

std::optional<uint64_t> ObservedBreakpointSequence()
{
    std::lock_guard<std::mutex> lock(observerMutex);
    return observer && observer->Ready.load() && !observer->Stop.load() ?
               std::optional<uint64_t>(observedBreakpointSequence.load()) : std::nullopt;
}

void SetBreakCapability(const kncore::SessionStamp &stamp, bool supported)
{
    breakCapability.Set(supported, stamp);
}

bool RequestTargetBreak(const kncore::SessionStamp &expected)
{
    std::lock_guard observerLock(observerMutex);
    if (!observer)
    {
        return false;
    }
    std::lock_guard endpointLock(observer->InterruptMutex);
    if (!observer->Ready.load() || observer->Stop.load() || !observer->InterruptControl ||
        Epochs().Stamp() != expected || !breakCapability.Get(expected).value_or(false))
    {
        return false;
    }
    breakCapability.Clear();
    // SetInterrupt is documented as callable from any thread and returns immediately.
    // ACTIVE requests a target break; EXIT only cancels an engine wait.
    return observer->InterruptControl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) == S_OK;
}

// Collects engine output between Begin()/End() on the owning thread only,
// so no locking is required.
class OutputCapture : public IDebugOutputCallbacksWide
{
  public:
    OutputCapture() : refCount_(1), active_(false)
    {
    }

    virtual ~OutputCapture() = default;

    STDMETHODIMP QueryInterface(REFIID riid, void **out) override
    {
        if (out == nullptr)
        {
            return E_POINTER;
        }

        if (riid == __uuidof(IUnknown))
        {
            *out = static_cast<IUnknown *>(this);
            AddRef();
            return S_OK;
        }

        if (riid == __uuidof(IDebugOutputCallbacksWide))
        {
            *out = static_cast<IDebugOutputCallbacksWide *>(this);
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

    STDMETHODIMP Output(ULONG /*mask*/, PCWSTR text) override
    {
        do
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (!active_ || text == nullptr)
            {
                break;
            }

            constexpr size_t budget = 4 * 1024 * 1024;
            const size_t remaining = budget - buffer_.size();
            const size_t length = wcsnlen_s(text, remaining + 1);
            // Host extensions routinely print warnings on the error channel
            // (e.g. "***Error in InitTypeRead ..." from !powertriage); that text
            // is captured output, not a capture failure; docs specify Partial /
            // HostDiagnosticUnparsed whenever the engine accepted the command.
            // Only truncation beyond the capture budget fails the capture.
            failed_ = failed_ || length > remaining;
            buffer_.append(text, std::min(length, remaining));
        } while (false);

        return S_OK;
    }

    void Begin()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = true;
        failed_ = false;
        buffer_.clear();
    }

    bool End(std::wstring *captured)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = false;

        const size_t prefix = knutil::Utf16PrefixUnits(buffer_, buffer_.size());
        failed_ = failed_ || prefix != buffer_.size();
        buffer_.resize(prefix);

        if (captured != nullptr)
        {
            *captured = buffer_;
        }
        return !failed_;
    }

  private:
    bool failed_ = false;
    std::atomic<long> refCount_;
    std::mutex mutex_;
    bool active_;
    std::wstring buffer_;
};

DbgSession::DbgSession()
    : client_(nullptr), control_(nullptr), symbols_(nullptr), systemObjects_(nullptr), dataSpaces_(nullptr), capture_(nullptr),
      connected_(false)
{
}

DbgSession::~DbgSession()
{
    Shutdown();
}

bool DbgSession::Initialize(IDebugClient *seed, bool observeEvents, std::atomic<uint64_t> *breakpointSequence)
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    bool ok = false;

    do
    {
        if (client_ != nullptr)
        {
            ok = connected_;
            break;
        }

        capture_ = new OutputCapture();

        IDebugClient *ownedSeed = nullptr;
        IDebugClient *created = nullptr;
        HRESULT hr = S_OK;
        if (seed == nullptr)
        {
            hr = DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void **>(&ownedSeed));
            seed = ownedSeed;
        }
        if (SUCCEEDED(hr) && seed != nullptr)
        {
            hr = seed->CreateClient(&created);
        }
        if (SUCCEEDED(hr) && created != nullptr)
        {
            hr = created->QueryInterface(__uuidof(IDebugClient5), reinterpret_cast<void **>(&client_));
        }
        if (created != nullptr)
        {
            created->Release();
        }
        if (ownedSeed != nullptr)
        {
            ownedSeed->Release();
        }
        if (FAILED(hr) || client_ == nullptr)
        {
            break;
        }

        // Prefer the widest control revision available on this runtime.
        hr = client_->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<void **>(&control_));

        if (FAILED(hr) || control_ == nullptr)
        {
            break;
        }

        hr = client_->QueryInterface(__uuidof(IDebugSymbols3), reinterpret_cast<void **>(&symbols_));

        if (FAILED(hr) || symbols_ == nullptr)
        {
            break;
        }

        hr = client_->QueryInterface(__uuidof(IDebugSystemObjects4), reinterpret_cast<void **>(&systemObjects_));

        if (FAILED(hr) || systemObjects_ == nullptr)
        {
            break;
        }

        hr = client_->QueryInterface(__uuidof(IDebugDataSpaces4), reinterpret_cast<void **>(&dataSpaces_));

        if (FAILED(hr) || dataSpaces_ == nullptr)
        {
            break;
        }

        if (observeEvents)
        {
            events_ = new SessionEvents(Epochs(), breakpointSequence);
            hr = client_->SetEventCallbacksWide(events_);
            if (FAILED(hr))
            {
                break;
            }
        }
        hr = client_->SetOutputCallbacksWide(capture_);

        if (FAILED(hr))
        {
            break;
        }

        const ULONG mask =
            DEBUG_OUTPUT_NORMAL | DEBUG_OUTPUT_ERROR | DEBUG_OUTPUT_WARNING | DEBUG_OUTPUT_EXTENSION_WARNING | DEBUG_OUTPUT_VERBOSE;

        client_->SetOutputMask(mask);

        // Deliberately NO ConnectSession here. In-process DebugCreate
        // clients already share the hosting engine instance and its
        // debuggee; ConnectSession is the remote-transport join API,
        // and calling it from an in-process client disturbs the live
        // session (observed as the kernel connection dropping).
        connected_ = SUCCEEDED(hr);
        ok = connected_;
    } while (false);

    if (!ok)
    {
        Shutdown();
    }

    return ok;
}

void DbgSession::Shutdown()
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    // Deliberately do NOT call EndSession: this client only joined the
    // host's session. Releasing our interfaces unregisters it without
    // touching session state owned by WinDbg.
    ReleaseAll();
}

kncore::TransferResult DbgSession::TransferMemory(kncore::AddressSpace space, bool write, ULONG64 address, void *buffer, ULONG length)
{
    auto *const telemetry = write ? nullptr : kncore::CurrentReadTelemetry;
    const auto readStart = telemetry ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
    kncore::ReadTiming timing;
    if (telemetry != nullptr)
    {
        FILETIME utc = {};
        GetSystemTimePreciseAsFileTime(&utc);
        timing.StartedUtc100ns = (uint64_t(utc.dwHighDateTime) << 32) | utc.dwLowDateTime;
        timing.ProcessId = GetCurrentProcessId();
        timing.ThreadId = GetCurrentThreadId();
    }
    const kncore::ObservedStage progress(kncore::OperationStage::MemoryIo);
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    kncore::TransferResult result;
    result.Requested = length;
    do
    {
        if (write && (!approvedWrite_ || space != kncore::AddressSpace::Virtual))
        {
            result.State = kncore::Status::Unavailable;
            result.Error.Message = L"PlanApprovalRequired";
            break;
        }
        if (Epochs().State() == kncore::SessionState::Faulted)
        {
            result.State = kncore::Status::InternalFault;
            break;
        }
        if (Cancelled())
        {
            result.State = kncore::Status::Cancelled;
            break;
        }
        if (!connected_ || dataSpaces_ == nullptr)
        {
            result.Error = {L"HRESULT", static_cast<uint32_t>(E_UNEXPECTED), L"MemoryTransfer", L"engine unavailable"};
            break;
        }
        if (buffer == nullptr || !kncore::ValidRange(address, length))
        {
            result.State = kncore::Status::InvalidInput;
            break;
        }
        const auto engineStart = telemetry ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        if (space == kncore::AddressSpace::Physical)
        {
            const auto primary = [&](size_t *transferred)
            {
                ULONG moved = 0;
                const HRESULT hr = write ? dataSpaces_->WritePhysical2(address, 0, buffer, length, &moved)
                                         : dataSpaces_->ReadPhysical2(address, 0, buffer, length, &moved);
                *transferred = moved;
                return static_cast<int32_t>(hr);
            };
            const auto legacy = [&](size_t *transferred)
            {
                ULONG moved = 0;
                const HRESULT hr = write ? dataSpaces_->WritePhysical(address, buffer, length, &moved)
                                         : dataSpaces_->ReadPhysical(address, buffer, length, &moved);
                *transferred = moved;
                return static_cast<int32_t>(hr);
            };
            result = kncore::PhysicalTransfer(length, primary, legacy);
        }
        else
        {
            ULONG moved = 0;
            const HRESULT hr = write ? dataSpaces_->WriteVirtual(address, buffer, length, &moved)
                                     : dataSpaces_->ReadVirtual(address, buffer, length, &moved);
            result = kncore::TransferStatus(length, moved, static_cast<int32_t>(hr));
        }
        result.Error.Operation = write ? L"WriteMemory" : L"ReadMemory";
        if (telemetry != nullptr)
        {
            timing.EngineElapsed = std::chrono::steady_clock::now() - engineStart;
        }
    } while (false);
    if (telemetry != nullptr)
    {
        telemetry->Observe(space, address, length, result, std::chrono::steady_clock::now() - readStart, timing);
    }
    return result;
}

knjson::Value DbgSession::MemoryCaptureInfo()
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    auto info = knjson::Value::MakeObject();
    info.Set(L"kind", knjson::Value(L"Unknown"));
    info.Set(L"class", knjson::Value());
    info.Set(L"qualifier", knjson::Value());
    info.Set(L"dumpFlags", knjson::Value());
    do
    {
        ULONG kind = 0;
        ULONG qualifier = 0;
        const HRESULT hr = connected_ && control_ != nullptr ? control_->GetDebuggeeType(&kind, &qualifier) : E_UNEXPECTED;
        info.Set(L"typeQueryHresult", knjson::Value(kncore::Hex(static_cast<uint32_t>(hr))));
        if (hr != S_OK)
        {
            break;
        }
        info.Set(L"class", knjson::Value(std::to_wstring(kind)));
        info.Set(L"qualifier", knjson::Value(std::to_wstring(qualifier)));
        const wchar_t *name = L"Unknown";
        if (kind == DEBUG_CLASS_KERNEL)
        {
            switch (qualifier)
            {
            case DEBUG_KERNEL_CONNECTION: name = L"KernelRemote"; break;
            case DEBUG_KERNEL_LOCAL: name = L"KernelLocal"; break;
            case DEBUG_KERNEL_EXDI_DRIVER: name = L"KernelExdi"; break;
            case DEBUG_KERNEL_SMALL_DUMP: name = L"KernelSmallDump"; break;
            case DEBUG_KERNEL_DUMP: name = L"KernelDump"; break;
            case DEBUG_KERNEL_FULL_DUMP: name = L"KernelCompleteDump"; break;
            case DEBUG_KERNEL_ACTIVE_DUMP: name = L"KernelActiveDump"; break;
            }
        }
        else if (kind == DEBUG_CLASS_USER_WINDOWS)
        {
            switch (qualifier)
            {
            case DEBUG_USER_WINDOWS_PROCESS: name = L"UserLive"; break;
            case DEBUG_USER_WINDOWS_PROCESS_SERVER: name = L"UserRemote"; break;
            case DEBUG_USER_WINDOWS_SMALL_DUMP: name = L"UserMinidump"; break;
            case DEBUG_USER_WINDOWS_DUMP: name = L"UserDump"; break;
            }
        }
        info.Set(L"kind", knjson::Value(name));
        if ((kind == DEBUG_CLASS_KERNEL || kind == DEBUG_CLASS_USER_WINDOWS) && qualifier >= DEBUG_DUMP_SMALL)
        {
            ULONG flags = 0;
            const HRESULT flagsHr = control_->GetDumpFormatFlags(&flags);
            info.Set(L"dumpFlagsHresult", knjson::Value(kncore::Hex(static_cast<uint32_t>(flagsHr))));
            if (flagsHr == S_OK)
            {
                info.Set(L"dumpFlags", knjson::Value(kncore::Hex(flags)));
            }
        }
    } while (false);
    return info;
}

kncore::ReadResult DbgSession::Read(kncore::AddressSpace space, uint64_t address, size_t length)
{
    kncore::ReadResult result;
    result.Space = space;
    result.Address = address;
    result.Requested = length;
    if (length > 64 * 1024 * 1024 || !kncore::ValidRange(address, length))
    {
        result.State = kncore::Status::InvalidInput;
    }
    else
    {
        result.Bytes.resize(length);
        const auto transfer = TransferMemory(space, false, address, result.Bytes.data(), static_cast<ULONG>(length));
        static_cast<kncore::TransferResult &>(result) = transfer;
        result.Valid.resize(length, 0);
        std::fill_n(result.Valid.begin(), transfer.Transferred, static_cast<unsigned char>(1));
    }
    return result;
}

bool DbgSession::ReadVirtual(ULONG64 address, void *buffer, ULONG length, ULONG *bytesRead)
{
    const auto result = TransferMemory(kncore::AddressSpace::Virtual, false, address, buffer, length);
    if (bytesRead != nullptr)
    {
        *bytesRead = static_cast<ULONG>(result.Transferred);
    }
    return result.State == kncore::Status::Success || result.State == kncore::Status::Partial;
}

bool DbgSession::ReadPhysical(ULONG64 address, void *buffer, ULONG length, ULONG *bytesRead)
{
    const auto result = TransferMemory(kncore::AddressSpace::Physical, false, address, buffer, length);
    if (bytesRead != nullptr)
    {
        *bytesRead = static_cast<ULONG>(result.Transferred);
    }
    return result.State == kncore::Status::Success || result.State == kncore::Status::Partial;
}

bool DbgSession::WriteVirtual(ULONG64 address, const void *buffer, ULONG length, ULONG *bytesWritten)
{
    const auto result = TransferMemory(kncore::AddressSpace::Virtual, true, address, const_cast<void *>(buffer), length);
    if (bytesWritten != nullptr)
    {
        *bytesWritten = static_cast<ULONG>(result.Transferred);
    }
    return result.State == kncore::Status::Success;
}

bool DbgSession::WritePhysical(ULONG64 address, const void *buffer, ULONG length, ULONG *bytesWritten)
{
    const auto result = TransferMemory(kncore::AddressSpace::Physical, true, address, const_cast<void *>(buffer), length);
    if (bytesWritten != nullptr)
    {
        *bytesWritten = static_cast<ULONG>(result.Transferred);
    }
    return result.State == kncore::Status::Success;
}

bool DbgSession::TranslateVirtual(ULONG64 virtualAddress, ULONG64 *physicalAddress)
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    bool ok = false;

    do
    {
        if (!connected_ || dataSpaces_ == nullptr || physicalAddress == nullptr)
        {
            break;
        }

        ULONG64 pa = 0;
        const HRESULT hr = dataSpaces_->VirtualToPhysical(virtualAddress, &pa);

        if (SUCCEEDED(hr))
        {
            *physicalAddress = pa;
            ok = true;
        }
    } while (false);

    return ok;
}

bool DbgSession::Evaluate(const std::wstring &expression, ULONG64 *value)
{
    SymbolQueryScope query;
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    bool ok = false;

    do
    {
        if (!connected_ || expression.empty() || value == nullptr || expression.find_first_of(L";{}\r\n") != std::wstring::npos)
        {
            break;
        }

        DEBUG_VALUE debugValue = {};
        ULONG remainder = 0;
        HRESULT hr = control_->EvaluateWide(expression.c_str(), DEBUG_VALUE_INT64, &debugValue, &remainder);

        if (FAILED(hr) || remainder > expression.size() || !knutil::Trim(expression.substr(remainder)).empty())
        {
            break;
        }

        switch (debugValue.Type)
        {
        case DEBUG_VALUE_INT64:
            *value = debugValue.I64;
            ok = true;
            break;
        case DEBUG_VALUE_INT32:
            *value = debugValue.I32;
            ok = true;
            break;
        case DEBUG_VALUE_INT16:
            *value = debugValue.I16;
            ok = true;
            break;
        case DEBUG_VALUE_INT8:
            *value = debugValue.I8;
            ok = true;
            break;
        default:
            break;
        }
    } while (false);

    return ok;
}

bool DbgSession::ReadRegisterHex(const std::wstring &registerName, ULONG64 *value)
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    bool ok = false;

    do
    {
        if (registerName.empty() || value == nullptr)
        {
            break;
        }

        IDebugRegisters2 *registers = nullptr;
        if (client_ == nullptr || FAILED(client_->QueryInterface(__uuidof(IDebugRegisters2), reinterpret_cast<void **>(&registers))))
        {
            break;
        }
        ULONG index = 0;
        DEBUG_VALUE native = {};
        HRESULT hr = registers->GetIndexByNameWide(registerName.c_str(), &index);
        if (SUCCEEDED(hr))
        {
            hr = registers->GetValue(index, &native);
        }
        registers->Release();
        if (FAILED(hr))
        {
            break;
        }
        switch (native.Type)
        {
        case DEBUG_VALUE_INT64:
            *value = native.I64;
            ok = true;
            break;
        case DEBUG_VALUE_INT32:
            *value = native.I32;
            ok = true;
            break;
        case DEBUG_VALUE_INT16:
            *value = native.I16;
            ok = true;
            break;
        case DEBUG_VALUE_INT8:
            *value = native.I8;
            ok = true;
            break;
        default:
            break;
        }
    } while (false);

    return ok;
}

bool DbgSession::ReadMsrValue(ULONG index, ULONG64 *value)
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    ULONG64 observed = 0;
    const bool ok = connected_ && dataSpaces_ != nullptr && value != nullptr && SUCCEEDED(dataSpaces_->ReadMsr(index, &observed));
    if (ok)
    {
        *value = observed;
    }
    return ok;
}

bool DbgSession::IsReady() const
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    return connected_;
}

IDebugClient5 *DbgSession::Client() const
{
    owner_.Require();
    return client_;
}

IDebugControl4 *DbgSession::Control() const
{
    owner_.Require();
    return control_;
}

IDebugSymbols3 *DbgSession::Symbols() const
{
    owner_.Require();
    return symbols_;
}

IDebugSystemObjects4 *DbgSession::SystemObjects() const
{
    owner_.Require();
    return systemObjects_;
}

kncore::ExecutionCoordinator &Coordinator()
{
    static kncore::ExecutionCoordinator coordinator;
    return coordinator;
}

bool RequestCancellation(kncore::ExecutionDomain domain)
{
    return Coordinator().Cancel(domain);
}

bool DbgSession::Cancelled() const
{
    return Coordinator().Cancelled();
}

void DbgSession::SetContextDtb(ULONG64 directoryTableBase)
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    Epochs().ContextChanged();
    contextDtb.Set(directoryTableBase, Epochs().Stamp());
}

void DbgSession::ClearContextDtb()
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    Epochs().ContextChanged();
    contextDtb.Clear();
}

bool DbgSession::HasContextDtb() const
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    return contextDtb.Get(Epochs().Stamp()).has_value();
}

ULONG64 DbgSession::ContextDtb() const
{
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    return contextDtb.Get(Epochs().Stamp()).value_or(0);
}

const wchar_t *SessionKindName(SessionKind kind)
{
    switch (kind)
    {
    case SessionKind::UserLive:
        return L"user live";
    case SessionKind::UserDump:
        return L"user dump";
    case SessionKind::KernelLocal:
        return L"kernel local";
    case SessionKind::KernelRemote:
        return L"kernel remote";
    case SessionKind::KernelDump:
        return L"kernel dump";
    default:
        return L"none";
    }
}

namespace
{
const wchar_t *ExecutionStatusName(ULONG status)
{
    switch (status & DEBUG_STATUS_MASK)
    {
    case DEBUG_STATUS_NO_DEBUGGEE:
        return L"no debuggee";
    case DEBUG_STATUS_BREAK:
        return L"break";
    case DEBUG_STATUS_GO:
        return L"go";
    case DEBUG_STATUS_GO_HANDLED:
        return L"go (handled)";
    case DEBUG_STATUS_GO_NOT_HANDLED:
        return L"go (not handled)";
    case DEBUG_STATUS_STEP_OVER:
        return L"step over";
    case DEBUG_STATUS_STEP_INTO:
        return L"step into";
    default:
        return L"unknown";
    }
}
} // namespace

void DbgSession::QueryStatus(SessionStatus *status)
{
    const kncore::ObservedStage progress(kncore::OperationStage::ContextQuery);
    if (status == nullptr)
    {
        return;
    }

    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    SessionStatus local = {};
    using RtlVersion = LONG(WINAPI *)(LPOSVERSIONINFOW);
    const auto version = reinterpret_cast<RtlVersion>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW host = {};
    host.dwOSVersionInfoSize = sizeof(host);
    if (version != nullptr && version(&host) == 0)
    {
        local.HostVersion =
            std::to_wstring(host.dwMajorVersion) + L"." + std::to_wstring(host.dwMinorVersion) + L"." + std::to_wstring(host.dwBuildNumber);
    }

    do
    {
        local.EngineReady = connected_;

        if (!connected_)
        {
            break;
        }

        ULONG debuggeeClass = 0;
        wchar_t targetVersion[512] = {};
        if (control_->GetSystemVersionStringWide(DEBUG_SYSVERSTR_BUILD, targetVersion, _countof(targetVersion), nullptr) == S_OK)
        {
            local.TargetVersion = targetVersion;
        }
        ULONG qualifier = 0;
        HRESULT hr = control_->GetDebuggeeType(&debuggeeClass, &qualifier);

        if (SUCCEEDED(hr))
        {
            local.TargetPresent = debuggeeClass != DEBUG_CLASS_UNINITIALIZED;
            local.Connected = local.TargetPresent;
            local.KernelMode = debuggeeClass == DEBUG_CLASS_KERNEL;
            local.DumpFile = qualifier >= 1024;
            local.LocalKernel = false;
            local.Kind = SessionKind::None;

            if (debuggeeClass == DEBUG_CLASS_KERNEL)
            {
                if (local.DumpFile)
                {
                    local.Kind = SessionKind::KernelDump;
                }
                else if (qualifier == DEBUG_KERNEL_LOCAL)
                {
                    local.Kind = SessionKind::KernelLocal;
                    local.LocalKernel = true;
                }
                else
                {
                    local.Kind = SessionKind::KernelRemote;
                }
            }
            else if (debuggeeClass == DEBUG_CLASS_USER_WINDOWS)
            {
                local.Kind = local.DumpFile ? SessionKind::UserDump : SessionKind::UserLive;
            }

            local.KindText = SessionKindName(local.Kind);
        }

        hr = symbols_->GetNumberModules(&local.ModulesLoaded, &local.ModulesUnloaded);

        if (FAILED(hr))
        {
            local.ModulesLoaded = 0;
            local.ModulesUnloaded = 0;
        }

        local.NtModuleResolved = false;
        for (const wchar_t *name : {L"nt", L"ntoskrnl", L"ntkrnlmp"})
        {
            ULONG index = DEBUG_ANY_ID;
            ULONG64 base = DEBUG_INVALID_OFFSET;
            if (symbols_->GetModuleByModuleNameWide(name, 0, &index, &base) == S_OK && index < local.ModulesLoaded &&
                base != 0 && base != DEBUG_INVALID_OFFSET)
            {
                local.NtModuleResolved = true;
                break;
            }
        }

        ULONG execution = 0;
        hr = control_->GetExecutionStatus(&execution);

        if (SUCCEEDED(hr))
        {
            local.Stopped = (execution & DEBUG_STATUS_MASK) == DEBUG_STATUS_BREAK;
            local.ExecutionStatusText = ExecutionStatusName(execution);
        }
        else
        {
            local.ExecutionStatusText = L"unavailable";
        }

        control_->GetActualProcessorType(&local.Architecture);
        std::wstring summary = knutil::Utf8ToWide("[kndbgx] session: ");

        summary += local.KindText.empty() ? (local.KernelMode ? (local.DumpFile ? L"kernel dump" : L"kernel live")
                                                              : (local.DumpFile ? L"user dump" : L"user live"))
                                          : local.KindText;

        summary += L", exec=";
        summary += local.ExecutionStatusText;
        summary += L", modules=" + std::to_wstring(local.ModulesLoaded);
        summary += L"/u" + std::to_wstring(local.ModulesUnloaded);
        summary += local.NtModuleResolved ? L", nt module present" : L", nt module not resolved";
        local.Summary = summary;
    } while (false);

    *status = local;
}

bool DbgSession::Execute(const std::wstring &commandLine, OutputRouting routing, std::wstring *captured)
{
    const kncore::ObservedStage progress(kncore::OperationStage::EngineCommand);
    owner_.Require();
    std::lock_guard<std::recursive_mutex> lock(ioLock_);
    bool ok = false;

    do
    {
        if (!connected_ || Cancelled())
        {
            break;
        }

        capture_->Begin();

        const ULONG outputControl = routing == OutputRouting::CaptureHere           ? DEBUG_OUTCTL_THIS_CLIENT
                                    : routing == OutputRouting::BroadcastAndCapture ? DEBUG_OUTCTL_ALL_CLIENTS
                                                                                    : DEBUG_OUTCTL_ALL_OTHER_CLIENTS;

        HRESULT hr = E_ABORT;
        {
            kncore::InterruptEndpoint endpoint(Coordinator(), control_,
                                               [](void *control)
                                               {
                                                   static_cast<IDebugControl4 *>(control)->SetInterrupt(DEBUG_INTERRUPT_EXIT);
                                               });
            if (!Cancelled())
            {
                hr = control_->ExecuteWide(outputControl, commandLine.c_str(), DEBUG_EXECUTE_DEFAULT);
            }
        }
        const bool capturedComplete = capture_->End(captured);
        ok = SUCCEEDED(hr) && capturedComplete;
    } while (false);

    return ok;
}

void DbgSession::ReleaseAll()
{
    owner_.Require();
    if (control_ != nullptr)
    {
        // Also cover native faults that bypass the Execute scope destructor.
        Coordinator().Disarm(control_);
    }
    if (client_ != nullptr)
    {
        client_->SetOutputCallbacksWide(nullptr);
        client_->SetEventCallbacksWide(nullptr);
    }

    if (dataSpaces_ != nullptr)
    {
        dataSpaces_->Release();
        dataSpaces_ = nullptr;
    }

    if (systemObjects_ != nullptr)
    {
        systemObjects_->Release();
        systemObjects_ = nullptr;
    }

    if (symbols_ != nullptr)
    {
        symbols_->Release();
        symbols_ = nullptr;
    }

    if (control_ != nullptr)
    {
        control_->Release();
        control_ = nullptr;
    }

    if (client_ != nullptr)
    {
        client_->Release();
        client_ = nullptr;
    }

    if (capture_ != nullptr)
    {
        capture_->Release();
        capture_ = nullptr;
    }

    if (events_ != nullptr)
    {
        events_->Release();
        events_ = nullptr;
    }
    connected_ = false;
}

kncore::SessionStamp DbgSession::RefreshStamp()
{
    const kncore::ObservedStage progress(kncore::OperationStage::ContextQuery);
    owner_.Require();
    if (!connected_)
    {
        return Epochs().Stamp();
    }
    kncore::TargetObservation observation;
    if (connected_)
    {
        ULONG kind = 0;
        ULONG qualifier = 0;
        ULONG execution = DEBUG_STATUS_NO_DEBUGGEE;
        observation.Present = SUCCEEDED(control_->GetDebuggeeType(&kind, &qualifier)) && kind != DEBUG_CLASS_UNINITIALIZED;
        observation.Kind = kind;
        observation.Qualifier = qualifier;
        control_->GetExecutionStatus(&execution);
        observation.Stopped = (execution & DEBUG_STATUS_MASK) == DEBUG_STATUS_BREAK;
        ULONG architecture = 0;
        control_->GetActualProcessorType(&architecture);
        observation.Architecture = architecture;
        if (observation.Present)
        {
            ULONG system = DEBUG_ANY_ID;
            ULONG process = DEBUG_ANY_ID;
            ULONG thread = DEBUG_ANY_ID;
            if (systemObjects_->GetCurrentSystemId(&system) == S_OK)
            {
                observation.Context.System = system;
            }
            if (systemObjects_->GetCurrentProcessId(&process) == S_OK)
            {
                observation.Context.Process = process;
            }
            if (systemObjects_->GetCurrentThreadId(&thread) == S_OK)
            {
                observation.Context.Thread = thread;
            }
            observation.System = system;
            observation.Process = process;
            observation.Thread = thread;
            ULONG64 offset = 0;
            ULONG effective = 0;
            if (systemObjects_->GetImplicitProcessDataOffset(&offset) == S_OK)
            {
                observation.Context.ImplicitProcess = offset;
            }
            if (systemObjects_->GetImplicitThreadDataOffset(&offset) == S_OK)
            {
                observation.Context.ImplicitThread = offset;
            }
            if (control_->GetEffectiveProcessorType(&effective) == S_OK)
            {
                observation.Context.EffectiveArchitecture = effective;
            }
            SymbolQueryScope passive;
            DEBUG_STACK_FRAME frame = {};
            if (symbols_->GetScope(&offset, &frame, nullptr, 0) == S_OK)
            {
                observation.Context.ScopeInstruction = offset;
                observation.Context.ScopeStack = frame.StackOffset;
                observation.Context.ScopeFrame = frame.FrameOffset;
                observation.Context.ScopeIndex = frame.FrameNumber;
            }
        }
    }
    Epochs().Observe(observation, InternalContextDepth != 0);
    return Epochs().Stamp();
}

void DbgSession::MarkFault()
{
    owner_.Require();
    Epochs().Fault();
}

bool DbgSession::ReadProcessorBlock(ULONG processor, ULONG64 *value)
{
    owner_.Require();
    ULONG read = 0;
    ULONG64 address = 0;
    const bool ok = value != nullptr && dataSpaces_ != nullptr &&
                    dataSpaces_->ReadProcessorSystemData(processor, DEBUG_DATA_KPRCB_OFFSET, &address, sizeof(address), &read) == S_OK &&
                    read == sizeof(address);
    if (ok)
    {
        *value = address;
    }
    return ok;
}

bool DbgSession::Reconnect(IDebugClient *seed)
{
    Shutdown();
    Epochs().Reconnect();
    return Initialize(seed);
}

bool ExecuteAdHoc(const std::wstring &commandLine)
{
    kncore::ExecutionLease lease(Coordinator());
    DbgSession session;
    return lease && session.Initialize() && session.Execute(commandLine, DbgSession::OutputRouting::AllOtherClients, nullptr);
}

bool QueryStatusAdHoc(SessionStatus *status)
{
    kncore::ExecutionLease lease(Coordinator());
    DbgSession session;
    const bool ok = lease && status != nullptr && session.Initialize();
    if (ok)
    {
        session.QueryStatus(status);
    }
    return ok;
}

void DbgSession::LockIo()
{
    owner_.Require();
    ioLock_.lock();
}

void DbgSession::UnlockIo()
{
    ioLock_.unlock();
}

ScopedIoLock::ScopedIoLock(DbgSession &session) : session_(&session)
{
    session_->LockIo();
}

ScopedIoLock::~ScopedIoLock()
{
    if (session_ != nullptr)
    {
        session_->UnlockIo();
    }
}
} // namespace knengine
