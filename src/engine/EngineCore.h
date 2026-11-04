#pragma once

// Each client, interface, callback and normal call belongs to one owner thread.
// CLI requests use a callback-local client. The UI executor owns its own client.
// Cancellation and target break use separately protected SetInterrupt endpoints.

#include <windows.h>

#include <mutex>
#include <string>
#include "../core/Result.h"
#include "../core/Execution.h"
#include "../core/Epochs.h"

struct IDebugClient;
struct IDebugClient5;
struct IDebugControl4;
struct IDebugSymbols3;
struct IDebugSystemObjects4;
struct IDebugDataSpaces4;

namespace kncmd
{
class MutationAdapter;
}

namespace knengine
{
enum class SessionKind
{
    None,
    UserLive,
    UserDump,
    KernelLocal,
    KernelRemote,
    KernelDump
};

const wchar_t *SessionKindName(SessionKind kind);

struct SessionStatus
{
    bool Connected;
    bool EngineReady;
    bool TargetPresent;
    bool Stopped;
    ULONG Architecture;
    bool KernelMode;
    bool DumpFile;
    bool LocalKernel;
    SessionKind Kind;
    unsigned long ModulesLoaded;
    unsigned long ModulesUnloaded;
    bool NtModuleResolved;
    std::wstring ExecutionStatusText;
    std::wstring KindText;
    std::wstring TargetVersion;
    std::wstring HostVersion;
    std::wstring Summary;
};

class OutputCapture;
class SessionEvents;
class ScopedIoLock;

class DbgSession : public kncore::TargetReader
{
  public:
    DbgSession();
    ~DbgSession();

    DbgSession(const DbgSession &) = delete;
    DbgSession &operator=(const DbgSession &) = delete;

    // Creates an owner-thread client from the host or an owner-thread seed.
    bool Initialize(IDebugClient *seed = nullptr, bool observeEvents = true, std::atomic<uint64_t> *breakpointSequence = nullptr);

    void Shutdown();
    bool IsReady() const;

    // Fills the status structure; safe to call when not connected.
    void QueryStatus(SessionStatus *status);

    enum class OutputRouting
    {
        // Stream to this client's callbacks only (captured, host silent).
        CaptureHere,

        // Stream to every other console client; our capture stays empty.
        AllOtherClients,

        // Stream to ALL clients: output appears in the hosting WinDbg
        // command window AND is captured for the UX mirror.
        BroadcastAndCapture
    };

    // Executes one raw command line. When routing is CaptureHere the
    // streamed output is collected into `captured`; when routing is
    // ToAllOtherClients the host consoles display it directly.
    bool Execute(const std::wstring &commandLine, OutputRouting routing, std::wstring *captured);

    // ---- primitives used by native command handlers ----

    bool ReadVirtual(ULONG64 address, void *buffer, ULONG length, ULONG *bytesRead);
    bool ReadPhysical(ULONG64 address, void *buffer, ULONG length, ULONG *bytesRead);
    bool WriteVirtual(ULONG64 address, const void *buffer, ULONG length, ULONG *bytesWritten);
    bool WritePhysical(ULONG64 address, const void *buffer, ULONG length, ULONG *bytesWritten);
    bool TranslateVirtual(ULONG64 virtualAddress, ULONG64 *physicalAddress);

    // Evaluates an expression (symbols, registers, arithmetic).
    bool Evaluate(const std::wstring &expression, ULONG64 *value);

    // Reads a register using the typed engine API.
    bool ReadRegisterHex(const std::wstring &registerName, ULONG64 *value);
    bool ReadMsrValue(ULONG index, ULONG64 *value);
    bool ReadProcessorBlock(ULONG processor, ULONG64 *value);
    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t length) override;
    knjson::Value MemoryCaptureInfo();

    bool Cancelled() const;
    kncore::SessionStamp RefreshStamp();
    void MarkFault();
    bool Reconnect(IDebugClient *seed = nullptr);

    // Optional process DTB override used by vtop / !address / procctx.
    void SetContextDtb(ULONG64 directoryTableBase);
    void ClearContextDtb();
    bool HasContextDtb() const;
    ULONG64 ContextDtb() const;

    IDebugClient5 *Client() const;
    IDebugControl4 *Control() const;
    IDebugSymbols3 *Symbols() const;
    IDebugSystemObjects4 *SystemObjects() const;

  private:
    kncore::TransferResult TransferMemory(kncore::AddressSpace space, bool write, ULONG64 address, void *buffer, ULONG length);
    friend class ScopedIoLock;
    friend class kncmd::MutationAdapter;
    void LockIo();
    void UnlockIo();
    void ReleaseAll();
    kncore::OwnerThread owner_;

    IDebugClient5 *client_;
    IDebugControl4 *control_;
    IDebugSymbols3 *symbols_;
    IDebugSystemObjects4 *systemObjects_;
    IDebugDataSpaces4 *dataSpaces_;
    OutputCapture *capture_;
    SessionEvents *events_ = nullptr;
    mutable std::recursive_mutex ioLock_;
    bool connected_;
    bool approvedWrite_ = false;
};

// ---- helpers usable from the engine thread or the UI thread ----

// Runs one raw command with output routed to all other clients.
bool ExecuteAdHoc(const std::wstring &commandLine);

// Builds a SessionStatus with an ad-hoc client on the calling thread.
bool QueryStatusAdHoc(SessionStatus *status);

kncore::ExecutionCoordinator &Coordinator();
bool RequestCancellation(kncore::ExecutionDomain domain = kncore::ExecutionDomain::Any);
kncore::EpochTracker &Epochs();
// The observer owns its client until cooperative shutdown completes.
bool StartSessionObserver();
void StopSessionObserver();
bool SessionObserverReady();
std::optional<uint64_t> ObservedBreakpointSequence();
// Only a checked live running target can use the observer's interrupt endpoint.
void SetBreakCapability(const kncore::SessionStamp &stamp, bool supported);
bool RequestTargetBreak(const kncore::SessionStamp &expected);

class ScopedIoLock
{
  public:
    explicit ScopedIoLock(DbgSession &session);
    ~ScopedIoLock();

    ScopedIoLock(const ScopedIoLock &) = delete;
    ScopedIoLock &operator=(const ScopedIoLock &) = delete;

  private:
    DbgSession *session_;
};
} // namespace knengine
