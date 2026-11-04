#include <Windows.h>
#include <winioctl.h>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>
#include "../Protocol.h"
#include "DeviceClientRegression.h"
#include "ServicePath.h"

namespace
{
using namespace knsnapshot;

struct HandleCloser
{
    void operator()(HANDLE value) const
    {
        if (value != INVALID_HANDLE_VALUE)
        {
            CloseHandle(value);
        }
    }
};
struct ServiceCloser
{
    void operator()(SC_HANDLE value) const
    {
        CloseServiceHandle(value);
    }
};
using Handle = std::unique_ptr<void, HandleCloser>;
using ServiceHandle = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceCloser>;
Handle g_ConsoleStop;
HANDLE g_StopEvent = nullptr;

bool CancellationRequested()
{
    return g_StopEvent != nullptr && WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0;
}

bool Win32Failure(const wchar_t *operation, DWORD error = GetLastError())
{
    std::fwprintf(stderr, L"%ls failed: Win32 %lu (0x%08lx).\n", operation, error, error);
    if (error == ERROR_INVALID_IMAGE_HASH)
    {
        std::fwprintf(stderr, L"Code integrity rejected this image. Check signing and the guest's CodeIntegrity log.\n");
    }
    return false;
}

Handle OpenPinnedFile(const std::wstring &path)
{
    return Handle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
}

bool SameFile(HANDLE expected, HANDLE actual)
{
    FILE_ID_INFO first = {};
    FILE_ID_INFO second = {};
    return GetFileInformationByHandleEx(expected, FileIdInfo, &first, sizeof(first)) &&
           GetFileInformationByHandleEx(actual, FileIdInfo, &second, sizeof(second)) && first.VolumeSerialNumber == second.VolumeSerialNumber &&
           std::memcmp(&first.FileId, &second.FileId, sizeof(first.FileId)) == 0;
}

class ServiceSession
{
  public:
    bool Prepare(const std::wstring &path, bool create)
    {
        if (CancellationRequested())
        {
            return Win32Failure(L"Service preparation cancelled", ERROR_CANCELLED);
        }
        expected_ = OpenPinnedFile(path);
        if (expected_.get() == INVALID_HANDLE_VALUE)
        {
            return Win32Failure(L"Open driver file");
        }
        std::vector<wchar_t> finalPath(32768);
        const DWORD count = GetFinalPathNameByHandleW(expected_.get(), finalPath.data(), static_cast<DWORD>(finalPath.size()), 0);
        wchar_t windowsDirectory[MAX_PATH] = {};
        const UINT windowsLength = GetWindowsDirectoryW(windowsDirectory, _countof(windowsDirectory));
        if (windowsLength == 0 || windowsLength >= _countof(windowsDirectory))
        {
            return Win32Failure(L"GetWindowsDirectory");
        }
        windowsDirectory_.assign(windowsDirectory, windowsLength);
        if (count == 0 || count >= finalPath.size() ||
            !ServiceImagePath(std::wstring_view(finalPath.data(), count), windowsDirectory_, canonicalPath_))
        {
            return Win32Failure(L"Resolve local driver path", ERROR_INVALID_NAME);
        }
        manager_.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager_)
        {
            return Win32Failure(L"OpenSCManager");
        }
        const DWORD access = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | (create ? SERVICE_START : DELETE);
        service_.reset(OpenServiceW(manager_.get(), ServiceName, access));
        if (!service_ && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST && create)
        {
            if (CancellationRequested())
            {
                return Win32Failure(L"Service creation cancelled", ERROR_CANCELLED);
            }
            manager_.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
            if (!manager_)
            {
                return Win32Failure(L"OpenSCManager(create)");
            }
            const auto quotedPath = L"\"" + canonicalPath_ + L"\"";
            service_.reset(CreateServiceW(manager_.get(), ServiceName, ServiceName, access | DELETE, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                         SERVICE_ERROR_NORMAL, quotedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
            created_ = static_cast<bool>(service_);
            if (!service_ && GetLastError() == ERROR_SERVICE_EXISTS)
            {
                service_.reset(OpenServiceW(manager_.get(), ServiceName, access));
            }
        }
        if (!service_)
        {
            return Win32Failure(L"Open or create driver service");
        }
        verified_ = VerifyConfiguredImage();
        return verified_;
    }

    bool Start()
    {
        if (CancellationRequested())
        {
            return Win32Failure(L"Driver start cancelled", ERROR_CANCELLED);
        }
        if (!VerifyConfiguredImage())
        {
            return false;
        }
        DWORD state = 0;
        if (!StableState(state, true))
        {
            return false;
        }
        if (state == SERVICE_STOPPED)
        {
            if (CancellationRequested())
            {
                return Win32Failure(L"Driver start cancelled", ERROR_CANCELLED);
            }
            if (StartServiceW(service_.get(), 0, nullptr))
            {
                started_ = true;
            }
            else if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            {
                return Win32Failure(L"StartService");
            }
            if (!StableState(state, true))
            {
                return false;
            }
        }
        if (state != SERVICE_RUNNING)
        {
            return Win32Failure(L"Driver did not reach Running", ERROR_SERVICE_NOT_ACTIVE);
        }
        std::wprintf(L"Service binary: %ls\nService created=%u started=%u by this run.\n", canonicalPath_.c_str(), created_, started_);
        return true;
    }

    bool Cleanup(bool explicitRemoval = false)
    {
        bool success = true;
        if (!service_)
        {
            return true;
        }
        if (!verified_ || !VerifyConfiguredImage())
        {
            std::fwprintf(stderr, L"Service identity could not be verified; service retained without stop or deletion.\n");
            return false;
        }
        DWORD state = 0;
        if (!StableState(state))
        {
            return false;
        }
        if ((started_ || explicitRemoval) && state == SERVICE_RUNNING)
        {
            SERVICE_STATUS status = {};
            if (!ControlService(service_.get(), SERVICE_CONTROL_STOP, &status))
            {
                return Win32Failure(L"Stop driver; service retained");
            }
            if (!StableState(state) || state != SERVICE_STOPPED)
            {
                return Win32Failure(L"Wait for driver stop; service retained", ERROR_TIMEOUT);
            }
        }
        if ((created_ || explicitRemoval) && state == SERVICE_STOPPED)
        {
            if (!VerifyConfiguredImage())
            {
                return false;
            }
            if (!DeleteService(service_.get()))
            {
                success = Win32Failure(L"DeleteService");
            }
            else
            {
                created_ = false;
                std::wprintf(L"Owned service deleted; the last service handle is closing.\n");
            }
        }
        else if (state == SERVICE_RUNNING)
        {
            std::wprintf(L"Running service outside this run's start ownership retained.\n");
            success = !created_;
        }
        else
        {
            std::wprintf(L"Pre-existing stopped service entry retained.\n");
        }
        service_.reset();
        return success;
    }

  private:
    bool VerifyConfiguredImage()
    {
        DWORD required = 0;
        const BOOL sized = QueryServiceConfigW(service_.get(), nullptr, 0, &required);
        if (sized || GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof(QUERY_SERVICE_CONFIGW) || required > 65536)
        {
            return Win32Failure(L"QueryServiceConfig(size)");
        }
        std::vector<unsigned char> storage(required);
        auto *configuration = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(storage.data());
        if (!QueryServiceConfigW(service_.get(), configuration, required, &required))
        {
            return Win32Failure(L"QueryServiceConfig");
        }
        std::wstring path;
        if (configuration->dwServiceType != SERVICE_KERNEL_DRIVER || configuration->lpBinaryPathName == nullptr ||
            !ServiceImagePath(configuration->lpBinaryPathName, windowsDirectory_, path))
        {
            return Win32Failure(L"Refuse service type or image path", ERROR_INVALID_DATA);
        }
        auto configured = OpenPinnedFile(path);
        if (configured.get() == INVALID_HANDLE_VALUE || !SameFile(expected_.get(), configured.get()))
        {
            return Win32Failure(L"Refuse service owned by another binary", ERROR_INVALID_DATA);
        }
        return true;
    }

    bool StableState(DWORD &state, bool allowCancellation = false)
    {
        const ULONGLONG deadline = GetTickCount64() + 15000;
        do
        {
            if (allowCancellation && CancellationRequested())
            {
                return Win32Failure(L"Service wait cancelled", ERROR_CANCELLED);
            }
            SERVICE_STATUS_PROCESS status = {};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(service_.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE *>(&status), sizeof(status), &bytes))
            {
                return Win32Failure(L"QueryServiceStatusEx");
            }
            state = status.dwCurrentState;
            if (state != SERVICE_START_PENDING && state != SERVICE_STOP_PENDING)
            {
                return true;
            }
            Sleep(100);
        }
        while (GetTickCount64() < deadline);
        return Win32Failure(L"Service transition deadline", ERROR_TIMEOUT);
    }

    Handle expected_;
    ServiceHandle manager_;
    ServiceHandle service_;
    std::wstring canonicalPath_;
    std::wstring windowsDirectory_;
    bool verified_ = false;
    bool created_ = false;
    bool started_ = false;
};

auto DeviceCall(HANDLE device)
{
    return [device](DWORD code, void *input, DWORD inputLength, void *output, DWORD outputLength) -> IoReply
    {
        DWORD returned = 0;
        const BOOL accepted = DeviceIoControl(device, code, input, inputLength, output, outputLength, &returned, nullptr);
        return {accepted != FALSE, accepted ? ERROR_SUCCESS : GetLastError(), returned};
    };
}

bool ReadState(HANDLE device, State &state, const Phase *phase = nullptr)
{
    auto call = DeviceCall(device);
    DWORD error = 0;
    if (!ReadDeviceState(call, state, error, phase))
    {
        return Win32Failure(L"Driver control or ABI response", error);
    }
    return true;
}

void PrintState(const State &state)
{
    std::wprintf(L"phase=%u mask=0x%02x generation=%llu operation=0x%08x cleanup=0x%08x registration=0x%08x\n",
                 static_cast<uint32_t>(state.ActivePhase), state.RegisteredMask, static_cast<unsigned long long>(state.Generation),
                 static_cast<uint32_t>(state.OperationStatus), static_cast<uint32_t>(state.CleanupStatus),
                 static_cast<uint32_t>(state.RegistrationStatus));
    for (unsigned bank = 0; bank < 2; ++bank)
    {
        std::wprintf(L"bank=%c process-pre=%llu thread-pre=%llu process-post=%llu thread-post=%llu all-pre=%llu\n", L'A' + bank,
                     static_cast<unsigned long long>(state.Events[bank][0]), static_cast<unsigned long long>(state.Events[bank][1]),
                     static_cast<unsigned long long>(state.Events[bank][2]), static_cast<unsigned long long>(state.Events[bank][3]),
                     static_cast<unsigned long long>(state.Events[bank][4]));
    }
}

bool TestDevice(HANDLE device)
{
    auto call = DeviceCall(device);
    return RunDeviceBoundaryTests(call,
                                  [](unsigned test, bool passed, DWORD error, DWORD returned)
                                  {
                                      std::wprintf(L"[device-test] case=%u pass=%u error=%lu returned=%lu\n", test, passed, error, returned);
                                  });
}

BOOL WINAPI ConsoleHandler(DWORD kind)
{
    if (kind == CTRL_C_EVENT || kind == CTRL_BREAK_EVENT || kind == CTRL_CLOSE_EVENT || kind == CTRL_LOGOFF_EVENT ||
        kind == CTRL_SHUTDOWN_EVENT)
    {
        SetEvent(g_StopEvent);
        return TRUE;
    }
    return FALSE;
}

class ConsoleControl
{
  public:
    bool Initialize()
    {
        g_ConsoleStop.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!g_ConsoleStop)
        {
            return Win32Failure(L"CreateEvent");
        }
        g_StopEvent = g_ConsoleStop.get();
        installed_ = SetConsoleCtrlHandler(ConsoleHandler, TRUE) != FALSE;
        if (!installed_)
        {
            g_StopEvent = nullptr;
            return Win32Failure(L"SetConsoleCtrlHandler");
        }
        return true;
    }

    ~ConsoleControl()
    {
        if (installed_)
        {
            SetConsoleCtrlHandler(ConsoleHandler, FALSE);
        }
        // Keep the event alive through process exit for already dispatched handlers.
    }

  private:
    bool installed_ = false;
};

bool Interactive(HANDLE device)
{
    DWORD consoleMode = 0;
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
    if (!GetConsoleMode(console, &consoleMode))
    {
        return Win32Failure(L"Interactive console required");
    }
    bool success = true;
    State state = {};
    std::wprintf(L"A: register bank A; B: replace with bank B; O: unregister; S: status; T: boundary tests; Q: quit.\n");
    std::wprintf(L"Capture a host snapshot while the guest is broken in KD. Resume the guest before using these keys.\n");
    HANDLE waits[] = {g_ConsoleStop.get(), console};
    while (true)
    {
        const DWORD ready = WaitForMultipleObjects(_countof(waits), waits, FALSE, INFINITE);
        if (ready == WAIT_OBJECT_0)
        {
            break;
        }
        if (ready != WAIT_OBJECT_0 + 1)
        {
            success = Win32Failure(L"Console wait");
            break;
        }
        INPUT_RECORD record = {};
        DWORD count = 0;
        if (!ReadConsoleInputW(console, &record, 1, &count))
        {
            success = Win32Failure(L"ReadConsoleInput");
            break;
        }
        if (count == 0 || record.EventType != KEY_EVENT || !record.Event.KeyEvent.bKeyDown)
        {
            continue;
        }
        const auto key = record.Event.KeyEvent.wVirtualKeyCode;
        if (key == 'Q')
        {
            break;
        }
        if (key == 'T')
        {
            success = TestDevice(device) && success;
        }
        else if (key == 'A' || key == 'B' || key == 'O' || key == 'S')
        {
            const Phase phase = key == 'A' ? Phase::A : key == 'B' ? Phase::B : Phase::Off;
            if (ReadState(device, state, key == 'S' ? nullptr : &phase))
            {
                PrintState(state);
                if (state.OperationStatus < 0 || state.CleanupStatus < 0)
                {
                    std::fwprintf(stderr, L"Callback operation incomplete. Inspect the statuses; use O to retry cleanup.\n");
                    success = false;
                }
            }
            else
            {
                success = false;
            }
        }
    }
    return success;
}

int SelfTest()
{
    unsigned failed = 0;
    const auto check = [&](bool ok, const wchar_t *name)
    {
        std::wprintf(L"[%ls] %ls\n", ok ? L"PASS" : L"FAIL", name);
        failed += ok ? 0 : 1;
    };
    std::wstring path;
    check(ServiceImagePath(L"\"C:\\test folder\\demo.sys\"", L"C:\\Windows", path) && path == L"C:\\test folder\\demo.sys",
          L"quoted local service path");
    check(ServiceImagePath(L"\\??\\C:\\demo.sys", L"C:\\Windows", path) && path == L"C:\\demo.sys", L"native DOS prefix");
    check(ServiceImagePath(L"\\SystemRoot\\System32\\drivers\\demo.sys", L"C:\\Windows", path) &&
              path == L"C:\\Windows\\System32\\drivers\\demo.sys",
          L"system root prefix");
    for (const auto *input : {L"demo.sys", L"\\\\server\\share\\demo.sys", L"\"C:\\demo.sys\" --other",
                             L"C:\\demo.sys --other", L"C:\\demo.exe", L"C:\\demo\nsys", L"\"\"", L"C:\\demo.sys:other.sys"})
    {
        check(!ServiceImagePath(input, L"C:\\Windows", path), L"reject unsupported service path");
    }
    check(sizeof(PhaseRequest) == 16 && sizeof(State) == 120 && offsetof(State, Events) == 40, L"shared x64 ABI");
    TestDeviceClient(check);
    {
        Handle cancellation(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        g_StopEvent = cancellation.get();
        check(cancellation && !CancellationRequested(), L"unsignaled startup cancellation permits admission");
        const bool signaled = cancellation && SetEvent(cancellation.get());
        check(signaled && CancellationRequested(), L"startup cancellation observed before service operations");
        g_StopEvent = nullptr;
    }
    wchar_t temporaryDirectory[MAX_PATH] = {};
    wchar_t firstPath[MAX_PATH] = {};
    wchar_t secondPath[MAX_PATH] = {};
    const DWORD temporaryLength = GetTempPathW(_countof(temporaryDirectory), temporaryDirectory);
    bool firstCreated = false;
    bool secondCreated = false;
    if (temporaryLength != 0 && temporaryLength < _countof(temporaryDirectory))
    {
        firstCreated = GetTempFileNameW(temporaryDirectory, L"kns", 0, firstPath) != 0;
        secondCreated = GetTempFileNameW(temporaryDirectory, L"kns", 0, secondPath) != 0;
    }
    {
        auto first = firstCreated ? OpenPinnedFile(firstPath) : Handle(INVALID_HANDLE_VALUE);
        auto alias = firstCreated ? OpenPinnedFile(firstPath) : Handle(INVALID_HANDLE_VALUE);
        auto second = secondCreated ? OpenPinnedFile(secondPath) : Handle(INVALID_HANDLE_VALUE);
        check(firstCreated && SameFile(first.get(), alias.get()), L"file identity accepts the same file");
        check(firstCreated && secondCreated && !SameFile(first.get(), second.get()), L"file identity rejects another file");
    }
    if (firstCreated)
    {
        check(DeleteFileW(firstPath) != FALSE, L"first identity fixture removed");
    }
    if (secondCreated)
    {
        check(DeleteFileW(secondPath) != FALSE, L"second identity fixture removed");
    }
    std::wprintf(L"Self-test failures=%u; no SCM or device access performed.\n", failed);
    return failed == 0 ? 0 : 1;
}
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && std::wstring_view(argv[1]) == L"--selftest")
    {
        return SelfTest();
    }
    if (argc < 2 || argc > 3 || (std::wstring_view(argv[1]) != L"run" && std::wstring_view(argv[1]) != L"remove"))
    {
        std::fwprintf(stderr, L"Usage: KnSnapshotDemoCtl.exe run|remove [absolute-driver-path]\n");
        return 2;
    }
    ConsoleControl console;
    if (!console.Initialize())
    {
        return 1;
    }
    std::vector<wchar_t> executable(32768);
    const DWORD count = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (count == 0 || count >= executable.size())
    {
        Win32Failure(L"GetModuleFileName");
        return 1;
    }
    const auto driverPath = argc == 3 ? std::filesystem::path(argv[2])
                                     : std::filesystem::path(executable.data()).parent_path() / L"KnSnapshotDemo.sys";
    const bool remove = std::wstring_view(argv[1]) == L"remove";
    ServiceSession service;
    bool success = service.Prepare(driverPath.wstring(), !remove);
    if (success && !remove)
    {
        success = service.Start();
        if (success)
        {
            Handle device(CreateFileW(UserDevice, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
            if (device.get() == INVALID_HANDLE_VALUE)
            {
                success = Win32Failure(L"Open exclusive demo device");
            }
            else
            {
                State state = {};
                success = ReadState(device.get(), state);
                if (success)
                {
                    PrintState(state);
                    success = Interactive(device.get());
                    const Phase off = Phase::Off;
                    const bool cleaned = ReadState(device.get(), state, &off) && state.ActivePhase == Phase::Off &&
                                         state.RegisteredMask == 0 && state.OperationStatus >= 0 && state.CleanupStatus >= 0;
                    success = cleaned && success;
                    if (!cleaned)
                    {
                        std::fwprintf(stderr, L"Cleanup could not be confirmed. Device close will request kernel cleanup.\n");
                    }
                }
            }
            // Device close triggers IRP_MJ_CLEANUP before SCM cleanup.
        }
    }
    if (remove && success && CancellationRequested())
    {
        success = Win32Failure(L"Service removal cancelled", ERROR_CANCELLED);
    }
    const bool cleaned = service.Cleanup(remove && success);
    return success && cleaned ? 0 : 1;
}
