#include <windows.h>
#include <dbgeng.h>
#include <new>
#include <DbgModel.h>
#include <wrl/client.h>
#include <atomic>
#include <array>
#include <cstdio>
#include <cstring>
#include <future>
#include <filesystem>
#include <mutex>
#include <string>
#include "../engine/EngineCore.h"
#include "../engine/ContextGuard.h"
#include "../engine/SessionEvents.h"
#include "../engine/LayoutResolver.h"
#include "../engine/SymbolHealth.h"
#include "../core/ScannerRules.h"
#include "../core/UiLifecycle.h"
#include "../core/Mutation.h"
#include "../util/Text.h"
#include "../util/FileReader.h"

using Microsoft::WRL::ComPtr;

class OwnedTargetEvents final : public DebugBaseEventCallbacksWide
{
  public:
    STDMETHOD_(ULONG, AddRef)() override
    {
        return ++references_;
    }
    STDMETHOD_(ULONG, Release)() override
    {
        const auto remaining = --references_;
        if (remaining == 0)
        {
            delete this;
        }
        return remaining;
    }
    STDMETHOD(GetInterestMask)(PULONG mask) override
    {
        *mask = DEBUG_EVENT_EXCEPTION | DEBUG_EVENT_BREAKPOINT;
        return S_OK;
    }
    STDMETHOD(Exception)(PEXCEPTION_RECORD64 exception, ULONG firstChance) override
    {
        std::printf("owned event exception=0x%08lx firstChance=%lu\n", exception->ExceptionCode, firstChance);
        return DEBUG_STATUS_BREAK;
    }
    STDMETHOD(Breakpoint)(PDEBUG_BREAKPOINT2) override
    {
        return DEBUG_STATUS_BREAK;
    }

  private:
    std::atomic<ULONG> references_{1};
};

extern "C" __declspec(dllexport) unsigned char KnFixtureBytes[8192] = {0x31, 0x31, 0x31, 0x31};
extern "C" __declspec(dllexport) void *KnFixturePointer = KnFixtureBytes;
extern "C" __declspec(dllexport) wchar_t KnMalformedString[] = {L'A', 0xd800, L'B', 0};
extern "C" __declspec(dllexport) unsigned char KnAnsiString[] = {0x41, 0x80, 0};
extern "C" __declspec(dllexport) unsigned char KnInstructionFixture[] = {0x90, 0x60, 0x90, 0xc3};
extern "C" __declspec(dllexport) constinit std::array<unsigned char, 4096> KnUnterminatedString = []()
{
    std::array<unsigned char, 4096> value;
    value.fill('A');
    return value;
}();
struct KN_LAYOUT_FIXTURE
{
    unsigned long Zero;
    unsigned long Flags : 3;
    unsigned long Remainder : 29;
    void *Buckets[37];
    long Signed;
    unsigned long Count;
};
extern "C" __declspec(dllexport) KN_LAYOUT_FIXTURE KnLayoutFixture = {};
struct KN_NESTED_LAYOUT_FIXTURE
{
    KN_LAYOUT_FIXTURE Embedded;
    KN_LAYOUT_FIXTURE Records[2][3];
    KN_LAYOUT_FIXTURE *Pointer;
};
extern "C" __declspec(dllexport) KN_NESTED_LAYOUT_FIXTURE KnNestedLayoutFixture = {};

namespace
{
int failures = 0;
void Check(bool ok, const char *name)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    std::fflush(stdout);
    if (!ok)
    {
        ++failures;
    }
}

class Capture final : public IDebugOutputCallbacksWide
{
  public:
    STDMETHOD(QueryInterface)(REFIID id, void **out) override
    {
        if (out == nullptr)
        {
            return E_POINTER;
        }
        *out = nullptr;
        if (id == __uuidof(IUnknown) || id == __uuidof(IDebugOutputCallbacksWide))
        {
            *out = this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHOD_(ULONG, AddRef)() override
    {
        return ++references_;
    }
    STDMETHOD_(ULONG, Release)() override
    {
        const auto remaining = --references_;
        if (remaining == 0)
        {
            delete this;
        }
        return remaining;
    }
    STDMETHOD(Output)(ULONG, PCWSTR text) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (text != nullptr && output_.size() < 1048576)
        {
            output_.append(text, wcsnlen_s(text, 1048576 - output_.size()));
        }
        return S_OK;
    }
    std::wstring Take()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring result;
        result.swap(output_);
        return result;
    }

  private:
    std::atomic<ULONG> references_{1};
    std::mutex mutex_;
    std::wstring output_;
};

bool RunCommand(IDebugControl4 *control, Capture *capture, const std::wstring &command, const wchar_t *expected)
{
    capture->Take();
    const HRESULT status = control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    const auto output = capture->Take();
    if (FAILED(status) || (expected != nullptr && output.find(expected) == std::wstring::npos))
    {
        std::wprintf(L"command: %s\nHRESULT: 0x%08x\n%s\n", command.c_str(), static_cast<unsigned>(status), output.c_str());
        return false;
    }
    return true;
}

knjson::Value StoredResultData(IDebugControl4 *control, Capture *capture, const std::wstring &id)
{
    capture->Take();
    control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, (L"!kndbgx result-read " + id).c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    const auto stored = capture->Take();
    const auto start = stored.find(L'{');
    knjson::Value data;
    if (start != std::wstring::npos)
    {
        knjson::Parse(stored.substr(start), &data);
    }
    if (!data.IsObject())
    {
        std::wprintf(L"stored result lookup failed: %s\n%s\n", id.c_str(), stored.c_str());
    }
    return data;
}

knjson::Value CommandResultData(IDebugControl4 *control, Capture *capture, const std::wstring &command)
{
    capture->Take();
    control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    const auto output = capture->Take();
    const auto marker = output.rfind(L"[result] ");
    if (marker == std::wstring::npos)
    {
        return {};
    }
    const auto end = output.find_first_of(L"\r\n", marker + 9);
    const auto id = knutil::Trim(output.substr(marker + 9, end == std::wstring::npos ? end : end - marker - 9));
    return StoredResultData(control, capture, id);
}

knjson::Value JobResultData(IDebugControl4 *control, Capture *capture, const std::wstring &command)
{
    capture->Take();
    control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    const auto output = capture->Take();
    const auto marker = output.find(L"[job] ");
    if (marker == std::wstring::npos)
    {
        return {};
    }
    const auto end = output.find_first_of(L"\r\n", marker + 6);
    const auto id = knutil::Trim(output.substr(marker + 6, end == std::wstring::npos ? end : end - marker - 6));
    const auto query = L"!kndbgx job " + id;
    const auto deadline = GetTickCount64() + 10000;
    while (GetTickCount64() < deadline)
    {
        control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, query.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
        const auto reply = capture->Take();
        const auto begin = reply.find(L"{\"jobId\":");
        knjson::Value job;
        if (begin != std::wstring::npos && knjson::Parse(reply.substr(begin), &job) &&
            job.Get(L"jobId").AsString(L"") == id && job.Get(L"result").IsObject())
        {
            const auto resultId = job.Get(L"resultId").AsString(L"");
            return resultId.empty() ? knjson::Value() : StoredResultData(control, capture, resultId);
        }
        Sleep(10);
    }
    std::wprintf(L"job result timed out: %s\n", command.c_str());
    control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, (L"!kndbgx cancel " + id).c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    capture->Take();
    return {};
}

void CheckMemoryHoles(IDebugClient5 *client, IDebugControl4 *control, Capture *capture, const std::wstring &outputPath)
{
    ComPtr<IDebugSystemObjects4> system;
    client->QueryInterface(IID_PPV_ARGS(&system));
    ULONG pid = 0;
    HANDLE process = system && system->GetCurrentProcessSystemId(&pid) == S_OK
                         ? OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid)
                         : nullptr;
    auto *range =
        process != nullptr ? static_cast<unsigned char *>(VirtualAllocEx(process, nullptr, 12288, MEM_RESERVE, PAGE_READWRITE)) : nullptr;
    bool prepared = false;
    if (range != nullptr)
    {
        std::array<unsigned char, 4096> bytes;
        bytes.fill('A');
        SIZE_T written = 0;
        prepared = VirtualAllocEx(process, range, 4096, MEM_COMMIT, PAGE_READWRITE) == range &&
                   VirtualAllocEx(process, range + 8192, 4096, MEM_COMMIT, PAGE_READWRITE) == range + 8192 &&
                   WriteProcessMemory(process, range, bytes.data(), bytes.size(), &written) && written == bytes.size() &&
                   WriteProcessMemory(process, range + 8192, bytes.data(), bytes.size(), &written) && written == bytes.size();
    }
    Check(prepared, "host.memory-hole-owned-fixture");
    if (prepared)
    {
        const auto address = reinterpret_cast<ULONG64>(range);
        const auto data = CommandResultData(control, capture, L"!kndbgx db " + kncore::Hex(address + 4094) + L" L1004");
        const auto &coverage = data.Get(L"Metadata").Get(L"coverage");
        Check(data.Get(L"Metadata").Get(L"status").AsString(L"") == L"Partial" && coverage.Get(L"readEntries").AsString(L"") == L"4" &&
                  coverage.Get(L"unreadableEntries").AsString(L"") == L"4096" && !coverage.Get(L"complete").AsBool(true),
              "host.memory-hole-does-not-hide-readable-tail");
        const auto &readEvidence = data.Get(L"Metadata").Get(L"analysis").Get(L"memoryRead");
        const auto &attempts = readEvidence.Get(L"attempts").Items();
        Check(readEvidence.Get(L"length").AsString(L"") == L"4100" && readEvidence.Get(L"read").AsString(L"") == L"4" &&
                  attempts.size() == 3 && attempts[0].Get(L"read").AsString(L"") == L"2" &&
                  attempts[1].Get(L"address").AsString(L"") == kncore::Hex(address + 4096) &&
                  attempts[1].Get(L"requested").AsString(L"") == L"4096" && attempts[1].Get(L"read").AsString(L"") == L"0" &&
                  attempts[1].Get(L"nativeError").Get(L"domain").AsString(L"") == L"HRESULT" &&
                  attempts[2].Get(L"read").AsString(L"") == L"2" &&
                  readEvidence.Get(L"capture").Get(L"kind").AsString(L"") == L"UserLive" &&
                  readEvidence.Get(L"unreadableCause").AsString(L"") == L"Unknown",
              "host.memory-evidence-preserves-hole-between-readable-pages");
        const auto holeEnd = CommandResultData(control, capture, L"!kndbgx db \"" + kncore::Hex(address + 8190) + L"\" L0x10");
        const auto &holeRows = holeEnd.Get(L"Rows").Items();
        Check(holeRows.size() == 1 && holeRows[0].Get(L"bytes").Items().size() == 16 &&
                  holeRows[0].Get(L"bytes").Items()[0].IsNull() && holeRows[0].Get(L"bytes").Items()[1].IsNull() &&
                  holeRows[0].Get(L"bytes").Items()[2].AsDouble(-1) == 'A' &&
                  holeRows[0].Get(L"bytes").Items()[15].AsDouble(-1) == 'A',
              "host.memory-view-null-hole-and-readable-tail");
        const auto text = CommandResultData(control, capture, L"!kndbgx da " + kncore::Hex(address + 4080));
        Check(text.Get(L"Metadata").Get(L"status").AsString(L"") == L"Partial" && !text.Get(L"Rows").Items().empty() &&
                  text.Get(L"Rows").Items()[0].Get(L"text").AsString(L"") == std::wstring(16, L'A') &&
                  text.Get(L"Metadata").Get(L"coverage").Get(L"stopReason").AsString(L"") == L"UnreadableStringTail",
              "host.memory-short-string-read-preserves-prefix");
        const auto holePath = std::filesystem::absolute(outputPath + L".hole").wstring();
        const auto hole =
            CommandResultData(control, capture, L"!kndbgx dump-raw " + kncore::Hex(address) + L" 0x3000 \"" + holePath + L"\"");
        const auto &holeMetadata = hole.Get(L"Metadata");
        const auto &holeCoverage = holeMetadata.Get(L"coverage");
        const auto &holeAnalysis = holeMetadata.Get(L"analysis");
        Check(holeMetadata.Get(L"status").AsString(L"") == L"Partial" && holeCoverage.Get(L"expectedEntries").AsString(L"") == L"12288" &&
                  holeCoverage.Get(L"readEntries").AsString(L"") == L"4096" &&
                  holeCoverage.Get(L"unknownEntries").AsString(L"") == L"8192" &&
                  holeCoverage.Get(L"stopReason").AsString(L"") == L"ReadFailed" &&
                  holeAnalysis.Get(L"firstUnreadAddress").AsString(L"") == kncore::Hex(address + 4096) &&
                  holeAnalysis.Get(L"firstUnreadOffset").AsString(L"") == kncore::Hex(4096),
              "host.raw-dump-hole-reports-prefix-and-first-missing-byte");
        bool noTemporary = true;
        for (const auto &entry : std::filesystem::directory_iterator(std::filesystem::path(holePath).parent_path()))
        {
            noTemporary = noTemporary && !entry.path().wstring().starts_with(holePath + L".knx-");
        }
        Check(!std::filesystem::exists(holePath) && noTemporary && !holeAnalysis.Get(L"artifactCommitted").AsBool(true),
              "host.raw-dump-hole-leaves-no-output-or-temporary-file");

        // Make a fully resident mapped PE with its NT headers beyond the first page.
        ComPtr<IDebugSymbols3> symbols;
        ComPtr<IDebugDataSpaces> memory;
        client->QueryInterface(IID_PPV_ARGS(&symbols));
        client->QueryInterface(IID_PPV_ARGS(&memory));
        std::vector<unsigned char> imageBytes(0x3000, 0);
        const auto store = [&](size_t offset, const auto &value)
        {
            std::memcpy(imageBytes.data() + offset, &value, sizeof(value));
        };
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x1000;
        store(0, dos);
        store(0x1000, DWORD(IMAGE_NT_SIGNATURE));
        IMAGE_FILE_HEADER file = {};
        file.Machine = IMAGE_FILE_MACHINE_AMD64;
        file.NumberOfSections = 1;
        file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        file.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
        store(0x1004, file);
        IMAGE_OPTIONAL_HEADER64 optional = {};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.ImageBase = address;
        optional.SectionAlignment = 0x1000;
        optional.FileAlignment = 0x200;
        optional.SizeOfImage = 0x3000;
        optional.SizeOfHeaders = 0x2000;
        optional.AddressOfEntryPoint = 0x2000;
        optional.NumberOfRvaAndSizes = 16;
        store(0x1018, optional);
        IMAGE_SECTION_HEADER section = {};
        std::memcpy(section.Name, ".text", 5);
        section.VirtualAddress = 0x2000;
        section.Misc.VirtualSize = 0x1000;
        section.SizeOfRawData = 0x1000;
        section.PointerToRawData = 0x2000;
        section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        store(0x1018 + sizeof(optional), section);
        std::fill(imageBytes.begin() + 0x2000, imageBytes.end(), static_cast<unsigned char>(0xc3));
        ULONG transferred = 0;
        const bool imageReady =
            symbols && memory && VirtualAllocEx(process, range + 4096, 4096, MEM_COMMIT, PAGE_READWRITE) == range + 4096 &&
            memory->WriteVirtual(address, imageBytes.data(), static_cast<ULONG>(imageBytes.size()), &transferred) == S_OK &&
            transferred == imageBytes.size();
        const bool added = imageReady && symbols->AddSyntheticModuleWide(address, static_cast<ULONG>(imageBytes.size()),
                                                                         L"knexportfixture.sys", L"knexportfixture", 0) == S_OK;
        Check(added, "host.mapped-PE-owned-synthetic-module-fixture");
        if (added)
        {
            const auto pePath = outputPath + L".mapped";
            const auto exported = CommandResultData(control, capture, L"!kndbgx dump-pe knexportfixture \"" + pePath + L"\"");
            Check(exported.Get(L"Metadata").Get(L"status").AsString(L"") == L"Success" &&
                      exported.Get(L"Metadata").Get(L"analysis").Get(L"artifactCommitted").AsBool(false) &&
                      exported.Get(L"Metadata").Get(L"coverage").Get(L"readEntries").AsString(L"") == L"12288" &&
                      !exported.Get(L"Rows").Items().empty() &&
                      exported.Get(L"Rows").Items()[0].Get(L"format").AsString(L"") == L"MappedPeImage",
                  "host.mapped-PE-large-header-export-commits-full-image");
            {
                knutil::FileReader saved(pePath);
                std::vector<unsigned char> actual(imageBytes.size());
                Check(saved.IsOpen() && saved.Size() == imageBytes.size() && saved.Read(0, actual) && actual == imageBytes,
                      "host.mapped-PE-export-matches-every-fixture-byte");
            }
            const auto collision = CommandResultData(control, capture, L"!kndbgx dump-pe knexportfixture \"" + pePath + L"\"");
            knutil::FileReader preserved(pePath);
            std::vector<unsigned char> after(imageBytes.size());
            Check(collision.Get(L"Metadata").Get(L"status").AsString(L"") == L"IOError" &&
                      collision.Get(L"Metadata").Get(L"coverage").Get(L"stopReason").AsString(L"") == L"CommitFailed" &&
                      !collision.Get(L"Metadata").Get(L"analysis").Get(L"artifactCommitted").AsBool(true) && preserved.IsOpen() &&
                      preserved.Read(0, after) && after == imageBytes,
                  "host.mapped-PE-existing-file-remains-intact");
            Check(symbols->RemoveSyntheticModule(address) == S_OK, "host.mapped-PE-synthetic-module-removed");
        }
    }
    if (range != nullptr)
    {
        VirtualFreeEx(process, range, 0, MEM_RELEASE);
    }
    if (process != nullptr)
    {
        CloseHandle(process);
    }
}

HWND OwnWindow()
{
    HWND found = nullptr;
    EnumWindows(
        [](HWND window, LPARAM parameter) -> BOOL
        {
            DWORD process = 0;
            GetWindowThreadProcessId(window, &process);
            wchar_t name[64] = {};
            GetClassNameW(window, name, 64);
            if (process == GetCurrentProcessId() && wcscmp(name, L"KNDbgX_UiHost") == 0)
            {
                *reinterpret_cast<HWND *>(parameter) = window;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&found));
    return found;
}

std::wstring PrepareCommandPlan(IDebugControl4 *control, Capture *capture, const std::wstring &command)
{
    capture->Take();
    control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    const auto output = capture->Take();
    const std::wstring marker = L"[plan.approval] ";
    const auto at = output.find(marker);
    if (at == std::wstring::npos)
    {
        std::wprintf(L"plan output: %s\n", output.c_str());
        return {};
    }
    const auto end = output.find(L'\n', at);
    return knutil::Trim(output.substr(at + marker.size(), end - at - marker.size()));
}

std::wstring PrepareWrite(IDebugControl4 *control, Capture *capture, ULONG64 address)
{
    return PrepareCommandPlan(control, capture, L"!kndbgx eb " + kncore::Hex(address) + L" 41 42 43");
}

std::wstring DebugPlan(IDebugControl4 *control, Capture *capture, const std::wstring &action)
{
    capture->Take();
    control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, (L"!kndbgx debug-plan " + action).c_str(), DEBUG_EXECUTE_NOT_LOGGED);
    const auto output = capture->Take();
    const std::wstring marker = L"Approve once: ";
    const auto at = output.find(marker);
    return at == std::wstring::npos ? L"" : knutil::Trim(output.substr(at + marker.size(), output.find(L'\n', at) - at - marker.size()));
}

using ExtensionCall = HRESULT(CALLBACK *)(PDEBUG_CLIENT, PCSTR);

bool ColdStartJob(IDebugControl4 *control, Capture *capture)
{
    capture->Take();
    const HRESULT submitted = control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, L"!kndbgx submit registers rip", DEBUG_EXECUTE_NOT_LOGGED);
    const auto output = capture->Take();
    const auto marker = output.find(L"[job] ");
    if (FAILED(submitted) || marker == std::wstring::npos)
    {
        return false;
    }
    const auto id = output.substr(marker + 6, 32);
    const auto command = L"!kndbgx job " + id;
    const auto deadline = GetTickCount64() + 10000;
    while (GetTickCount64() < deadline)
    {
        control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, command.c_str(), DEBUG_EXECUTE_NOT_LOGGED);
        const auto reply = capture->Take();
        const auto begin = reply.find(L"{\"jobId\":");
        knjson::Value job;
        if (begin != std::wstring::npos && knjson::Parse(reply.substr(begin), &job) && job.Get(L"jobId").AsString(L"") == id &&
            job.Get(L"result").IsObject())
        {
            const auto resultId = job.Get(L"resultId").AsString(L"");
            return job.Get(L"state").AsString(L"") == L"Success" && !resultId.empty() &&
                   RunCommand(control, capture, L"!kndbgx result-read " + resultId, L"rawBytes");
        }
        Sleep(20);
    }
    return false;
}

void CheckJobs(HMODULE extension, IDebugClient *client, Capture *capture)
{
    const auto invoke = reinterpret_cast<ExtensionCall>(GetProcAddress(extension, "kndbgx"));
    Check(invoke != nullptr, "host.job-modern-entry-present");
    if (invoke == nullptr)
    {
        return;
    }
    std::atomic<bool> ended{false};
    auto watchdog = std::async(std::launch::async,
                               [&]()
                               {
                                   const auto deadline = GetTickCount64() + 5000;
                                   while (!ended.load() && GetTickCount64() < deadline)
                                   {
                                       Sleep(10);
                                   }
                                   if (!ended.load())
                                   {
                                       invoke(nullptr, "cancel");
                                   }
                               });
    capture->Take();
    const auto start = GetTickCount64();
    const HRESULT submitted = invoke(client, "submit raw --ack-effects .while (1) { r @$t0 = @$t0 + 1; }");
    const auto submission = capture->Take();
    const auto marker = submission.find(L"[job] ");
    std::wstring id;
    if (marker != std::wstring::npos)
    {
        id = submission.substr(marker + 6, 32);
    }
    Check(SUCCEEDED(submitted) && id.size() == 32 && GetTickCount64() - start < 1000, "host.long-cli-job-submission-nonblocking");
    const auto query = "job " + knutil::WideToUtf8(id);
    const auto deadline = GetTickCount64() + 2000;
    HRESULT busyStatus = S_OK;
    while (GetTickCount64() < deadline)
    {
        busyStatus = invoke(nullptr, "status");
        if (busyStatus == HRESULT_FROM_WIN32(ERROR_BUSY))
        {
            break;
        }
        Sleep(10);
    }
    Check(busyStatus == HRESULT_FROM_WIN32(ERROR_BUSY), "host.cli-engine-busy-immediate");
    const auto queried = GetTickCount64();
    Check(!id.empty() && SUCCEEDED(invoke(nullptr, query.c_str())) && GetTickCount64() - queried < 1000,
          "host.job-query-without-engine-output-nonblocking");
    invoke(nullptr, "cancel");
    bool completed = false;
    const auto completionDeadline = GetTickCount64() + 3000;
    while (!id.empty() && GetTickCount64() < completionDeadline)
    {
        capture->Take();
        invoke(client, query.c_str());
        const auto output = capture->Take();
        completed = output.find(L"\"result\"") != std::wstring::npos && output.find(L"Cancelled") != std::wstring::npos;
        if (completed)
        {
            break;
        }
        Sleep(10);
    }
    Check(completed, "host.cancelled-job-result-retained");
    Check(FAILED(invoke(nullptr, ("cancel " + knutil::WideToUtf8(id)).c_str())), "host.completed-job-cancel-rejected");
    ended.store(true);
    watchdog.get();
}

int ProbePdb(const wchar_t *path, const wchar_t *guid, const wchar_t *age, const wchar_t *requestedType = nullptr)
{
    GUID expected = {};
    uint64_t parsedAge = 0;
    const auto formattedGuid = L"{" + std::wstring(guid) + L"}";
    knengine::PdbMetadata metadata;
    if (CLSIDFromString(formattedGuid.c_str(), &expected) != S_OK || !kncore::ParseUnsigned(age, 10, &parsedAge) ||
        parsedAge > UINT32_MAX || !metadata.Open(path, expected, static_cast<uint32_t>(parsedAge)))
    {
        std::wprintf(L"PDB validation failed: %s\n", metadata.Diagnostic().c_str());
        return 1;
    }
    if (requestedType != nullptr && requestedType[0] == L'@')
    {
        kncore::FieldInfo symbol;
        uint32_t rva = 0;
        const bool present = metadata.Symbol(requestedType + 1, &symbol, &rva);
        const bool publicPresent = !present && metadata.PublicRva(requestedType + 1, &rva);
        auto row = knjson::Value::MakeObject();
        row.Set(L"symbol", knjson::Value(requestedType + 1));
        row.Set(L"present", knjson::Value(present));
        row.Set(L"publicPresent", knjson::Value(publicPresent));
        row.Set(L"rva", knjson::Value(kncore::Hex(rva)));
        row.Set(L"typeName", knjson::Value(symbol.TypeName));
        row.Set(L"size", knjson::Value(std::to_wstring(symbol.Size)));
        row.Set(L"kind", knjson::Value(std::to_wstring(static_cast<unsigned>(symbol.Kind))));
        row.Set(L"count", symbol.ArrayCount ? knjson::Value(std::to_wstring(*symbol.ArrayCount)) : knjson::Value());
        row.Set(L"elementSize", symbol.ElementSize ? knjson::Value(std::to_wstring(*symbol.ElementSize)) : knjson::Value());
        row.Set(L"leafSize", symbol.LeafElementSize ? knjson::Value(std::to_wstring(*symbol.LeafElementSize)) : knjson::Value());
        row.Set(L"leafType", knjson::Value(symbol.LeafTypeName));
        std::printf("%s\n", knutil::WideToUtf8(row.Write()).c_str());
        return present || publicPresent ? 0 : 1;
    }
    const std::pair<const wchar_t *, const wchar_t *> probes[] = {{L"_EPROCESS", L"ActiveProcessLinks"},
                                                                  {L"_EPROCESS", L"UniqueProcessId"},
                                                                  {L"_EPROCESS", L"ImageFileName"},
                                                                  {L"_EPROCESS", L"CreateTime"},
                                                                  {L"_EPROCESS", L"Pcb"},
                                                                  {L"_KPROCESS", L"DirectoryTableBase"},
                                                                  {L"_EPROCESS", L"VadRoot"},
                                                                  {L"_EPROCESS", L"ObjectTable"},
                                                                  {L"_OBJECT_DIRECTORY", L"HashBuckets"},
                                                                  {L"_OBJECT_DIRECTORY_ENTRY", L"ChainLink"},
                                                                  {L"_OBJECT_DIRECTORY_ENTRY", L"Object"},
                                                                  {L"_OBJECT_HEADER", L"Body"},
                                                                  {L"_OBJECT_HEADER", L"TypeIndex"},
                                                                  {L"_OBJECT_HEADER", L"InfoMask"},
                                                                  {L"_OBJECT_HEADER_NAME_INFO", L"Name"},
                                                                  {L"_OBJECT_HEADER_NAME_INFO", L"Directory"},
                                                                  {L"_OBJECT_TYPE", L"Name"},
                                                                  {L"_OBJECT_TYPE", L"Index"},
                                                                  {L"_MMVAD_FLAGS", L"Protection"},
                                                                  {L"_MMVAD_SHORT", L"StartingVpn"},
                                                                  {L"_MMVAD_SHORT", L"StartingVpnHigh"},
                                                                  {L"_MMVAD_SHORT", L"EndingVpn"},
                                                                  {L"_MMVAD_SHORT", L"EndingVpnHigh"},
                                                                  {L"_MMVAD_SHORT", L"u"},
                                                                  {L"_EX_CALLBACK_ROUTINE_BLOCK", L"Function"},
                                                                  {L"_KPRCB", L"DpcData"},
                                                                  {L"_KDPC_DATA", L"DpcListHead"},
                                                                  {L"_KDPC", L"DpcListEntry"},
                                                                  {L"_KDPC", L"DeferredRoutine"},
                                                                  {L"_KTIMER", L"TimerListEntry"},
                                                                  {L"_KTIMER", L"Dpc"},
                                                                  {L"_DRIVER_OBJECT", L"DriverSize"},
                                                                  {L"_DRIVER_OBJECT", L"MajorFunction"}};
    auto root = knjson::Value::MakeObject();
    root.Set(L"schema", knjson::Value(L"kndbgx.pdb-observations.v1"));
    root.Set(L"pdbGuid", knjson::Value(guid));
    root.Set(L"pdbAge", knjson::Value(age));
    root.Set(L"source", knjson::Value(L"Offline PDB; not a kernel memory observation"));
    auto rows = knjson::Value::MakeArray();
    std::vector<std::pair<std::wstring, std::wstring>> requested;
    kncore::LayoutDescriptor descriptor;
    if (requestedType != nullptr)
    {
        if (!metadata.Describe(requestedType, &descriptor))
        {
            std::printf("Type metadata unavailable\n");
            return 1;
        }
        root.Set(L"typeSize", knjson::Value(std::to_wstring(descriptor.Size)));
        for (const auto &[name, info] : descriptor.Fields)
        {
            requested.emplace_back(requestedType, name);
        }
        for (const auto &name : descriptor.UnknownFields)
        {
            requested.emplace_back(requestedType, name);
        }
    }
    else
    {
        for (const auto &probe : probes)
        {
            requested.emplace_back(probe.first, probe.second);
        }
    }
    for (const auto &[type, field] : requested)
    {
        auto row = knjson::Value::MakeObject();
        kncore::FieldInfo info;
        const bool present = metadata.Field(type.c_str(), field.c_str(), &info);
        row.Set(L"type", knjson::Value(type));
        row.Set(L"field", knjson::Value(field));
        row.Set(L"present", knjson::Value(present));
        if (present)
        {
            row.Set(L"typeName", knjson::Value(info.TypeName));
            row.Set(L"kind", knjson::Value(std::to_wstring(static_cast<unsigned>(info.Kind))));
            row.Set(L"offset", knjson::Value(kncore::Hex(info.Offset)));
            row.Set(L"size", knjson::Value(std::to_wstring(info.Size)));
            row.Set(L"arrayCount", info.ArrayCount ? knjson::Value(std::to_wstring(*info.ArrayCount)) : knjson::Value());
            row.Set(L"elementSize", info.ElementSize ? knjson::Value(std::to_wstring(*info.ElementSize)) : knjson::Value());
            row.Set(L"leafSize", info.LeafElementSize ? knjson::Value(std::to_wstring(*info.LeafElementSize)) : knjson::Value());
            row.Set(L"leafType", knjson::Value(info.LeafTypeName));
            auto dimensions = knjson::Value::MakeArray();
            for (const auto dimension : info.ArrayDimensions)
            {
                dimensions.Push(knjson::Value(std::to_wstring(dimension)));
            }
            row.Set(L"dimensions", dimensions);
            row.Set(L"bitOffset", info.BitOffset ? knjson::Value(std::to_wstring(*info.BitOffset)) : knjson::Value());
            row.Set(L"bitWidth", info.BitWidth ? knjson::Value(std::to_wstring(*info.BitWidth)) : knjson::Value());
        }
        else
        {
            row.Set(L"reason", knjson::Value(metadata.Diagnostic()));
        }
        rows.Push(row);
    }
    root.Set(L"fields", rows);
    std::printf("%s\n", knutil::WideToUtf8(root.Write()).c_str());
    return 0;
}
} // namespace

#ifdef KNDBGX_UI_TESTS
namespace
{
template <typename Predicate> bool AwaitUi(Predicate predicate, unsigned milliseconds = 20000)
{
    const auto deadline = GetTickCount64() + milliseconds;
    do
    {
        if (predicate())
        {
            return true;
        }
        Sleep(20);
    } while (GetTickCount64() < deadline);
    return predicate();
}
LRESULT UiTest(HWND window, UINT message, WPARAM argument = 0)
{
    DWORD_PTR reply = 0;
    return SendMessageTimeoutW(window, message, argument, 0, SMTO_ABORTIFHUNG, 5000, &reply) ? static_cast<LRESULT>(reply) : 0;
}
bool UiReady(HWND window)
{
    return GetPropW(window, L"KNDbgX.Ready") != nullptr && GetPropW(window, L"KNDbgX.WorkerReplyAcknowledged") != nullptr;
}

void CheckUiExecution(HWND window, IDebugControl4 *control, IDebugClient5 *client)
{
    ComPtr<IDebugRegisters> registers;
    Check(SUCCEEDED(client->QueryInterface(IID_PPV_ARGS(&registers))), "host.ui-execution-registers-available");
    if (!registers)
    {
        return;
    }
    for (const WPARAM action : {1u, 2u, 3u})
    {
        ULONG64 before = 0;
        registers->GetInstructionOffset(&before);
        const bool submitted = UiTest(window, WM_APP + 107, action) != 0 && AwaitUi(
            [&]()
            {
                ULONG execution = DEBUG_STATUS_BREAK;
                return (control->GetExecutionStatus(&execution) == S_OK && (execution & DEBUG_STATUS_MASK) != DEBUG_STATUS_BREAK) ||
                    GetPropW(window, L"KNDbgX.ExecutionReply") != nullptr;
            }, 10000);
        ULONG execution = DEBUG_STATUS_NO_DEBUGGEE;
        control->GetExecutionStatus(&execution);
        const bool alreadyStopped = (execution & DEBUG_STATUS_MASK) == DEBUG_STATUS_BREAK &&
            reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.ExecutionReply")) == 1;
        const bool stopped = submitted && (alreadyStopped || control->WaitForEvent(0, 10000) == S_OK);
        Check(stopped && AwaitUi(
            [&]()
            {
                return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.ExecutionReply")) == 1;
            }),
              action == 1 ? "host.ui-step-over-reaches-owned-stop" : action == 2 ? "host.ui-step-into-reaches-owned-stop" :
                                                                               "host.ui-continue-reaches-owned-debugbreak");
        if (!stopped)
        {
            control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
            control->WaitForEvent(0, 5000);
            break;
        }
        ULONG64 after = 0;
        const bool current = registers->GetInstructionOffset(&after) == S_OK && after != 0 && after != before;
        Check(current && AwaitUi(
            [&]()
            {
                if (GetPropW(window, L"KNDbgX.FollowChecked") == nullptr)
                {
                    UiTest(window, WM_APP + 107, static_cast<WPARAM>(after));
                }
                const auto checked = reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.FollowChecked"));
                if (checked == 2)
                {
                    RemovePropW(window, L"KNDbgX.FollowChecked");
                }
                return checked == 1;
            }), "host.ui-followed-disassembly-matches-real-ip");
        RemovePropW(window, L"KNDbgX.FollowChecked");
    }
    RemovePropW(window, L"KNDbgX.BreakReply");
    ComPtr<IDebugSystemObjects4> system;
    ULONG pid = 0;
    client->QueryInterface(IID_PPV_ARGS(&system));
    const auto signalName = system && system->GetCurrentProcessSystemId(&pid) == S_OK ?
                                L"Local\\KNDbgX.UiRunning." + std::to_wstring(pid) : std::wstring();
    const HANDLE runningSignal = signalName.empty() ? nullptr : CreateEventW(nullptr, TRUE, FALSE, signalName.c_str());
    const bool ownedSignal = runningSignal != nullptr && GetLastError() != ERROR_ALREADY_EXISTS;
    Check(ownedSignal, "host.ui-header-break-owns-running-probe");
    const bool continued = ownedSignal && UiTest(window, WM_APP + 107, 4) != 0 && AwaitUi([&]()
    {
        ULONG execution = DEBUG_STATUS_NO_DEBUGGEE;
        return control->GetExecutionStatus(&execution) == S_OK && (execution & DEBUG_STATUS_MASK) == DEBUG_STATUS_GO;
    }, 10000);
    Check(continued, "host.ui-header-continue-from-memory-tab");
    auto requestBreak = std::async(std::launch::async, [window, runningSignal, continued]()
    {
        // WaitForEvent must have resumed the owned process before exercising Break.
        return continued && WaitForSingleObject(runningSignal, 5000) == WAIT_OBJECT_0 && UiTest(window, WM_APP + 107, 5) != 0;
    });
    const bool stopped = continued && control->WaitForEvent(0, 15000) == S_OK;
    const bool requested = requestBreak.get();
    if (runningSignal != nullptr)
    {
        CloseHandle(runningSignal);
    }
    Check(requested && stopped && AwaitUi([&]()
    {
        return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.BreakReply")) == 1;
    }, 1000), "host.ui-header-break-stops-owned-running-target");
    if (continued && !stopped)
    {
        control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
        control->WaitForEvent(0, 5000);
    }
    ULONG64 stoppedIp = 0;
    Check(stopped && registers->GetInstructionOffset(&stoppedIp) == S_OK && AwaitUi([&]()
    {
        if (GetPropW(window, L"KNDbgX.FollowChecked") == nullptr)
        {
            UiTest(window, WM_APP + 107, static_cast<WPARAM>(stoppedIp));
        }
        const auto checked = reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.FollowChecked"));
        if (checked == 2)
        {
            RemovePropW(window, L"KNDbgX.FollowChecked");
        }
        return checked == 1;
    }), "host.ui-header-break-settles-current-ip-before-next-fixture");
    RemovePropW(window, L"KNDbgX.FollowChecked");
}
void CheckBoundNavigation(HWND window, IDebugControl4 *control, Capture *capture, ULONG64 address)
{
    Check(RunCommand(control, capture, L"!kndbgx navigate va " + kncore::Hex(address), L"AddressObservation"),
          "host.ui-bound-navigation-source-collected");
    const bool queued = UiTest(window, WM_APP + 103, 1) != 0 && AwaitUi(
                                                                    [&]()
                                                                    {
                                                                        return GetPropW(window, L"KNDbgX.BoundHeld") != nullptr;
                                                                    });
    const bool changed = control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386) == S_OK &&
                         control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64) == S_OK;
    UiTest(window, WM_APP + 103, 0);
    const bool rejected = AwaitUi(
        [&]()
        {
            return GetPropW(window, L"KNDbgX.BoundReply") != nullptr;
        });
    Check(queued && changed && rejected && reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.BoundReply")) == 1,
          "host.ui-bound-action-dequeue-context-race-refused-before-navigation");
    // Wait for the completed reply and resulting status refresh to reach the page.
    Check(UiTest(window, WM_APP + 102) != 0 && AwaitUi(
                                                   [&]()
                                                   {
                                                       return UiReady(window);
                                                   }),
          "host.ui-bound-race-status-refresh");
    Check(RunCommand(control, capture, L"!kndbgx navigate va " + kncore::Hex(address), L"AddressObservation"),
          "host.ui-fresh-manual-navigation-after-context-race");
    Check(UiTest(window, WM_APP + 103, 2) != 0 && AwaitUi(
                                                      [&]()
                                                      {
                                                          return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.BoundReply")) == 2;
                                                      }),
          "host.ui-fresh-bound-action-through-real-worker-succeeds");
}

void CheckUiFailures(HWND window)
{
    using namespace kncore;
    for (const WPARAM visible : {0u, 1u})
    {
        if (visible != 0)
        {
            UiTest(window, WM_CLOSE);
        }
        const HANDLE generation = GetPropW(window, L"KNDbgX.NavigationGeneration");
        Check(UiTest(window, WM_APP + 109, visible) != 0 && AwaitUi(
            [&]()
            {
                return GetPropW(window, L"KNDbgX.FailedStage") == reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(UiStep::Visible) + 1);
            }) && GetPropW(window, L"KNDbgX.Ready") == nullptr && generation != GetPropW(window, L"KNDbgX.NavigationGeneration"),
              visible == 0 ? "host.failed-hide-invalidates-document-and-reports-visible-stage" :
                             "host.failed-show-invalidates-document-and-reports-visible-stage");
        PostMessageW(window, WM_APP + 1, 0, 0);
        Check(AwaitUi(
            [&]()
            {
                return IsWindowVisible(window) && UiReady(window) && GetPropW(window, L"KNDbgX.FailedStage") == nullptr;
            }), "host.explicit-show-recovers-failed-visibility-with-fresh-handshake");
    }
    Check(GetPropW(window, L"KNDbgX.ResourceFilterKind") == reinterpret_cast<HANDLE>(1),
          "third.V05.owned-webview-uses-resource-source-kind-filter");
    const auto filterGeneration = GetPropW(window, L"KNDbgX.NavigationGeneration");
    Check(UiTest(window, WM_APP + 105, 5) != 0 &&
              AwaitUi(
                  [&]()
                  {
                      return filterGeneration != GetPropW(window, L"KNDbgX.NavigationGeneration") && UiReady(window);
                  }) &&
              GetPropW(window, L"KNDbgX.ResourceFilterKind") == reinterpret_cast<HANDLE>(2),
          "third.V05.injected-missing-source-kind-capability-keeps-legacy-policy-and-handshake");
    const auto fallbackGeneration = GetPropW(window, L"KNDbgX.NavigationGeneration");
    Check(UiTest(window, WM_APP + 105, 0) != 0 && AwaitUi(
                                                      [&]()
                                                      {
                                                          return fallbackGeneration != GetPropW(window, L"KNDbgX.NavigationGeneration") &&
                                                                 UiReady(window);
                                                      }),
          "third.V05.restore-modern-filter-after-capability-fixture");
    for (unsigned fault : {1u, 2u, 3u})
    {
        Check(UiTest(window, WM_APP + 104, fault) != 0 &&
                  AwaitUi(
                      [&]()
                      {
                          return GetPropW(window, L"KNDbgX.DeliveryFault") != nullptr &&
                                 GetPropW(window, L"KNDbgX.WorkerReplyAcknowledged") != nullptr;
                      }) &&
                  reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.WorkerStarts")) == 1,
              "third.T08-T09.owned-webview-terminal-fault-recovers-with-js-ack-and-no-reexecution");
    }
    for (unsigned fault : {1u, 2u, 3u, 4u})
    {
        const auto expected =
            fault == 4 ? UiStep::HandshakeTimeout : static_cast<UiStep>(static_cast<unsigned>(UiStep::ResourceStream) + fault - 1);
        Check(UiTest(window, WM_APP + 105, fault) != 0 &&
                  AwaitUi(
                      [&]()
                      {
                          return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.FailedStage")) ==
                                 static_cast<unsigned>(expected) + 1;
                      }) &&
                  GetPropW(window, L"KNDbgX.Ready") == nullptr,
              "third.T11.owned-webview-required-script-failure-converges-to-native-retry");
        Check(UiTest(window, WM_APP + 105, 0) != 0 && AwaitUi(
                                                          [&]()
                                                          {
                                                              return UiReady(window);
                                                          }),
              "third.T11.owned-webview-resource-retry-handshake-and-js-ack");
    }
    for (unsigned index = 0; index < static_cast<unsigned>(UiStep::Count); ++index)
    {
        const bool sent = UiTest(window, WM_APP + 100, index + 1) != 0;
        const bool failed = sent && AwaitUi(
                                        [&]()
                                        {
                                            return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.FailedStage")) == index + 1;
                                        });
        std::printf("ui.failure-step=%u observed=%d\n", index, failed);
        Check(failed && GetPropW(window, L"KNDbgX.Ready") == nullptr && GetPropW(window, L"KNDbgX.NavigateCalls") == nullptr,
              "host.webview-init-injected-failure-no-navigation");
        if (!failed)
        {
            break;
        }
    }
    Check(UiTest(window, WM_APP + 100) != 0 && AwaitUi(
                                                   [&]()
                                                   {
                                                       return UiReady(window);
                                                   }),
          "host.webview-init-retry-fresh-handshake");
    // Process kind values come from the WebView2 SDK. The Debug UDF is isolated by host PID.
    for (unsigned kind : {4u, 2u})
    {
        const auto generation = GetPropW(window, L"KNDbgX.NavigationGeneration");
        const auto expected = kind == 4 ? UiProcessFailure::GpuExited : UiProcessFailure::UtilityExited;
        const bool ended = UiTest(window, WM_APP + 101, kind) != 0;
        const bool observed = ended && AwaitUi(
                                           [&]()
                                           {
                                               return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.ProcessFailure")) ==
                                                      static_cast<ULONG_PTR>(expected) + 1;
                                           });
        Check(observed && generation == GetPropW(window, L"KNDbgX.NavigationGeneration") && UiReady(window),
              kind == 4 ? "host.webview-real-gpu-failure-preserves-document" : "host.webview-real-utility-failure-preserves-document");
        Check(UiTest(window, WM_APP + 102) != 0 && AwaitUi(
                                                       [&]()
                                                       {
                                                           return UiReady(window);
                                                       }),
              "host.webview-read-after-recoverable-process-failure");
    }
    const auto responsiveGeneration = GetPropW(window, L"KNDbgX.NavigationGeneration");
    const bool scriptStarted = UiTest(window, WM_APP + 101, 100) != 0;
    const bool unresponsive = scriptStarted && AwaitUi(
                                                   [&]()
                                                   {
                                                       return reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.ProcessFailure")) ==
                                                              static_cast<ULONG_PTR>(UiProcessFailure::RendererUnresponsive) + 1;
                                                   },
                                                   20000);
    std::printf("ui.unresponsive-notification=%s\n", unresponsive ? "observed" : "not-observed");
    const bool stalled = UiTest(window, WM_APP + 102) != 0 && !AwaitUi(
                                                                  [&]()
                                                                  {
                                                                      return UiReady(window);
                                                                  },
                                                                  2000);
    Check(scriptStarted && stalled && GetPropW(window, L"KNDbgX.NavigationGeneration") == responsiveGeneration,
          "host.webview-real-hung-script-preserves-generation-without-replay");
    for (unsigned kind : {1u, 0u})
    {
        const auto generation = GetPropW(window, L"KNDbgX.NavigationGeneration");
        const bool ended = UiTest(window, WM_APP + 101, kind) != 0;
        Check(ended &&
                  AwaitUi(
                      [&]()
                      {
                          return GetPropW(window, L"KNDbgX.FailedStage") != nullptr;
                      }) &&
                  GetPropW(window, L"KNDbgX.Ready") == nullptr && generation != GetPropW(window, L"KNDbgX.NavigationGeneration"),
              kind == 1 ? "host.webview-real-renderer-failure-invalidates-document"
                        : "host.webview-real-browser-failure-invalidates-document");
        Check(UiTest(window, WM_APP + 100) != 0 && AwaitUi(
                                                       [&]()
                                                       {
                                                           return UiReady(window);
                                                       }),
              "host.webview-fatal-retry-creates-new-handshake");
        Check(UiTest(window, WM_APP + 102) != 0 && AwaitUi(
                                                       [&]()
                                                       {
                                                           return UiReady(window);
                                                       }),
              "host.webview-read-after-fatal-recreation");
    }
    std::fflush(stdout);
}
} // namespace
#endif

int wmain(int argc, wchar_t **argv)
{
    const bool deferredProbe = argc == 5 && wcscmp(argv[1], L"--deferred-symbols") == 0;
    if (deferredProbe)
    {
        --argc;
        ++argv;
    }
    if (argc == 6 && wcscmp(argv[1], L"--pdb-type") == 0)
    {
        return ProbePdb(argv[2], argv[3], argv[4], argv[5]);
    }
    if (argc == 5 && wcscmp(argv[1], L"--pdb-layout") == 0)
    {
        return ProbePdb(argv[2], argv[3], argv[4]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--debuggee") == 0)
    {
        const HMODULE fixture = LoadLibraryW(argv[2]);
        if (fixture == nullptr)
        {
            return 2;
        }
        DebugBreak();
        Sleep(10);
        DebugBreak();
#ifdef KNDBGX_UI_TESTS
        // Keep an owned stop available for the UI Continue check.
        Sleep(10);
        DebugBreak();
        const auto signalName = L"Local\\KNDbgX.UiRunning." + std::to_wstring(GetCurrentProcessId());
        const HANDLE runningSignal = OpenEventW(EVENT_MODIFY_STATE, FALSE, signalName.c_str());
        if (runningSignal != nullptr)
        {
            SetEvent(runningSignal);
            CloseHandle(runningSignal);
        }
#endif
        Sleep(30000);
        FreeLibrary(fixture);
        return 0;
    }
    if (argc != 4)
    {
        std::printf("usage: engine-test [--deferred-symbols] <dbgeng-directory> <extension-dll> <fixture-dump>\n");
        return 2;
    }
#ifdef KNDBGX_UI_TESTS
    SetEnvironmentVariableW(L"KNDBGX_TEST_UI", L"1");
#endif
    const std::wstring engineDirectory = argv[1];
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
    const auto directoryCookie = AddDllDirectory(engineDirectory.c_str());
    const HMODULE engine =
        LoadLibraryExW((engineDirectory + L"\\dbgeng.dll").c_str(), nullptr,
                       LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
    Check(engine != nullptr, "host.load-installed-dbgeng");
    if (engine == nullptr)
    {
        std::printf("Win32=%lu\n", GetLastError());
        return 1;
    }
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    {
        using Create = HRESULT(WINAPI *)(REFIID, PVOID *);
        auto create = reinterpret_cast<Create>(GetProcAddress(engine, "DebugCreate"));
        ComPtr<IDebugClient5> client;
        ComPtr<IDebugControl4> control;
        ComPtr<Capture> capture;
        capture.Attach(new Capture());
        ComPtr<OwnedTargetEvents> events;
        events.Attach(new OwnedTargetEvents());
        ComPtr<IModelObject> publishedModel;
        std::wstring publishedId;
        do
        {
            HRESULT status = create != nullptr ? create(__uuidof(IDebugClient5), reinterpret_cast<void **>(client.GetAddressOf())) : E_FAIL;
            Check(SUCCEEDED(status) && client != nullptr, "host.create-client");
            if (client == nullptr)
            {
                break;
            }
            client.As(&control);
            client->SetOutputCallbacksWide(capture.Get());
            client->SetEventCallbacksWide(events.Get());
            client->SetOutputMask(DEBUG_OUTPUT_NORMAL | DEBUG_OUTPUT_ERROR | DEBUG_OUTPUT_WARNING);
            if (wcscmp(argv[3], L"--probe-local") == 0)
            {
                const HRESULT attached = client->AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL, nullptr);
                ULONG kind = 0, qualifier = 0;
                const HRESULT classified = control->GetDebuggeeType(&kind, &qualifier);
                std::printf("local-kernel attach=0x%08x classify=0x%08x kind=%lu qualifier=%lu\n", static_cast<unsigned>(attached),
                            static_cast<unsigned>(classified), kind, qualifier);
                if (SUCCEEDED(attached))
                {
                    ULONG64 extensionHandle = 0;
                    control->AddExtensionWide(argv[2], 0, &extensionHandle);
                    RunCommand(control.Get(), capture.Get(), L"!kndbgx status", L"local");
                    control->RemoveExtension(extensionHandle);
                }
                break;
            }
            wchar_t self[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, self, MAX_PATH);
            std::wstring command = L"\"" + std::wstring(self) + L"\" --debuggee \"" + argv[2] + L"\"";
            if (deferredProbe)
            {
                ComPtr<IDebugSymbols3> symbols;
                status = client.As(&symbols);
                if (SUCCEEDED(status))
                {
                    status = symbols->AddSymbolOptions(SYMOPT_DEFERRED_LOADS);
                }
                if (SUCCEEDED(status))
                {
                    status = client->OpenDumpFileWide(argv[3], 0);
                }
            }
            else
            {
                status = client->CreateProcessAndAttachWide(0, command.data(), DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, 0, 0);
            }
            Check(SUCCEEDED(status), deferredProbe ? "host.open-owned-deferred-symbol-dump" : "host.launch-owned-debuggee");
            if (FAILED(status))
            {
                break;
            }
            status = control->WaitForEvent(0, 10000);
            Check(SUCCEEDED(status), deferredProbe ? "host.deferred-dump-context" : "host.initial-break");
            if (FAILED(status))
            {
                break;
            }
            ULONG64 extensionHandle = 0;
            status = control->AddExtensionWide(argv[2], 0, &extensionHandle);
            std::printf("AddExtension HRESULT=0x%08x handle=0x%llx\n", static_cast<unsigned>(status), extensionHandle);
            Check(SUCCEEDED(status), "host.load-extension");
            if (deferredProbe)
            {
                RunCommand(control.Get(), capture.Get(), L"!kndbgx version", L"DbgEng ABI");
                ComPtr<IDebugSymbols3> symbols;
                client.As(&symbols);
                ULONG index = 0;
                ULONG64 base = 0;
                DEBUG_MODULE_PARAMETERS before = {};
                const bool deferred = symbols && symbols->GetModuleByModuleNameWide(L"kndbgx", 0, &index, &base) == S_OK &&
                                      symbols->GetModuleParameters(1, &base, 0, &before) == S_OK &&
                                      before.SymbolType == DEBUG_SYMTYPE_DEFERRED;
                Check(deferred, "host.annotation-fixture-starts-with-deferred-pdb");
                CommandResultData(control.Get(), capture.Get(), L"!kndbgx lm");
                DEBUG_MODULE_PARAMETERS inventory = {};
                Check(deferred && symbols->GetModuleParameters(1, &base, 0, &inventory) == S_OK &&
                          inventory.SymbolType == DEBUG_SYMTYPE_DEFERRED,
                      "host.module-bases-do-not-load-deferred-pdbs");
                const HMODULE extension = GetModuleHandleW(argv[2]);
                const auto exported = extension != nullptr ? GetProcAddress(extension, "DebugExtensionInitialize") : nullptr;
                ULONG64 rva = exported != nullptr ? reinterpret_cast<ULONG64>(exported) - reinterpret_cast<ULONG64>(extension) :
                                                   before.Size;
#ifdef KNDBGX_UI_TESTS
                // Incremental Debug exports can point at an ILT stub rather than the named function.
                if (rva < before.Size && before.Size - rva >= 5)
                {
                    std::array<unsigned char, 5> thunk = {};
                    SIZE_T read = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void *>(exported), thunk.data(),
                                          thunk.size(), &read) && read == thunk.size() && thunk[0] == 0xe9)
                    {
                        int32_t displacement = 0;
                        std::memcpy(&displacement, thunk.data() + 1, sizeof(displacement));
                        const int64_t target = static_cast<int64_t>(rva) + 5 + displacement;
                        rva = target >= 0 && static_cast<ULONG64>(target) < before.Size ? static_cast<ULONG64>(target) : before.Size;
                    }
                }
#endif
                const ULONG64 address = rva < before.Size ? base + rva : 0;
                std::printf("deferred.fixture-function-rva=0x%llx\n", rva);
                const auto resolved = CommandResultData(control.Get(), capture.Get(), L"!kndbgx db " + kncore::Hex(address) + L" L1");
                const auto &rows = resolved.Get(L"Rows").Items();
                DEBUG_MODULE_PARAMETERS after = {};
                Check(deferred && rows.size() == 1 &&
                          rows[0].Get(L"symbol").AsString(L"").find(L"DebugExtensionInitialize") != std::wstring::npos &&
                          rows[0].Get(L"symbolSource").AsString(L"") == L"LoadedDebuggerSymbols" &&
                          rows[0].Get(L"symbolAddress").AsString(L"") == kncore::Hex(address) &&
                          symbols->GetModuleParameters(1, &base, 0, &after) == S_OK && after.SymbolType == DEBUG_SYMTYPE_PDB,
                      "host.common-address-annotation-loads-the-deferred-owning-pdb");
                const auto dumpCi = CommandResultData(control.Get(), capture.Get(), L"!kndbgx !ci");
                Check(dumpCi.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unsupported" &&
                          dumpCi.Get(L"Rows").Items().empty(), "host.ci-dump-cannot-silently-query-host");
                const auto dumpHostCi = CommandResultData(control.Get(), capture.Get(), L"!kndbgx !ci /host");
                const auto &dumpHostRows = dumpHostCi.Get(L"Rows").Items();
                Check(dumpHostRows.size() == 1 && dumpHostRows[0].Get(L"scope").AsString(L"") == L"DebuggerHost" &&
                          dumpHostCi.Get(L"Metadata").Get(L"provenance").Get(L"source").AsString(L"") == L"HostSystemCodeIntegrity",
                      "host.ci-explicit-host-query-from-dump-retains-provenance");
                control->RemoveExtension(extensionHandle);
                break;
            }
            Check(ColdStartJob(control.Get(), capture.Get()), "host.rereview-cold-start-job-survives-observer-readiness");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx version", L"DbgEng ABI"), "host.modern-extension-abi");
            Check(GetModuleHandleW(argv[2]) != nullptr, "host.extension-module-present-after-lazy-load");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx status", L"user live"), "host.cli-local-client-target");
            const auto moduleInventory = CommandResultData(control.Get(), capture.Get(), L"!kndbgx lm");
            const auto &moduleRows = moduleInventory.Get(L"Rows").Items();
            Check(!moduleRows.empty() && std::any_of(moduleRows.begin(), moduleRows.end(), [](const auto &row)
                      {
                          return row.Get(L"symbolSource").AsString(L"") == L"ModuleRva";
                      }) && std::all_of(moduleRows.begin(), moduleRows.end(), [](const auto &row)
                      {
                          return row.Get(L"symbolSource").AsString(L"") != L"ModuleRva" ||
                              !row.Get(L"symbol").AsString(L"").ends_with(L"+0x0000000000000000");
                      }), "host.module-base-symbols-omit-zero-offset");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx ? 1+2", L"3"), "host.cli-expression-not-help");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx gateway", L"Unsupported"), "host.gate-exact-token");
            const auto stackCapture = CommandResultData(control.Get(), capture.Get(), L"!kndbgx stack");
            const auto &stackRows = stackCapture.Get(L"Rows").Items();
            const auto &stackContext = stackCapture.Get(L"Metadata").Get(L"analysis").Get(L"stackContext");
            Check(!stackRows.empty() && std::all_of(stackRows.begin(), stackRows.end(), [&](const auto &row)
                  {
                      return row.Get(L"kind").AsString(L"") == L"StackFrame" &&
                          row.Get(L"context").Write() == stackContext.Write();
                  }), "host.typed-stack-context-and-source");
            const auto registerCapture = CommandResultData(control.Get(), capture.Get(), L"!kndbgx registers rip");
            const auto &registerRows = registerCapture.Get(L"Rows").Items();
            Check(registerRows.size() == 1 && registerRows[0].Get(L"rawBytes").IsString(), "host.typed-register-read");
            ComPtr<IDebugSystemObjects4> registerSystem;
            ULONG registerPid = 0, registerTid = 0, registerEnginePid = 0, registerEngineTid = 0;
            const auto registerContext = registerRows.empty() ? knjson::Value() : registerRows[0].Get(L"context");
            const auto &registerIdentity = registerContext.Get(L"targetContext");
            Check(SUCCEEDED(client->QueryInterface(IID_PPV_ARGS(&registerSystem))) &&
                      registerSystem->GetCurrentProcessSystemId(&registerPid) == S_OK &&
                      registerSystem->GetCurrentThreadSystemId(&registerTid) == S_OK &&
                      registerSystem->GetCurrentProcessId(&registerEnginePid) == S_OK &&
                      registerSystem->GetCurrentThreadId(&registerEngineTid) == S_OK &&
                      registerIdentity.Get(L"pid").AsString(L"") == std::to_wstring(registerPid) &&
                      registerIdentity.Get(L"tid").AsString(L"") == std::to_wstring(registerTid) &&
                      !registerIdentity.Get(L"image").AsString(L"").empty() &&
                      registerContext.Get(L"engineProcessId").AsString(L"") == std::to_wstring(registerEnginePid) &&
                      registerContext.Get(L"engineThreadId").AsString(L"") == std::to_wstring(registerEngineTid),
                  "host.register-context-keeps-system-identities-separate-from-engine-ids");
            const auto &stackIdentity = stackContext.Get(L"targetContext");
            Check(stackIdentity.Get(L"pid").AsString(L"") == std::to_wstring(registerPid) &&
                      stackIdentity.Get(L"tid").AsString(L"") == std::to_wstring(registerTid) &&
                      !stackIdentity.Get(L"image").AsString(L"").empty() &&
                      stackContext.Get(L"engineProcessId").AsString(L"") == std::to_wstring(registerEnginePid) &&
                      stackContext.Get(L"engineThreadId").AsString(L"") == std::to_wstring(registerEngineTid) &&
                      stackContext.Get(L"processId").IsNull() && stackContext.Get(L"threadId").IsNull(),
                  "host.stack-metadata-keeps-system-identities-separate-from-engine-ids");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx event", L"LastEvent"), "host.typed-event-read");
            const auto ciRefusal = CommandResultData(control.Get(), capture.Get(), L"!kndbgx !ci");
            Check(ciRefusal.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unsupported" &&
                      ciRefusal.Get(L"Rows").Items().empty(), "host.ci-user-target-cannot-silently-query-host");
            const auto hostCi = CommandResultData(control.Get(), capture.Get(), L"!kndbgx !ci /host");
            const auto &ciRows = hostCi.Get(L"Rows").Items();
            const bool ciKnown = ciRows.size() == 1 && ciRows[0].Get(L"known").AsBool(false);
            std::printf("host.ciKnown=%s\n", ciKnown ? "true" : "false");
            Check(ciRows.size() == 1 && ciRows[0].Get(L"scope").AsString(L"") == L"DebuggerHost" &&
                      hostCi.Get(L"Metadata").Get(L"provenance").Get(L"source").AsString(L"") == L"HostSystemCodeIntegrity" &&
                      (ciKnown ? ciRows[0].Get(L"hvciEnabled").IsBool() : ciRows[0].Get(L"hvciEnabled").IsNull()),
                  "host.ci-explicit-host-result-keeps-provenance-and-unknowns");
            const auto hostHv = JobResultData(control.Get(), capture.Get(), L"!kndbgx !hv");
            const auto &hvRows = hostHv.Get(L"Rows").Items();
            Check(hvRows.size() == 2 && hvRows[0].Get(L"scope").AsString(L"") == L"DebuggerHost" &&
                      hvRows[1].Get(L"scope").AsString(L"") == L"Debuggee" &&
                      (!hvRows[0].Get(L"hardwareFeaturesAvailable").AsBool(false) ||
                       hvRows[0].Get(L"interfaceSignature").AsString(L"") == kncore::Hex(0x31237648)),
                  "host.hv-qualified-features-keep-host-and-target-scopes-separate");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx model", L"available"), "host.data-model-capability-query");
            capture->Take();
            control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, L"!kndbgx registers rip", DEBUG_EXECUTE_NOT_LOGGED);
            const auto sharedOutput = capture->Take();
            const auto sharedAt = sharedOutput.find(L"[result] ");
            const auto sharedId = sharedAt == std::wstring::npos ? L"" : knutil::Trim(sharedOutput.substr(sharedAt + 9));
            Check(!sharedId.empty() && RunCommand(control.Get(), capture.Get(), L"!kndbgx result-read " + sharedId, L"rawBytes"),
                  "host.cli-shared-result-readable");
            capture->Take();
            control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, L"!kndbgx model", DEBUG_EXECUTE_NOT_LOGGED);
            const bool dataModelAvailable = capture->Take().find(L"\"available\":true") != std::wstring::npos;
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx model publish " + sharedId,
                             dataModelAvailable ? L"Result page available in the host" : L"Data Model publication unavailable"),
                  dataModelAvailable ? "host.data-model-page-publication" : "host.data-model-unavailable-keeps-cli-results");
            std::printf("host.dataModelAvailable=%s\n", dataModelAvailable ? "true" : "false");
            if (dataModelAvailable)
            {
                ComPtr<IHostDataModelAccess> access;
                ComPtr<IDataModelManager> manager;
                ComPtr<IDebugHost> modelHost;
                ComPtr<IModelObject> root, debugger, models, id;
                VARIANT value;
                VariantInit(&value);
                const bool read = SUCCEEDED(client.As(&access)) && SUCCEEDED(access->GetDataModel(&manager, &modelHost)) &&
                                  SUCCEEDED(manager->GetRootNamespace(&root)) &&
                                  SUCCEEDED(root->GetKeyValue(L"Debugger", &debugger, nullptr)) &&
                                  SUCCEEDED(debugger->GetKeyValue(L"Models", &models, nullptr)) &&
                                  SUCCEEDED(models->GetKeyValue(L"KNDbgX", &publishedModel, nullptr)) &&
                                  SUCCEEDED(publishedModel->GetKeyValue(L"ResultId", &id, nullptr)) &&
                                  SUCCEEDED(id->GetIntrinsicValueAs(VT_BSTR, &value));
                publishedId = read && value.bstrVal != nullptr ? value.bstrVal : L"";
                VariantClear(&value);
                Check(read && publishedId == sharedId, "host.data-model-cli-identical-result-id");
                Check(RunCommand(control.Get(), capture.Get(), L"dx -r4 Debugger.Models.KNDbgX", L"rawBytes"),
                      "host.dx-reads-published-register-values");
            }

            ComPtr<IDebugSymbols3> symbols;
            ComPtr<IDebugDataSpaces> memory;
            client.As(&symbols);
            client.As(&memory);
            ULONG64 imageBase = 0;
            symbols->GetModuleByIndex(0, &imageBase);
            const ULONG64 fixture =
                imageBase + reinterpret_cast<ULONG64>(KnFixtureBytes) - reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
            const auto displayAddress = [](ULONG64 address)
            {
                auto text = kncore::Hex(address).substr(2);
                text.insert(8, L"`");
                return text;
            };
            DEBUG_VALUE instruction = {};
            const bool haveInstruction = control->EvaluateWide(L"@$ip", DEBUG_VALUE_INT64, &instruction, nullptr) == S_OK;
            Check(haveInstruction && RunCommand(control.Get(), capture.Get(), L"!kndbgx db",
                                                 (L"[memory] start=" + displayAddress(instruction.I64)).c_str()),
                  "host.memory-omitted-address-starts-at-current-instruction");
            const auto currentCode = CommandResultData(control.Get(), capture.Get(), L"!kndbgx u L1");
            Check(haveInstruction && currentCode.Get(L"Rows").Items().size() == 1 &&
                      currentCode.Get(L"Rows").Items()[0].Get(L"address").AsString(L"") == kncore::Hex(instruction.I64),
                  "host.disassembly-omitted-address-starts-at-current-instruction");
            const auto absentCode = CommandResultData(control.Get(), capture.Get(), L"!kndbgx u 0 L1");
            Check(absentCode.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unavailable" &&
                      absentCode.Get(L"Rows").Items().empty(), "host.disassembly-unreadable-address-is-not-a-decoded-row");
            wchar_t firstInstruction[4096] = {};
            ULONG64 nextInstruction = 0;
            const bool haveNextInstruction = haveInstruction && control->DisassembleWide(instruction.I64, 0, firstInstruction,
                _countof(firstInstruction), nullptr, &nextInstruction) == S_OK;
            const auto &currentInstructions = currentCode.Get(L"Rows").Items();
            ULONG readInstructionBytes = 0;
            std::array<unsigned char, 16> instructionBytes = {};
            const bool verifiedInstructionBytes = haveNextInstruction && nextInstruction > instruction.I64 &&
                nextInstruction - instruction.I64 <= instructionBytes.size() &&
                memory->ReadVirtual(instruction.I64, instructionBytes.data(),
                    static_cast<ULONG>(nextInstruction - instruction.I64), &readInstructionBytes) == S_OK &&
                readInstructionBytes == nextInstruction - instruction.I64;
            Check(verifiedInstructionBytes && currentInstructions.size() == 1 &&
                      currentInstructions[0].Get(L"nextAddress").AsString(L"") == kncore::Hex(nextInstruction) &&
                      currentInstructions[0].Get(L"bytes").AsString(L"") ==
                          kncore::BytesHex(std::span<const unsigned char>(instructionBytes.data(), readInstructionBytes)) &&
                      currentInstructions[0].Get(L"instruction").AsString(L"") == firstInstruction &&
                      !currentInstructions[0].Get(L"instructionText").AsString(L"").empty(),
                  "host.disassembly-rows-retain-verified-bytes-and-exact-next-address");
            const auto continuedCode = CommandResultData(control.Get(), capture.Get(), L"!kndbgx u L1");
            Check(haveNextInstruction && continuedCode.Get(L"Rows").Items().size() == 1 &&
                      continuedCode.Get(L"Rows").Items()[0].Get(L"address").AsString(L"") == kncore::Hex(nextInstruction),
                  "host.failed-disassembly-preserves-last-successful-cursor");
            const ULONG64 instructionFixture = imageBase + reinterpret_cast<ULONG64>(KnInstructionFixture) -
                                               reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
            const auto invalidInstruction = CommandResultData(control.Get(), capture.Get(),
                L"!kndbgx u " + kncore::Hex(instructionFixture + 1) + L" L1");
            if (!invalidInstruction.Get(L"Rows").Items().empty())
            {
                std::wprintf(L"Unexpected decoded instruction: %s\n", invalidInstruction.Get(L"Rows").Write().c_str());
            }
            Check(invalidInstruction.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unavailable" &&
                      invalidInstruction.Get(L"Rows").Items().empty(),
                  "host.readable-invalid-opcode-is-not-a-decoded-instruction");
            const auto instructionPrefix = CommandResultData(control.Get(), capture.Get(),
                L"!kndbgx u " + kncore::Hex(instructionFixture) + L" L2");
            Check(instructionPrefix.Get(L"Metadata").Get(L"status").AsString(L"") == L"Partial" &&
                      instructionPrefix.Get(L"Rows").Items().size() == 1 &&
                      instructionPrefix.Get(L"Metadata").Get(L"coverage").Get(L"decodedEntries").AsString(L"") == L"1" &&
                      instructionPrefix.Get(L"Metadata").Get(L"coverage").Get(L"unknownEntries").AsString(L"") == L"1",
                  "host.invalid-opcode-retains-only-decoded-prefix");
            Check(instructionPrefix.Get(L"Rows").Items().size() == 1 &&
                      instructionPrefix.Get(L"Rows").Items()[0].Get(L"bytes").AsString(L"") == L"90" &&
                      instructionPrefix.Get(L"Rows").Items()[0].Get(L"instructionText").AsString(L"") == L"nop",
                  "host.disassembly-instruction-text-excludes-address-and-encoded-bytes");
            const auto invalidFunction = CommandResultData(control.Get(), capture.Get(),
                L"!kndbgx uf " + kncore::Hex(instructionFixture + 1));
            Check(invalidFunction.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unavailable" &&
                      invalidFunction.Get(L"Rows").Items().empty(),
                  "host.function-invalid-opcode-is-unavailable");
            ULONG assemblyOptions = 0;
            const bool haveAssemblyOptions = control->GetAssemblyOptions(&assemblyOptions) == S_OK;
            const bool changedAssemblyOptions = haveAssemblyOptions &&
                control->SetAssemblyOptions(assemblyOptions | DEBUG_ASMOPT_NO_CODE_BYTES | DEBUG_ASMOPT_SOURCE_LINE_NUMBER) == S_OK;
            const auto noBytesInvalid = CommandResultData(control.Get(), capture.Get(),
                L"!kndbgx u " + kncore::Hex(instructionFixture + 1) + L" L1");
            const auto noBytesValid = CommandResultData(control.Get(), capture.Get(),
                L"!kndbgx u " + kncore::Hex(instructionFixture + 2) + L" L1");
            Check(changedAssemblyOptions && noBytesInvalid.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unavailable" &&
                      noBytesInvalid.Get(L"Rows").Items().empty() &&
                      noBytesValid.Get(L"Metadata").Get(L"status").AsString(L"") == L"Success" &&
                      noBytesValid.Get(L"Rows").Items().size() == 1,
                  "host.instruction-validation-respects-assembly-display-options");
            Check(haveAssemblyOptions && control->SetAssemblyOptions(assemblyOptions) == S_OK,
                  "host.instruction-validation-restores-test-display-options");
            const auto unreadableDisplay = CommandResultData(control.Get(), capture.Get(), L"!kndbgx db 0 L10");
            Check(unreadableDisplay.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unavailable", "host.memory-unreadable-status");
            const auto &missingRows = unreadableDisplay.Get(L"Rows").Items();
            Check(missingRows.size() == 1 && missingRows[0].Get(L"bytes").Items().size() == 16 &&
                      std::all_of(missingRows[0].Get(L"bytes").Items().begin(), missingRows[0].Get(L"bytes").Items().end(),
                          [](const auto &value)
                          {
                              return value.IsNull();
                          }), "host.memory-view-unreadable-range-is-not-zero-filled");
            const auto readableDisplay = CommandResultData(control.Get(), capture.Get(), L"!kndbgx db " + kncore::Hex(fixture) + L" L3");
            Check(readableDisplay.Get(L"Metadata").Get(L"status").AsString(L"") == L"Success" &&
                      readableDisplay.Get(L"Metadata").Get(L"coverage").Get(L"complete").AsBool(false),
                  "host.memory-readable-byte-coverage");
            const auto &memoryRows = readableDisplay.Get(L"Rows").Items();
            Check(memoryRows.size() == 1 && memoryRows[0].Get(L"kind").AsString(L"") == L"MemoryBytes" &&
                      memoryRows[0].Get(L"address").AsString(L"") == kncore::Hex(fixture) &&
                      memoryRows[0].Get(L"addressSpace").AsString(L"") == L"virtual" &&
                      memoryRows[0].Get(L"bytes").Write() == L"[49,49,49]", "host.memory-view-retains-exact-target-bytes");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx dw L2",
                             (L"[memory] start=" + displayAddress(fixture + 3) + L" length=0x4").c_str()),
                  "host.memory-length-only-continues-across-display-formats");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx dq",
                             (L"[memory] start=" + displayAddress(fixture + 7)).c_str()),
                  "host.memory-no-arguments-continues-with-default-length");
            const auto targetAddress = [&](const void *local)
            {
                return imageBase + reinterpret_cast<ULONG64>(local) - reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
            };
            const auto malformedString =
                CommandResultData(control.Get(), capture.Get(), L"!kndbgx du " + kncore::Hex(targetAddress(KnMalformedString)));
            Check(malformedString.Get(L"Metadata").Get(L"status").AsString(L"") == L"Partial" &&
                      malformedString.Get(L"Metadata").Get(L"coverage").Get(L"stopReason").AsString(L"") == L"InvalidUtf16",
                  "host.memory-malformed-string-remains-retained");
            const auto shortWide = CommandResultData(control.Get(), capture.Get(),
                                                     L"!kndbgx du " + kncore::Hex(targetAddress(KnMalformedString)) + L" L1");
            Check(shortWide.Get(L"Metadata").Get(L"status").AsString(L"") == L"Success" &&
                      shortWide.Get(L"Rows").Items().size() == 1 && shortWide.Get(L"Rows").Items()[0].Get(L"text").AsString(L"") == L"A" &&
                      shortWide.Get(L"Metadata").Get(L"coverage").Get(L"readEntries").AsString(L"") == L"2",
                  "host.memory-wide-length-counts-code-units-without-reading-tail");
            const auto shortAscii = CommandResultData(control.Get(), capture.Get(),
                                                      L"!kndbgx da " + kncore::Hex(targetAddress(KnAnsiString)) + L" L1");
            Check(shortAscii.Get(L"Metadata").Get(L"status").AsString(L"") == L"Success" &&
                      shortAscii.Get(L"Rows").Items().size() == 1 && shortAscii.Get(L"Rows").Items()[0].Get(L"text").AsString(L"") == L"A" &&
                      shortAscii.Get(L"Metadata").Get(L"coverage").Get(L"readEntries").AsString(L"") == L"1",
                  "host.memory-ascii-length-is-enforced");
            const auto unterminatedString =
                CommandResultData(control.Get(), capture.Get(), L"!kndbgx da " + kncore::Hex(targetAddress(KnUnterminatedString.data())));
            Check(unterminatedString.Get(L"Metadata").Get(L"status").AsString(L"") == L"Partial" &&
                      unterminatedString.Get(L"Metadata").Get(L"coverage").Get(L"stopReason").AsString(L"") == L"StringLimit",
                  "host.memory-unterminated-string-not-complete");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx da " + kncore::Hex(targetAddress(KnAnsiString)), L"A\\x80"),
                  "host.memory-high-byte-escaped-without-sign-extension");
            CheckMemoryHoles(client.Get(), control.Get(), capture.Get(), argv[3]);
            const auto rawDump = CommandResultData(control.Get(), capture.Get(),
                                                   L"!kndbgx dump-raw " + kncore::Hex(fixture) + L" 3 \"" + argv[3] + L".raw\"");
            Check(rawDump.Get(L"Metadata").Get(L"analysis").Get(L"artifactCommitted").AsBool(false) &&
                      rawDump.Get(L"Metadata").Get(L"coverage").Get(L"readEntries").AsString(L"") == L"3",
                  "host.raw-dump-committed-receipt");
            const ULONG64 pointerFixture =
                imageBase + reinterpret_cast<ULONG64>(&KnFixturePointer) - reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
            capture->Take();
            control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, (L"!kndbgx dqs " + kncore::Hex(pointerFixture) + L" L1").c_str(),
                                 DEBUG_EXECUTE_NOT_LOGGED);
            const auto annotated = capture->Take();
            const auto firstBang = annotated.find(L'!');
            Check(firstBang != std::wstring::npos && annotated.find(L'!', firstBang + 1) == std::wstring::npos &&
                      annotated.find(L"KnFixtureBytes") != std::wstring::npos,
                  "host.memory-symbol-single-module-prefix");
            const auto pointerResult = CommandResultData(control.Get(), capture.Get(),
                                                         L"!kndbgx dqs " + kncore::Hex(pointerFixture) + L" L1");
            const auto &pointerRows = pointerResult.Get(L"Rows").Items();
            Check(pointerRows.size() == 1 && pointerRows[0].Get(L"kind").AsString(L"") == L"MemoryPointer" &&
                      pointerRows[0].Get(L"pointer").AsString(L"") == kncore::Hex(fixture) &&
                      pointerRows[0].Get(L"symbol").AsString(L"").find(L"KnFixtureBytes") != std::wstring::npos &&
                      pointerRows[0].Get(L"symbolSource").AsString(L"") == L"LoadedDebuggerSymbols" &&
                      pointerRows[0].Get(L"symbolField").AsString(L"") == L"pointer",
                  "host.pointer-table-symbol-describes-pointer-value-not-storage-address");
            const auto boundNearestResult = CommandResultData(control.Get(), capture.Get(),
                                                              L"!kndbgx ln " + kncore::Hex(fixture + 1));
            const auto &boundNearestRows = boundNearestResult.Get(L"Rows").Items();
            Check(boundNearestRows.size() == 1 && boundNearestRows[0].Get(L"symbolSource").AsString(L"") == L"LoadedDebuggerSymbols" &&
                      boundNearestRows[0].Get(L"symbolAddress").AsString(L"") == kncore::Hex(fixture + 1) &&
                      boundNearestRows[0].Get(L"symbolDisplacement").AsString(L"") == kncore::Hex(1) &&
                      boundNearestRows[0].Get(L"displacement").AsString(L"") == kncore::Hex(1),
                  "host.nearest-symbol-uses-the-shared-verified-address-and-displacement");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx navigate va " + kncore::Hex(fixture + 1),
                             L"\"symbolSource\":\"LoadedDebuggerSymbols\""),
                  "host.navigation-console-emits-verified-symbol-provenance-before-storage");
            capture->Take();
            const HRESULT historyStatus = control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, L"!kndbgx history", DEBUG_EXECUTE_NOT_LOGGED);
            const auto historyText = capture->Take();
            knjson::Value boundHistory;
            const auto historyStart = historyText.find(L'[');
            const bool historyParsed = historyStart != std::wstring::npos && knjson::Parse(historyText.substr(historyStart), &boundHistory);
            const auto &boundHistoryRows = boundHistory.Items();
            Check(historyStatus == S_OK && historyParsed && !boundHistoryRows.empty() &&
                      boundHistoryRows.back().Get(L"address").AsString(L"") == kncore::Hex(fixture + 1) &&
                      boundHistoryRows.back().Get(L"symbolSource").AsString(L"") == L"LoadedDebuggerSymbols" &&
                      boundHistoryRows.back().Get(L"symbolDisplacement").AsString(L"") == kncore::Hex(1),
                  "host.navigation-history-retains-verified-name-address-and-displacement");
            const auto expressionResult = CommandResultData(control.Get(), capture.Get(), L"!kndbgx ? 1+2");
            Check(expressionResult.Get(L"Rows").Items().size() == 1 &&
                      expressionResult.Get(L"Rows").Items()[0].Get(L"value").AsString(L"") == kncore::Hex(3),
                  "host.expression-retains-a-structured-value-row");
            wchar_t pointerModule[1024] = {};
            symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, 0, 0, pointerModule, _countof(pointerModule), nullptr);
            const auto typedPointer = CommandResultData(control.Get(), capture.Get(),
                                                        L"!kndbgx dt " + std::wstring(pointerModule) + L"!KN_NESTED_LAYOUT_FIXTURE " +
                                                            kncore::Hex(targetAddress(&KnNestedLayoutFixture)));
            bool knownNullPointer = false;
            for (const auto &field : typedPointer.Get(L"Rows").Items())
            {
                if (field.Get(L"field").AsString(L"") == L"Pointer")
                {
                    knownNullPointer = field.Get(L"pointer").AsString(L"") == kncore::Hex(0) &&
                                       field.Get(L"symbolSource").AsString(L"") == L"NullAddress";
                }
            }
            Check(knownNullPointer, "host.typed-pointer-value-is-distinct-from-an-unreadable-field");
            const auto overflowingType = CommandResultData(control.Get(), capture.Get(),
                                                            L"!kndbgx dt " + std::wstring(pointerModule) +
                                                                L"!KN_NESTED_LAYOUT_FIXTURE 0xffffffffffffffff");
            Check(overflowingType.Get(L"Metadata").Get(L"status").AsString(L"") == L"InvalidInput" &&
                      overflowingType.Get(L"Rows").Items().empty(),
                  "host.typed-instance-overflow-is-rejected-before-field-observations");
            unsigned char original[3] = {};
            ULONG transferred = 0;
            Check(SUCCEEDED(memory->ReadVirtual(fixture, original, 3, &transferred)) && transferred == 3 && original[0] == 0x31 &&
                      original[1] == 0x31,
                  "host.owned-mutation-fixture");
            const auto approval = PrepareWrite(control.Get(), capture.Get(), fixture);
            memory->ReadVirtual(fixture, original, 3, &transferred);
            Check(!approval.empty() && original[0] == 0x31, "host.real-plan-does-not-write");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx approve missing-plan missing-token", L"UnknownPlanOrApprovalToken"),
                  "host.memory-write-still-requires-an-approval-token");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx navigate va " + kncore::Hex(fixture), L"AddressObservation"),
                  "host.scoped-address-navigation");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx bookmark \"owned fixture\"", L"Bookmark saved"),
                  "host.observation-bookmark");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx bookmarks", L"owned fixture"), "host.bookmark-roundtrip");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx " + approval, L"AppliedAndVerified"),
                  "host.real-approved-write-verifies");
            memory->ReadVirtual(fixture, original, 3, &transferred);
            Check(original[0] == 0x41 && original[1] == 0x42 && original[2] == 0x43, "host.approved-bytes-exact");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx " + approval, L"UnknownPlanOrApprovalToken"),
                  "host.real-approval-replay-denied");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx eb " + kncore::Hex(fixture) + L" 50 100", L"InvalidMutation"),
                  "host.invalid-late-value-rejected");
            memory->ReadVirtual(fixture, original, 3, &transferred);
            Check(original[0] == 0x41, "host.invalid-command-wrote-zero");
            const auto architecturePlan = PrepareWrite(control.Get(), capture.Get(), fixture);
            const bool switched = control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386) == S_OK;
            const bool switchedBack = control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64) == S_OK;
            Check(switched && switchedBack && !architecturePlan.empty() &&
                      RunCommand(control.Get(), capture.Get(), L"!kndbgx " + architecturePlan, L"Stale"),
                  "host.rereview-cli-idle-effective-context-roundtrip-invalidates-plan");
            const auto symbolsPlan = PrepareWrite(control.Get(), capture.Get(), fixture);
            const bool reloaded =
                RunCommand(control.Get(), capture.Get(), L".reload /f " + std::filesystem::path(self).filename().wstring(), nullptr);
            Check(reloaded && !symbolsPlan.empty() && RunCommand(control.Get(), capture.Get(), L"!kndbgx " + symbolsPlan, L"Stale"),
                  "host.rereview-cli-idle-symbol-reload-invalidates-plan");
            memory->ReadVirtual(fixture, original, 3, &transferred);
            Check(original[0] == 0x41 && original[1] == 0x42 && original[2] == 0x43, "host.rereview-cli-stale-plans-preserve-owned-bytes");
            const auto staleApproval = PrepareWrite(control.Get(), capture.Get(), fixture);
            const unsigned char outsideChange = 0x55;
            memory->WriteVirtual(fixture, const_cast<unsigned char *>(&outsideChange), 1, &transferred);
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx " + staleApproval, L"Stale"), "host.real-original-state-recheck");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx policy readonly", L"global write policy has been removed"),
                  "host.legacy-policy-reports-removal");

            auto worker =
                std::async(std::launch::async,
                           [&]()
                           {
                               knengine::DbgSession session;
                               const bool initialized = session.Initialize();
                               knengine::SessionStatus observed = {};
                               session.QueryStatus(&observed);
                               ULONG64 instruction = 0;
                               const bool typed = session.ReadRegisterHex(L"rip", &instruction);
                               knengine::ContextGuard restore(session);
                               const bool restored = restore.Valid() && restore.Restore();
                               std::printf("context capture=0x%lx restore=0x%lx valid=%d restored=%d\n", restore.CapturedMask(),
                                           restore.RestoredMask(), restore.Valid(), restored);
                               return initialized && observed.TargetPresent && observed.Stopped && typed && instruction != 0 && restored;
                           });
            Check(worker.get(), "host.worker-owned-seed-sees-same-target");
#ifdef KNDBGX_UI_TESTS
            auto contextProbe =
                std::async(std::launch::async,
                           [&]()
                           {
                               knengine::DbgSession session;
                               if (!session.Initialize())
                               {
                                   return false;
                               }
                               session.RefreshStamp();
                               {
                                   std::lock_guard lock(knengine::SessionTraceMutex);
                                   knengine::SessionTrace.clear();
                               }
                               const auto before = knengine::Epochs().Stamp();
                               bool restored = false;
                               {
                                   knengine::ContextGuard guard(session);
                                   const bool changed = session.Control()->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386) == S_OK;
                                   restored = changed && guard.Restore();
                               }
                               session.Client()->DispatchCallbacks(100);
                               const auto after = knengine::Epochs().Stamp();
                               std::lock_guard lock(knengine::SessionTraceMutex);
                               for (const auto &event : knengine::SessionTrace)
                               {
                                   std::printf("observer.owner=%lu caller=%lu kind=%u flags=0x%lx suppressed=%d\n", event.Owner,
                                               event.Caller, event.Kind, event.Flags, event.Suppressed);
                               }
                               return restored && before.ContextGeneration == after.ContextGeneration && !knengine::SessionTrace.empty();
                           });
            Check(contextProbe.get(), "third.T14.real-engine-internal-context-roundtrip-does-not-invalidate-own-epoch");
            std::promise<bool> observerReady;
            std::atomic<bool> stopObserver{false};
            auto observerProbe = std::async(std::launch::async,
                                            [&]()
                                            {
                                                knengine::DbgSession session;
                                                const bool initialized = session.Initialize();
                                                observerReady.set_value(initialized);
                                                // Delay only the owned observer, never the host client or its message pump.
                                                Sleep(200);
                                                while (initialized && !stopObserver.load())
                                                {
                                                    session.Client()->DispatchCallbacks(50);
                                                }
                                                return initialized;
                                            });
            const bool observing = observerReady.get_future().get();
            const auto observedBefore = knengine::Epochs().Stamp();
            const bool externalRoundtrip = observing && control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386) == S_OK &&
                                           control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64) == S_OK;
            const bool invalidated = AwaitUi(
                [&]()
                {
                    return knengine::Epochs().Stamp().ContextGeneration > observedBefore.ContextGeneration;
                },
                2000);
            stopObserver.store(true);
            Check(observerProbe.get() && externalRoundtrip && invalidated,
                  "third.T13.real-engine-delayed-observer-captures-external-context-roundtrip");
#endif
            auto layoutWorker = std::async(
                std::launch::async,
                [&]()
                {
                    knengine::DbgSession session;
                    session.Initialize();
                    knengine::LayoutResolver layout(session);
                    wchar_t name[1024] = {};
                    session.Symbols()->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, 0, 0, name, _countof(name), nullptr);
                    const auto loadedIdentity = layout.LoadedIdentity(name);
                    const auto zero = layout.Field(name, L"KN_LAYOUT_FIXTURE", L"Zero");
                    const auto array = layout.Field(name, L"KN_LAYOUT_FIXTURE", L"Buckets");
                    const auto bits = layout.Field(name, L"KN_LAYOUT_FIXTURE", L"Flags");
                    const auto signedField = layout.Field(name, L"KN_LAYOUT_FIXTURE", L"Signed");
                    const auto identity = layout.Identity(name);
                    const auto descriptor = layout.Describe(name, L"KN_LAYOUT_FIXTURE");
                    Check(descriptor && descriptor->Complete && descriptor->Fields.size() == 6, "host.layout-complete-field-enumeration");
                    Check(identity && identity->Matched && !identity->PdbGuid.empty(), "host.layout-matched-pdb-identity");
                    const auto diagnosticStamp = session.RefreshStamp();
                    const auto diagnosticModules = knengine::ReadSymbolModules(session, diagnosticStamp, 0);
                    Check(diagnosticModules.Get(L"ok").AsBool(false) && !diagnosticModules.Get(L"modules").Items().empty(),
                          "host.symbol-health-inventory-uses-current-module-metadata");
                    if (!diagnosticModules.Get(L"modules").Items().empty())
                    {
                        const auto key = kncore::ParseSymbolModuleKey(diagnosticModules.Get(L"modules").Items()[0].Get(L"key"));
                        Check(key.has_value(), "host.symbol-health-module-key-decodes");
                        if (key)
                        {
                            const auto health = knengine::InspectSymbolHealth(session, diagnosticStamp, *key, L"KN_LAYOUT_FIXTURE", L"Zero");
                            Check(health.Get(L"ok").AsBool(false) && health.Get(L"imageMatch").AsString(L"") == L"Matched" &&
                                      health.Get(L"requestedType").Get(L"state").AsString(L"") == L"Available" &&
                                      health.Get(L"requestedType").Get(L"fieldOffset").AsString(L"") == L"0",
                                  "host.symbol-health-matched-pdb-and-real-zero-offset-field");
                            const auto missing = knengine::InspectSymbolHealth(session, diagnosticStamp, *key, L"KN_LAYOUT_FIXTURE", L"NotPresent");
                            Check(missing.Get(L"imageMatch").AsString(L"") == L"Matched" &&
                                      missing.Get(L"requestedType").Get(L"state").AsString(L"") == L"FieldUnavailable" &&
                                      !missing.Get(L"requestedType").Get(L"nativeError").IsNull(),
                                  "host.symbol-health-missing-field-does-not-become-pdb-mismatch");
                            auto reused = *key;
                            ++reused.Timestamp;
                            const auto stale = knengine::InspectSymbolHealth(session, diagnosticStamp, reused, L"", L"");
                            Check(!stale.Get(L"ok").AsBool(true) && stale.Get(L"error").AsString(L"") == L"StaleModuleIdentity",
                                  "host.symbol-health-rejects-reused-module-address");
                        }
                    }
                    Check(loadedIdentity && identity && loadedIdentity->Key() == identity->Key() && zero,
                          "host.loaded-identity-does-not-poison-later-field-metadata");
                    ULONG loaded = 0;
                    ULONG unloaded = 0;
                    session.Symbols()->GetNumberModules(&loaded, &unloaded);
                    bool deferredChecked = false;
                    for (ULONG index = 0; index < loaded && !deferredChecked; ++index)
                    {
                        DEBUG_MODULE_PARAMETERS before = {};
                        wchar_t deferredName[1024] = {};
                        if (session.Symbols()->GetModuleParameters(1, nullptr, index, &before) == S_OK &&
                            before.SymbolType == DEBUG_SYMTYPE_DEFERRED &&
                            session.Symbols()->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, index, 0, deferredName,
                                                                      _countof(deferredName), nullptr) == S_OK)
                        {
                            const auto unavailable = layout.LoadedIdentity(deferredName);
                            const auto health = knengine::InspectSymbolHealth(session, session.RefreshStamp(),
                                {before.Base, before.Size, before.TimeDateStamp, before.Checksum}, L"", L"");
                            Check(health.Get(L"ok").AsBool(false) && health.Get(L"module").Get(L"loadState").AsString(L"") == L"Deferred" &&
                                      health.Get(L"imageMatch").AsString(L"") == L"Unknown" &&
                                      health.Get(L"requestedType").Get(L"state").AsString(L"") == L"NotRequested",
                                  "host.symbol-health-metadata-inspection-preserves-deferred-state");
                            DEBUG_MODULE_PARAMETERS after = {};
                            deferredChecked = !unavailable &&
                                              session.Symbols()->GetModuleParameters(1, nullptr, index, &after) == S_OK &&
                                              after.SymbolType == DEBUG_SYMTYPE_DEFERRED;
                            break;
                        }
                    }
                    Check(deferredChecked, "host.loaded-identity-preserves-deferred-symbols");
                    Check(zero && zero->Offset == 0 && zero->Size == 4 && zero->SimpleWritable(), "host.layout-offset-zero-width-and-kind");
                    Check(array && array->ArrayCount == 37u && array->ElementSize == 8u && array->Size == 296,
                          "host.layout-pdb-array-count-not-structure-remainder");
                    Check(array && array->LeafKind == kncore::FieldKind::Pointer, "host.layout-pointer-array-leaf-is-not-composite");
                    const auto nested = layout.Field(name, L"KN_NESTED_LAYOUT_FIXTURE", L"Embedded");
                    const auto records = layout.Field(name, L"KN_NESTED_LAYOUT_FIXTURE", L"Records");
                    const auto pointer = layout.Field(name, L"KN_NESTED_LAYOUT_FIXTURE", L"Pointer");
                    const auto leaf = kncore::ArrayElement(records, 5, true);
                    const auto nestedZero = kncore::NestedField(leaf, zero);
                    Check(nested && kncore::NestedField(nested, zero) && records && records->LeafKind == kncore::FieldKind::Composite &&
                              nestedZero &&
                              nestedZero->Offset == offsetof(KN_NESTED_LAYOUT_FIXTURE, Records) + 5 * sizeof(KN_LAYOUT_FIXTURE),
                          "host.layout-nested-composite-array-retains-pdb-kind-and-offset");
                    Check(pointer && !kncore::NestedField(pointer, zero) && !kncore::NestedField(array, zero),
                          "host.layout-pointer-and-array-cannot-be-implicit-containers");
                    Check(bits && bits->BitOffset == 0u && bits->BitWidth == 3u && !bits->SimpleWritable(),
                          "host.layout-bitfield-contract");
                    Check(signedField && signedField->Kind == kncore::FieldKind::Signed, "host.layout-signedness-from-pdb");
                    Check(!layout.Field(name, L"KN_LAYOUT_FIXTURE", L"Absent"), "host.layout-missing-field-not-zero");
                    const auto missingDiagnostic = layout.Diagnostic();
                    const bool otherMissing = !layout.Field(name, L"KN_LAYOUT_FIXTURE", L"AnotherAbsent");
                    const auto otherDiagnostic = layout.Diagnostic();
                    Check(otherMissing && !missingDiagnostic.empty() && missingDiagnostic != otherDiagnostic &&
                              !layout.Field(name, L"KN_LAYOUT_FIXTURE", L"Absent") && layout.Diagnostic() == missingDiagnostic,
                          "host.layout-cached-field-retains-own-failure-diagnostic");
                    GUID wrong = {};
                    knengine::PdbMetadata mismatch;
                    Check(!mismatch.Open(std::filesystem::path(self).replace_extension(L".pdb").wstring(), wrong, 1),
                          "host.layout-pdb-guid-mismatch-rejected");
                    Check(!mismatch.FieldAbsent(L"KN_LAYOUT_FIXTURE", L"Absent"), "host.layout-unavailable-provider-is-not-field-absence");
                    GUID actual = {};
                    knengine::PdbMetadata presence;
                    const bool opened =
                        identity && CLSIDFromString(identity->PdbGuid.c_str(), &actual) == S_OK &&
                        presence.Open(std::filesystem::path(self).replace_extension(L".pdb").wstring(), actual, identity->PdbAge);
                    Check(opened && presence.FieldAbsent(L"KN_LAYOUT_FIXTURE", L"Absent") &&
                              presence.FieldAbsent(L"KN_MISSING_LAYOUT_FIXTURE", L"Absent"),
                          "host.layout-profile-absence-proved-by-matched-pdb");
                    Check(opened && !presence.FieldAbsent(L"KN_LAYOUT_FIXTURE", L"Zero") &&
                              !presence.FieldAbsent(L"KN_LAYOUT_FIXTURE", L"Flags") &&
                              !presence.FieldAbsent(L"KN_LAYOUT_FIXTURE", L"Buckets.Absent"),
                          "host.layout-declared-or-unverifiable-member-is-not-absent");
                    if (!array || !array->ArrayCount)
                    {
                        std::wprintf(L"layout module=%s zero=%d array=%d bits=%d diagnostic=%s\n", name, zero.has_value(),
                                     array.has_value(), bits.has_value(), layout.Diagnostic().c_str());
                    }
                    return true;
                });
            layoutWorker.get();
            wchar_t fixtureModule[1024] = {};
            symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, 0, 0, fixtureModule, _countof(fixtureModule), nullptr);
            const ULONG64 typedFixture =
                imageBase + reinterpret_cast<ULONG64>(&KnLayoutFixture) - reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
            const auto typedCommand = L"!kndbgx setfield " + kncore::Hex(typedFixture) + L" " + fixtureModule + L"!KN_LAYOUT_FIXTURE ";
            Check(RunCommand(control.Get(), capture.Get(), typedCommand + L"Flags 2", L"VerifiedScalarFieldRequired"),
                  "host.typed-bitfield-write-rejected");
            Check(RunCommand(control.Get(), capture.Get(), typedCommand + L"Signed 80000000", L"InvalidMutation"),
                  "host.typed-signed-overflow-rejected");
            const auto typedPlan = PrepareCommandPlan(control.Get(), capture.Get(), typedCommand + L"Signed -1");
            Check(!typedPlan.empty(), "host.typed-signed-plan-created");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx " + typedPlan, L"AppliedAndVerified"),
                  "host.typed-approved-write-revalidates-layout");
            ULONG observedSigned = 0;
            memory->ReadVirtual(typedFixture + offsetof(KN_LAYOUT_FIXTURE, Signed), &observedSigned, sizeof(observedSigned), &transferred);
            Check(transferred == 4 && observedSigned == ULONG_MAX, "host.typed-exact-storage-width");
            const ULONG64 codeAddress =
                imageBase + reinterpret_cast<ULONG64>(&RunCommand) - reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
            const auto nearest = CommandResultData(control.Get(), capture.Get(), L"!kndbgx ln " + kncore::Hex(codeAddress + 1));
            const auto matched = CommandResultData(control.Get(), capture.Get(),
                L"!kndbgx x " + std::wstring(fixtureModule) + L"!KnLayoutFixture");
            const auto &matchedRows = matched.Get(L"Rows").Items();
            Check(matchedRows.size() == 1 && matchedRows[0].Get(L"address").AsString(L"") == kncore::Hex(typedFixture) &&
                      matchedRows[0].Get(L"addressSpace").AsString(L"") == L"virtual",
                  "host.symbol-search-retains-virtual-address-for-navigation");
            const auto &nearestRows = nearest.Get(L"Rows").Items();
            Check(nearestRows.size() == 1 && nearestRows[0].Get(L"address").AsString(L"") == kncore::Hex(codeAddress + 1) &&
                      nearestRows[0].Get(L"addressSpace").AsString(L"") == L"virtual",
                  "host.nearest-symbol-retains-requested-address-for-navigation");
            const auto implicitNearest = CommandResultData(control.Get(), capture.Get(), L"!kndbgx ln");
            const auto &implicitNearestRows = implicitNearest.Get(L"Rows").Items();
            Check(haveInstruction && implicitNearestRows.size() == 1 &&
                      implicitNearestRows[0].Get(L"address").AsString(L"") == kncore::Hex(instruction.I64),
                  "host.nearest-symbol-default-is-current-instruction");
            const auto implicitFunction = CommandResultData(control.Get(), capture.Get(), L"!kndbgx uf");
            const auto &implicitFunctionRows = implicitFunction.Get(L"Rows").Items();
            Check(haveInstruction && implicitFunctionRows.size() == 1 &&
                      implicitFunctionRows[0].Get(L"address").AsString(L"") == kncore::Hex(instruction.I64),
                  "host.function-default-is-current-instruction-not-disassembly-cursor");
            const auto absentFunction = CommandResultData(control.Get(), capture.Get(), L"!kndbgx uf 0");
            Check(absentFunction.Get(L"Metadata").Get(L"status").AsString(L"") == L"Unavailable" &&
                      !absentFunction.Get(L"Metadata").Get(L"coverage").Get(L"complete").AsBool(true),
                  "host.function-unreadable-address-is-not-success");
            const auto function = CommandResultData(control.Get(), capture.Get(), L"!kndbgx uf " + kncore::Hex(codeAddress));
            Check(function.Get(L"Metadata").Get(L"status").AsString(L"") == L"Partial" &&
                      function.Get(L"Metadata").Get(L"coverage").Get(L"stopReason").AsString(L"") == L"HostFunctionDisassemblyUnparsed" &&
                      !function.Get(L"Metadata").Get(L"coverage").Get(L"complete").AsBool(true),
                  "host.function-native-output-does-not-prove-full-function-coverage");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx uf " + kncore::Hex(codeAddress), L"[function]"),
                  "host.function-disassembly-delegated");
            ULONG breakpointsBefore = 0;
            control->GetNumberBreakpoints(&breakpointsBefore);
            const auto addBreakpoint = DebugPlan(control.Get(), capture.Get(), L"breakpoint-add " + kncore::Hex(codeAddress));
            Check(!addBreakpoint.empty() && RunCommand(control.Get(), capture.Get(), L"!kndbgx " + addBreakpoint, L"\"applied\":true"),
                  "host.breakpoint-approved-add");
            ULONG breakpointsAfter = 0;
            control->GetNumberBreakpoints(&breakpointsAfter);
            Check(breakpointsAfter == breakpointsBefore + 1 &&
                      RunCommand(control.Get(), capture.Get(), L"!kndbgx breakpoints", L"\"enabled\":true"),
                  "host.breakpoint-typed-list");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx " + addBreakpoint, L"Action rejected"),
                  "host.debug-action-replay-denied");
            IDebugBreakpoint2 *added = nullptr;
            ULONG addedId = DEBUG_ANY_ID;
            if (control->GetBreakpointByIndex2(breakpointsBefore, &added) == S_OK)
            {
                added->GetId(&addedId);
            }
            const std::wstring conditionCommand = L"bp" + std::to_wstring(addedId) + L" /w \"@rax == 0\" " + kncore::Hex(codeAddress);
            const bool conditionSet = addedId != DEBUG_ANY_ID &&
                                      control->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, conditionCommand.c_str(), DEBUG_EXECUTE_NOT_LOGGED) == S_OK;
            added = nullptr;
            const bool conditionBreakpoint = control->GetBreakpointById2(addedId, &added) == S_OK;
            const auto conditionList = CommandResultData(control.Get(), capture.Get(), L"!kndbgx breakpoints");
            bool conditionRead = false;
            for (const auto &entry : conditionList.Get(L"Rows").Items())
            {
                if (entry.Get(L"id").AsString(L"") == std::to_wstring(addedId))
                {
                    conditionRead = entry.Get(L"condition").AsString(L"") == L"@rax == 0";
                }
            }
            Check(conditionSet && conditionBreakpoint && conditionRead, "host.breakpoint-condition-is-read-without-evaluation");
            const auto disableBreakpoint = DebugPlan(control.Get(), capture.Get(), L"breakpoint-disable " + std::to_wstring(addedId));
            ULONG flags = 0;
            Check(!disableBreakpoint.empty() && RunCommand(control.Get(), capture.Get(), L"!kndbgx " + disableBreakpoint, L"\"applied\":true") &&
                      added != nullptr && added->GetFlags(&flags) == S_OK && (flags & DEBUG_BREAKPOINT_ENABLED) == 0,
                  "host.breakpoint-approved-disable");
            const auto enableBreakpoint = DebugPlan(control.Get(), capture.Get(), L"breakpoint-enable " + std::to_wstring(addedId));
            Check(!enableBreakpoint.empty() && RunCommand(control.Get(), capture.Get(), L"!kndbgx " + enableBreakpoint, L"\"applied\":true") &&
                      added != nullptr && added->GetFlags(&flags) == S_OK && (flags & DEBUG_BREAKPOINT_ENABLED) != 0 &&
                      RunCommand(control.Get(), capture.Get(), L"!kndbgx breakpoints", L"\"identity\":"),
                  "host.breakpoint-approved-enable-and-identity");
            const auto removeBreakpoint = DebugPlan(control.Get(), capture.Get(), L"breakpoint-remove " + std::to_wstring(addedId));
            Check(!removeBreakpoint.empty() &&
                      RunCommand(control.Get(), capture.Get(), L"!kndbgx " + removeBreakpoint, L"\"applied\":true"),
                  "host.breakpoint-approved-remove");
            control->GetNumberBreakpoints(&breakpointsAfter);
            Check(breakpointsAfter == breakpointsBefore, "host.breakpoint-count-restored");
            IDebugBreakpoint2 *hardware = nullptr;
            ULONG hardwareId = DEBUG_ANY_ID;
            bool hardwareReady = control->AddBreakpoint2(DEBUG_BREAKPOINT_DATA, DEBUG_ANY_ID, &hardware) == S_OK;
            if (hardwareReady)
            {
                hardwareReady = hardware->GetId(&hardwareId) == S_OK && hardware->SetOffset(typedFixture) == S_OK &&
                                hardware->SetDataParameters(1, DEBUG_BREAK_WRITE) == S_OK;
            }
            const auto hardwarePlan = hardwareReady
                                          ? DebugPlan(control.Get(), capture.Get(), L"breakpoint-remove " + std::to_wstring(hardwareId))
                                          : std::wstring();
            const bool changedHardware = hardwareReady && hardware->SetDataParameters(2, DEBUG_BREAK_WRITE) == S_OK;
            const bool configuredHardware = changedHardware && hardware->SetPassCount(3) == S_OK &&
                                            hardware->SetMatchThreadId(0) == S_OK && hardware->SetCommandWide(L".echo fixture-hit") == S_OK;
            const auto configuredEvent = CommandResultData(control.Get(), capture.Get(), L"!kndbgx event");
            const auto &eventRows = configuredEvent.Get(L"Rows").Items();
            bool hardwareSettings = false;
            for (const auto &entry : eventRows)
            {
                if (entry.Get(L"kind").AsString(L"") == L"Breakpoint" &&
                    entry.Get(L"id").AsString(L"") == std::to_wstring(hardwareId))
                {
                    hardwareSettings = entry.Get(L"address").AsString(L"") == kncore::Hex(typedFixture) &&
                                       entry.Get(L"trigger").AsString(L"") == L"Write (2 bytes)" &&
                                       entry.Get(L"dataSize").AsString(L"") == L"2" &&
                                       entry.Get(L"passCount").AsString(L"") == L"3" &&
                                       entry.Get(L"matchThreadId").AsString(L"") == L"0" &&
                                       entry.Get(L"symbol").AsString(L"").find(L"KnLayoutFixture") != std::wstring::npos &&
                                       entry.Get(L"command").AsString(L"") == L".echo fixture-hit" &&
                                       entry.Get(L"condition").IsString() && entry.Get(L"condition").AsString(L"unknown").empty();
                }
            }
            Check(configuredHardware && !eventRows.empty() && eventRows[0].Get(L"kind").AsString(L"") == L"LastEvent" &&
                      hardwareSettings && configuredEvent.Get(L"Metadata").Get(L"analysis").Get(L"lastEvent").IsObject(),
                  "host.event-retains-last-stop-and-breakpoint-address-trigger-and-conditions");
            ULONG eventPid = 0, eventTid = 0;
            ComPtr<IDebugSystemObjects4> eventSystem;
            const auto &eventContext = configuredEvent.Get(L"Metadata").Get(L"analysis").Get(L"lastEvent").Get(L"targetContext");
            Check(SUCCEEDED(client->QueryInterface(IID_PPV_ARGS(&eventSystem))) &&
                      eventSystem->GetCurrentProcessSystemId(&eventPid) == S_OK && eventSystem->GetCurrentThreadSystemId(&eventTid) == S_OK &&
                      eventContext.Get(L"pid").AsString(L"") == std::to_wstring(eventPid) &&
                      eventContext.Get(L"tid").AsString(L"") == std::to_wstring(eventTid),
                  "host.event-user-process-and-thread-use-system-ids");
            Check(changedHardware && !hardwarePlan.empty() &&
                      RunCommand(control.Get(), capture.Get(), L"!kndbgx " + hardwarePlan, L"Breakpoint changed"),
                  "host.review-hardware-breakpoint-reconfiguration-invalidates-approval");
            IDebugBreakpoint2 *remainingHardware = nullptr;
            if (control->GetBreakpointById2(hardwareId, &remainingHardware) == S_OK)
            {
                control->RemoveBreakpoint2(remainingHardware);
            }

            auto contextWorker = std::async(std::launch::async,
                                            []()
                                            {
                                                {
                                                    knengine::DbgSession first;
                                                    first.Initialize();
                                                    first.RefreshStamp();
                                                    first.SetContextDtb(0x12345000);
                                                }
                                                knengine::DbgSession next;
                                                next.Initialize();
                                                next.RefreshStamp();
                                                const bool persisted = next.HasContextDtb() && next.ContextDtb() == 0x12345000;
                                                knengine::Epochs().SymbolsChanged();
                                                const bool invalidated = !next.HasContextDtb();
                                                next.ClearContextDtb();
                                                return persisted && invalidated;
                                            });
            Check(contextWorker.get(), "host.dtb-persists-across-clients-and-invalidates-on-symbol-change");
            std::promise<void> ready;
            auto active = std::async(std::launch::async,
                                     [&]()
                                     {
                                         kncore::ExecutionLease lease(knengine::Coordinator());
                                         knengine::DbgSession session;
                                         const bool initialized = session.Initialize();
                                         ready.set_value();
                                         std::wstring ignored;
                                         if (initialized)
                                         {
                                             session.Execute(L".while (1) { r @$t0 = @$t0 + 1; }",
                                                             knengine::DbgSession::OutputRouting::CaptureHere, &ignored);
                                         }
                                         return initialized && session.Cancelled();
                                     });
            ready.get_future().wait();
            Sleep(100);
            const ULONGLONG before = GetTickCount64();
            Check(knengine::RequestCancellation(), "host.real-engine-cancel-request");
            const bool finished = active.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
            Check(finished && active.get() && GetTickCount64() - before < 2000, "host.real-engine-cancel-completes");

            ComPtr<IDebugClient> baseClient;
            client.As(&baseClient);
            CheckJobs(GetModuleHandleW(argv[2]), baseClient.Get(), capture.Get());

            const auto continuePlan = DebugPlan(control.Get(), capture.Get(), L"go");
            const auto direct = reinterpret_cast<ExtensionCall>(GetProcAddress(GetModuleHandleW(argv[2]), "kndbgx"));
            const HRESULT resumed = !continuePlan.empty() ? direct(baseClient.Get(), knutil::WideToUtf8(continuePlan).c_str()) : E_FAIL;
            ULONG execution = 0;
            control->GetExecutionStatus(&execution);
            const HRESULT awaited = SUCCEEDED(resumed) ? control->WaitForEvent(0, 5000) : E_FAIL;
            std::printf("action.go HRESULT=0x%08x execution=%lu wait=0x%08x\n", static_cast<unsigned>(resumed), execution,
                        static_cast<unsigned>(awaited));
            Check(SUCCEEDED(resumed) && awaited == S_OK, "host.approved-go-reaches-owned-debugbreak");
            if (awaited != S_OK)
            {
                control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
                control->WaitForEvent(0, 5000);
            }

            const auto dump = CommandResultData(control.Get(), capture.Get(), L"!kndbgx .dump \"" + std::wstring(argv[3]) + L"\"");
            Check(dump.Get(L"Metadata").Get(L"analysis").Get(L"artifactCommitted").AsBool(false), "host.create-real-minidump-fixture");
            Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx dump-analyze \"" + std::wstring(argv[3]) + L"\"",
                             L"[dump.modules] validated="),
                  "host.actual-dump-product-parser");
            const auto dumpMetadata = CommandResultData(control.Get(), capture.Get(),
                                                        L"!kndbgx dump-analyze \"" + std::wstring(argv[3]) + L"\"");
            Check(!dumpMetadata.Get(L"Rows").Items().empty() &&
                      dumpMetadata.Get(L"Rows").Items()[0].Get(L"kind").AsString(L"") == L"DumpMetadata" &&
                      dumpMetadata.Get(L"Metadata").Get(L"provenance").Get(L"source").AsString(L"") == L"HostDumpMetadata",
                  "host.dump-metadata-table-does-not-borrow-current-target-symbols");
            for (unsigned repeat = 0; repeat < 3; ++repeat)
            {
                Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx", nullptr), "host.open-ui-nonblocking");
                const ULONGLONG deadline = GetTickCount64() + 15000;
                HWND window = nullptr;
                bool booted = false;
                while (GetTickCount64() < deadline)
                {
                    window = OwnWindow();
                    booted = window != nullptr && reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.StartupRpcMask")) == 3 &&
                             GetPropW(window, L"KNDbgX.WorkerReplyPosted") != nullptr;
                    if (booted)
                    {
                        break;
                    }
                    Sleep(20);
                }
                Check(booted, "host.real-webview-boot-and-worker-status");
#ifdef KNDBGX_UI_TESTS
                const auto inspect = [&](WPARAM mode)
                {
                    return UiTest(window, WM_APP + 110, mode) != 0 && AwaitUi([&]()
                    {
                        return GetPropW(window, L"KNDbgX.InspectionChecked") != nullptr;
                    }) && GetPropW(window, L"KNDbgX.InspectionChecked") == reinterpret_cast<HANDLE>(1);
                };
                if (booted && repeat == 0)
                {
                    CheckBoundNavigation(window, control.Get(), capture.Get(), fixture);
                    capture->Take();
                    const bool forwarded =
                        UiTest(window, WM_APP + 106) != 0 && AwaitUi(
                                                                 [&]()
                                                                 {
                                                                     return GetPropW(window, L"KNDbgX.ConsoleReply") != nullptr;
                                                                 });
                    const auto hostOutput = capture->Take();
                    Check(forwarded && reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.ConsoleReply")) == 1 &&
                              hostOutput.find(L"KNDBGX_UI_HOST_FIRST") != std::wstring::npos &&
                              hostOutput.find(L"KNDBGX_UI_HOST_SECOND:42") != std::wstring::npos,
                          "host.ui-unregistered-windbg-command-preserves-compound-syntax-and-output");
                    CheckUiExecution(window, control.Get(), client.Get());
                    Check(inspect(1), "host.float-inspection-requested");
                    HWND floating = nullptr;
                    const bool detached = AwaitUi([&]()
                    {
                        floating = static_cast<HWND>(GetPropW(window, L"KNDbgX.InspectWindow"));
                        return floating != nullptr && IsWindowVisible(floating);
                    });
                    Check(detached && AwaitUi([&]()
                    {
                        return inspect(2);
                    }), "host.real-floating-webview-preserves-nodes-drafts-and-styles");
                    if (detached)
                    {
                        Check(inspect(22), "host.drag-docking-respects-occlusion-and-input-transparent-overlays");
                        TITLEBARINFO caption = {};
                        caption.cbSize = sizeof(caption);
                        Check(GetTitleBarInfo(floating, &caption) &&
                                  ((caption.rgstate[2] | caption.rgstate[3]) & (STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_UNAVAILABLE)) == 0,
                              "host.floating-caption-exposes-minimize-and-maximize");
                        Check(GetClassLongPtrW(floating, GCLP_HICONSM) != 0 &&
                                  GetClassLongPtrW(floating, GCLP_HICONSM) == GetClassLongPtrW(window, GCLP_HICONSM),
                              "host.floating-caption-shares-the-application-icon");
                        PostMessageW(floating, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
                        Check(AwaitUi([&]()
                        {
                            return IsZoomed(floating) != FALSE;
                        }) && inspect(2), "host.floating-maximize-preserves-the-inspection-document");
                        PostMessageW(floating, WM_SYSCOMMAND, SC_RESTORE, 0);
                        Check(AwaitUi([&]()
                        {
                            return !IsZoomed(floating) && !IsIconic(floating);
                        }) && inspect(2), "host.floating-restore-preserves-the-inspection-document");
                        PostMessageW(floating, WM_SYSCOMMAND, SC_MINIMIZE, 0);
                        Check(AwaitUi([&]()
                        {
                            return IsIconic(floating) != FALSE;
                        }), "host.floating-inspection-can-minimize");
                        Check(inspect(7), "host.floating-frame-close-rejects-earlier-show-epoch");
                        Check(AwaitUi([&]()
                        {
                            return !IsWindowVisible(floating) && inspect(3);
                        }),
                              "host.floating-frame-close-hides-without-destroying-state");
                        Check(inspect(4) && AwaitUi([&]()
                        {
                            return IsWindowVisible(floating);
                        }) && !IsIconic(floating) && inspect(2),
                              "host.inspect-toggle-reopens-same-floating-panel");
                        PostMessageW(floating, WM_CLOSE, 0, 0);
                        Check(AwaitUi([&]()
                        {
                            return !IsWindowVisible(floating) && inspect(3);
                        }), "host.floating-wm-close-dispatch-hides-the-panel");
                        Check(inspect(4) && AwaitUi([&]()
                        {
                            return IsWindowVisible(floating);
                        }) && inspect(2), "host.floating-wm-close-reopens-with-current-visibility-epoch");
                        PostMessageW(window, WM_CLOSE, 0, 0);
                        Check(AwaitUi([&]()
                        {
                            return !IsWindowVisible(window) && !IsWindowVisible(floating);
                        }),
                              "host.main-close-hides-floating-inspection");
                        Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx", nullptr) &&
                                  AwaitUi([&]()
                                  {
                                      return IsWindowVisible(window) && IsWindowVisible(floating);
                                  }) && inspect(2),
                              "host.main-reopen-restores-same-floating-inspection");
                        Check(inspect(5) && AwaitUi([&]()
                        {
                            return !IsWindow(floating);
                        }) && inspect(6),
                              "host.dock-returns-original-nodes-and-closes-owned-controller");
                    }
                    Check(inspect(8), "host.independent-four-inspection-windows-requested");
                    std::vector<HWND> panels;
                    const bool fourPanels = AwaitUi(
                        [&]()
                        {
                            panels.clear();
                            for (const auto *name : {L"processes", L"memory", L"disassembly", L"registers"})
                            {
                                panels.push_back(
                                    static_cast<HWND>(GetPropW(window, (std::wstring(L"KNDbgX.InspectWindow.") + name).c_str())));
                            }
                            return std::all_of(panels.begin(), panels.end(),
                                               [](HWND panel)
                                               {
                                                   return panel != nullptr && IsWindowVisible(panel);
                                               }) &&
                                   inspect(9);
                        });
                    Check(fourPanels, "host.four-native-inspection-controllers-preserve-independent-documents-and-drafts");
                    if (fourPanels)
                    {
                        Check(std::all_of(panels.begin(), panels.end(), [](HWND panel)
                        {
                            TITLEBARINFO caption = {};
                            caption.cbSize = sizeof(caption);
                            return GetTitleBarInfo(panel, &caption) &&
                                   ((caption.rgstate[2] | caption.rgstate[3]) & (STATE_SYSTEM_INVISIBLE | STATE_SYSTEM_UNAVAILABLE)) == 0 &&
                                   GetClassLongPtrW(panel, GCLP_HICONSM) != 0;
                        }), "host.all-four-inspection-captions-expose-icons-and-window-controls");
                        PostMessageW(window, WM_CLOSE, 0, 0);
                        Check(AwaitUi(
                                  [&]()
                                  {
                                      return !IsWindowVisible(window) && std::none_of(panels.begin(), panels.end(),
                                                                                      [](HWND panel)
                                                                                      {
                                                                                          return IsWindowVisible(panel) != FALSE;
                                                                                      });
                                  }),
                              "host.main-close-hides-all-four-inspection-windows");
                        Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx", nullptr) &&
                                  AwaitUi(
                                      [&]()
                                      {
                                          return IsWindowVisible(window) &&
                                                 std::all_of(panels.begin(), panels.end(),
                                                             [](HWND panel)
                                                             {
                                                                 return IsWindowVisible(panel) != FALSE;
                                                             }) &&
                                                 inspect(9);
                                      }),
                              "host.main-reopen-restores-all-four-inspection-windows");
                        PostMessageW(panels[1], WM_CLOSE, 0, 0);
                        Check(AwaitUi(
                                  [&]()
                                  {
                                      return !IsWindow(panels[1]) && IsWindowVisible(panels[0]) && IsWindowVisible(panels[2]) &&
                                             IsWindowVisible(panels[3]) && inspect(10);
                                  }),
                              "host.native-close-docks-only-the-selected-inspection-view");
                        Check(inspect(11) && AwaitUi(
                                                 [&]()
                                                 {
                                                     return std::none_of(panels.begin(), panels.end(),
                                                                         [](HWND panel)
                                                                         {
                                                                             return IsWindow(panel) != FALSE;
                                                                         }) &&
                                                            inspect(12);
                                                 }),
                              "host.dock-all-restores-original-views-and-releases-every-controller");
                    }
                    HWND mixedGroup = nullptr;
                    Check(inspect(13) && AwaitUi([&]()
                    {
                        mixedGroup = static_cast<HWND>(GetPropW(window, L"KNDbgX.InspectWindow"));
                        return mixedGroup != nullptr && IsWindowVisible(mixedGroup);
                    }), "host.group-opens-for-mixed-floating");
                    std::vector<HWND> mixedPanels;
                    const bool mixed = inspect(14) && AwaitUi([&]()
                    {
                        mixedPanels.clear();
                        for (const auto *name : {L"processes", L"memory", L"disassembly", L"registers"})
                        {
                            mixedPanels.push_back(static_cast<HWND>(GetPropW(window, (std::wstring(L"KNDbgX.InspectWindow.") + name).c_str())));
                        }
                        return IsWindowVisible(mixedGroup) && std::all_of(mixedPanels.begin(), mixedPanels.end(), [](HWND panel)
                        {
                            return panel != nullptr && IsWindowVisible(panel);
                        }) && inspect(15);
                    });
                    Check(mixed, "host.all-four-views-float-from-the-group-with-five-live-controllers");
                    if (mixed)
                    {
                        Check(inspect(16) && AwaitUi([&]()
                        {
                            return !IsWindow(mixedPanels[1]) && inspect(17);
                        }), "host.independent-dock-returns-the-original-view-to-the-floating-group");
                        Check(inspect(18) && AwaitUi([&]()
                        {
                            return !IsWindow(mixedGroup) && IsWindowVisible(mixedPanels[0]) && IsWindowVisible(mixedPanels[2]) &&
                                   IsWindowVisible(mixedPanels[3]) && inspect(19);
                        }), "host.group-docking-keeps-independent-sibling-windows-open");
                        Check(inspect(20) && AwaitUi([&]()
                        {
                            return std::none_of(mixedPanels.begin(), mixedPanels.end(), [](HWND panel)
                            {
                                return IsWindow(panel) != FALSE;
                            }) && inspect(21);
                        }), "host.mixed-dock-all-preserves-original-nodes-and-drafts");
                    }
                }
#endif
                if (booted && repeat == 0)
                {
                    const HMODULE loaded = GetModuleHandleW(argv[2]);
                    using Observe = ULONG64 (*)();
                    const auto observe = reinterpret_cast<Observe>(GetProcAddress(loaded, "KnDbgXLifecycleState"));
                    const HANDLE navigation = GetPropW(window, L"KNDbgX.NavigationGeneration");
                    for (unsigned cycle = 0; cycle < 2; ++cycle)
                    {
#ifdef KNDBGX_UI_TESTS
                        const auto probe = [&](WPARAM mode)
                        {
                            return UiTest(window, WM_APP + 108, mode) != 0 && AwaitUi(
                                [&]()
                                {
                                    return GetPropW(window, L"KNDbgX.WorkspaceChecked") != nullptr;
                                }) && GetPropW(window, L"KNDbgX.WorkspaceChecked") == reinterpret_cast<HANDLE>(1);
                        };
                        Check(probe(1), "host.capture-workspace-before-normal-close");
#endif
                        PostMessageW(window, WM_CLOSE, 0, 0);
                        const ULONGLONG hideDeadline = GetTickCount64() + 5000;
                        while (IsWindowVisible(window) && GetTickCount64() < hideDeadline)
                        {
                            Sleep(20);
                        }
                        Check(!IsWindowVisible(window) && OwnWindow() == window && observe != nullptr && (observe() & 0xff) == 1 &&
                                  GetPropW(window, L"KNDbgX.NavigationGeneration") == navigation,
                              "host.normal-close-hides-same-window-and-keeps-document-generation");
#ifdef KNDBGX_UI_TESTS
                        Check(probe(2), "host.hidden-workspace-keeps-dom-and-view-state");
#endif
                        Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx", nullptr), "host.show-retained-workspace");
                        const ULONGLONG showDeadline = GetTickCount64() + 5000;
                        while (!IsWindowVisible(window) && GetTickCount64() < showDeadline)
                        {
                            Sleep(20);
                        }
                        Check(IsWindowVisible(window) && OwnWindow() == window &&
                                  GetPropW(window, L"KNDbgX.NavigationGeneration") == navigation,
                              "host.reopen-raises-same-window-without-navigation");
#ifdef KNDBGX_UI_TESTS
                        Check(probe(3), "host.reopened-workspace-keeps-dom-and-view-state");
#endif
                    }
#ifdef KNDBGX_UI_TESTS
                    CheckUiFailures(window);
#endif
                    for (unsigned cycle = 0; cycle < 2; ++cycle)
                    {
                        if (cycle == 0)
                        {
                            PostMessageW(window, WM_CLOSE, 0, 0);
                            const ULONGLONG hideDeadline = GetTickCount64() + 5000;
                            while (IsWindowVisible(window) && GetTickCount64() < hideDeadline)
                            {
                                Sleep(20);
                            }
                            Check(!IsWindowVisible(window), "host.explicit-shutdown-starts-from-hidden-workspace");
                        }
                        Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx shutdown", nullptr),
                              "host.close-ui-without-unloading-extension");
                        const ULONGLONG closeDeadline = GetTickCount64() + 10000;
                        bool closed = false;
                        while (GetTickCount64() < closeDeadline)
                        {
                            closed = OwnWindow() == nullptr && observe != nullptr && (observe() & 0xffffff) == 0;
                            if (closed)
                            {
                                break;
                            }
                            Sleep(20);
                        }
                        Check(closed && GetModuleHandleW(argv[2]) == loaded, "host.closed-ui-keeps-same-extension-loaded");
                        Check(RunCommand(control.Get(), capture.Get(), L"!kndbgx", nullptr), "host.reopen-ui-in-same-dll-lifetime");
                        const ULONGLONG reopenDeadline = GetTickCount64() + 15000;
                        bool reopened = false;
                        while (GetTickCount64() < reopenDeadline)
                        {
                            window = OwnWindow();
                            reopened = window != nullptr && reinterpret_cast<ULONG_PTR>(GetPropW(window, L"KNDbgX.StartupRpcMask")) == 3 &&
                                       GetPropW(window, L"KNDbgX.WorkerReplyPosted") != nullptr;
                            if (reopened)
                            {
                                break;
                            }
                            Sleep(20);
                        }
                        Check(reopened && GetModuleHandleW(argv[2]) == loaded, "host.same-dll-reopen-completes-webview-handshake");
                        if (!reopened)
                        {
                            break;
                        }
                    }
                }
                HWND floatingOnUnload = nullptr;
#ifdef KNDBGX_UI_TESTS
                std::vector<HWND> panelsOnUnload;
                if (booted && repeat == 1)
                {
                    Check(inspect(8) && AwaitUi(
                                            [&]()
                                            {
                                                panelsOnUnload.clear();
                                                for (const auto *name : {L"processes", L"memory", L"disassembly", L"registers"})
                                                {
                                                    panelsOnUnload.push_back(static_cast<HWND>(
                                                        GetPropW(window, (std::wstring(L"KNDbgX.InspectWindow.") + name).c_str())));
                                                }
                                                return std::all_of(panelsOnUnload.begin(), panelsOnUnload.end(),
                                                                   [](HWND panel)
                                                                   {
                                                                       return panel != nullptr && IsWindowVisible(panel);
                                                                   }) &&
                                                       inspect(9);
                                            }),
                          "host.four-independent-inspection-windows-open-before-extension-unload");
                }
                if (booted && repeat == 2)
                {
                    Check(inspect(1) && AwaitUi(
                                            [&]()
                                            {
                                                floatingOnUnload = static_cast<HWND>(GetPropW(window, L"KNDbgX.InspectWindow"));
                                                return floatingOnUnload != nullptr && IsWindowVisible(floatingOnUnload) && inspect(2);
                                            }),
                          "host.floating-inspection-open-before-extension-unload");
                }
#endif
                Check(SUCCEEDED(control->RemoveExtension(extensionHandle)), "host.unload-while-ui-open");
                const ULONGLONG closedDeadline = GetTickCount64() + 10000;
                while (GetModuleHandleW(argv[2]) != nullptr && GetTickCount64() < closedDeadline)
                {
                    Sleep(20);
                }
                Check(OwnWindow() == nullptr && GetModuleHandleW(argv[2]) == nullptr, "host.leases-drain-and-module-unloads");
                if (floatingOnUnload != nullptr)
                {
                    Check(!IsWindow(floatingOnUnload), "host.extension-unload-destroys-owned-floating-window");
                }
#ifdef KNDBGX_UI_TESTS
                if (!panelsOnUnload.empty())
                {
                    Check(std::none_of(panelsOnUnload.begin(), panelsOnUnload.end(),
                                       [](HWND panel)
                                       {
                                           return IsWindow(panel) != FALSE;
                                       }),
                          "host.extension-unload-destroys-all-four-independent-inspection-windows");
                }
#endif
                if (GetModuleHandleW(argv[2]) == nullptr && publishedModel != nullptr)
                {
                    ComPtr<IModelObject> id;
                    VARIANT value;
                    VariantInit(&value);
                    const bool read = SUCCEEDED(publishedModel->GetKeyValue(L"ResultId", &id, nullptr)) &&
                                      SUCCEEDED(id->GetIntrinsicValueAs(VT_BSTR, &value));
                    Check(read && value.bstrVal != nullptr && publishedId == value.bstrVal,
                          "host.data-model-value-survives-extension-unload");
                    VariantClear(&value);
                }
                if (GetModuleHandleW(argv[2]) != nullptr)
                {
                    HMODULE held = nullptr;
                    if (GetModuleHandleExW(0, argv[2], &held))
                    {
                        using Observe = ULONG64 (*)();
                        const auto observe = reinterpret_cast<Observe>(GetProcAddress(held, "KnDbgXLifecycleState"));
                        if (observe != nullptr)
                        {
                            std::printf("lifecycle=0x%llx\n", observe());
                            std::fflush(stdout);
                        }
                        FreeLibrary(held);
                    }
                    break;
                }
                if (repeat != 2)
                {
                    control->AddExtensionWide(argv[2], 0, &extensionHandle);
                }
            }
        } while (false);
        if (client != nullptr)
        {
            if (deferredProbe || wcscmp(argv[3], L"--probe-local") == 0)
            {
                client->EndSession(DEBUG_END_PASSIVE);
            }
            else
            {
                client->TerminateProcesses();
                client->EndSession(DEBUG_END_ACTIVE_TERMINATE);
            }
            client->SetOutputCallbacksWide(nullptr);
            client->SetEventCallbacksWide(nullptr);
        }
    }
    if (SUCCEEDED(com))
    {
        CoUninitialize();
    }
    // Delay-load imports still reference this module until process exit.
    if (directoryCookie != nullptr)
    {
        RemoveDllDirectory(directoryCookie);
    }
    std::printf("engine integration failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
