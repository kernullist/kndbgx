#pragma once

// Internal shared context passed to native handlers. Not part of the public
// surface; include only from src/cmd/*.cpp.

#include <string>
#include <vector>

#include "CmdUtil.h"
#include "../engine/EngineCore.h"
#include "../core/MapperDetect.h"
#include "../core/Result.h"

namespace kncmd
{
// Simple line-oriented output builder.
class CmdText
{
  public:
    void Add(const std::wstring &text)
    {
        const size_t limit = 8 * 1024 * 1024;
        if (text.size() > limit - buffer_.size())
        {
            if (Details.State == kncore::Status::Success)
            {
                Details.State = kncore::Status::Partial;
            }
            Details.Collected.Complete = false;
            Details.Collected.StopReason = L"OutputBudgetExceeded";
            return;
        }
        buffer_ += text;
    }

    void AddLine(const std::wstring &text = L"")
    {
        Add(text + L"\n");
    }

    void Fail(kncore::Status status, const std::wstring &message, const kncore::NativeError &error = {})
    {
        Details.State = status;
        Details.Error = error;
        Details.Error.Message = message;
        Details.Collected.Complete = false;
        AddLine(message);
    }

    const std::wstring &Text() const
    {
        return buffer_;
    }

    kncore::Result Details;

  private:
    std::wstring buffer_;
};

struct ParsedCommand;
struct Ctx
{
    knengine::DbgSession &Session;
    const std::vector<std::wstring> &Args; // tokens, original case
    CmdText &Out;
    const ParsedCommand *Request = nullptr;
    const kncore::SessionStamp *ExpectedStamp = nullptr;
    std::function<bool()> RequestCancelled;
};

typedef void (*HandlerFn)(Ctx &ctx);
void ExecuteCollector(HandlerFn handler, Ctx &context);

void DisplayMemory(Ctx &ctx, int unitBytes, bool asciiGutter, bool dwordAsciiMode, bool symbolAnnotate, bool physical);
void DisplayString(Ctx &ctx, bool utf16);
void FillMemoryCmd(Ctx &ctx);
void WritePhysicalMemory(Ctx &ctx, int unitBytes);
void WriteVirtualMemory(Ctx &ctx, int unitBytes);
void RecordDumpArtifact(Ctx &ctx, const std::wstring &path, uint64_t bytes, const wchar_t *format);

// ---- handlers implemented in CoreCmds.cpp ----
void ProbeQuery(Ctx &ctx);
void TranslateVtop(Ctx &ctx);
void EvaluateExpression(Ctx &ctx);

// ---- handlers implemented in ScannerCmds.cpp ----
void ScanProcessList(Ctx &ctx);
void ScanSsdt(Ctx &ctx);
void ScanWin32kPolicy(Ctx &ctx, const std::wstring &selector);
void ScanIdt(Ctx &ctx);
void ScanMsrCheck(Ctx &ctx);
void ScanControlRegisters(Ctx &ctx);
void InspectAddress(Ctx &ctx);

// ---- handlers implemented in CallbacksCmds.cpp ----
void ScanCallbacks(Ctx &ctx);

// ---- handlers implemented in PoolCmds.cpp ----
void ScanPool(Ctx &ctx);

// ---- handlers implemented in MoreScanners.cpp ----
void ScanNmi(Ctx &ctx);
void ScanHal(Ctx &ctx);
void ScanEtwLoggers(Ctx &ctx);
void DecodeWnf(Ctx &ctx);

// ---- handlers implemented in ProcScanCmds.cpp ----
void ScanVad(Ctx &ctx);
void ScanThreads(Ctx &ctx);
void ScanHandles(Ctx &ctx);
void ScanHiddenProc(Ctx &ctx);

void ScanHive(Ctx &ctx);
void ScanDpc(Ctx &ctx);
void ScanTimer(Ctx &ctx);
void ScanAlpc(Ctx &ctx);
void ScanModuleIntegrity(Ctx &ctx);
void ScanMinifilters(Ctx &ctx);

// ---- handlers implemented in UserCollectors.cpp ----
void ScanWfp(Ctx &ctx);
void ScanTargetWfp(Ctx &ctx);
void ScanHv(Ctx &ctx);
void ScanCodeIntegrity(Ctx &ctx);
void ScanDma(Ctx &ctx);
void ScanByovd(Ctx &ctx);
void ScanFwtable(Ctx &ctx);

// ---- handlers implemented in DrvobjCmds.cpp ----
void ScanDrvobj(Ctx &ctx);
void ScanDevstack(Ctx &ctx);

// ---- handlers implemented in DumpCmds.cpp ----
void AnalyzeDump(Ctx &ctx);
void DumpLive(Ctx &ctx);
void DumpRaw(Ctx &ctx);
void DumpPe(Ctx &ctx);

// ---- handlers implemented in ExtraCmds.cpp ----
void ClearScreenCmd(Ctx &ctx);
void ProcessContextCmd(Ctx &ctx);
void ScanToken(Ctx &ctx);
void ScanUnloadedDrivers(Ctx &ctx);
void ScanPiddb(Ctx &ctx);
void ScanCiHash(Ctx &ctx);
void ScanMapper(Ctx &ctx);
void ScanMapperImages(Ctx &ctx, const std::vector<kncore::MapperHistoryRecord> &history);
void ScanPayload(Ctx &ctx);
void ScanDriverList(Ctx &ctx);
void ScanKpage(Ctx &ctx);
void SnapshotCmd(Ctx &ctx);
void DiffCmd(Ctx &ctx);
void ImportLegacySnapshot(Ctx &ctx);
void SetFieldCmd(Ctx &ctx);
} // namespace kncmd
