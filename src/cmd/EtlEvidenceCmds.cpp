#include "CommandSpec.h"
#include "../core/Input.h"
#include "../core/EtwEvidence.h"
#include "../util/FileReader.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <objbase.h>
#include <optional>
#include <algorithm>
#include <array>

namespace kncmd
{
namespace
{
std::optional<std::wstring> MetadataText(const std::vector<unsigned char> &bytes, ULONG offset)
{
    if (offset < offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) || (offset & 1) != 0 || offset >= bytes.size())
    {
        return {};
    }
    std::wstring result;
    for (size_t i = offset; i + sizeof(wchar_t) <= bytes.size() && result.size() <= 4096; i += sizeof(wchar_t))
    {
        wchar_t c = 0;
        std::memcpy(&c, bytes.data() + i, sizeof(c));
        if (c == 0)
        {
            return kncore::ValidUtf16(result, false) ? std::optional<std::wstring>(result) : std::nullopt;
        }
        result.push_back(c);
    }
    return {};
}

struct TraceRead
{
    Ctx *Context;
    size_t Limit;
    std::chrono::steady_clock::time_point Deadline;
    kncore::Result Result;
    bool Stopped = false;
    bool Fault = false;
    uint64_t MetadataMissing = 0;
    ULONG EventsLost = 0;
    ULONG BuffersLost = 0;
    std::wstring Reason;

    bool StopRequested()
    {
        if (!Stopped && Context->Session.Cancelled())
        {
            Stopped = true;
            Reason = L"Cancelled";
            Result.State = kncore::Status::Cancelled;
        }
        if (!Stopped && std::chrono::steady_clock::now() >= Deadline)
        {
            Stopped = true;
            Reason = L"TraceDeadline";
        }
        return Stopped;
    }
};

void WINAPI TraceEvent(PEVENT_RECORD event)
{
    auto *state = static_cast<TraceRead *>(event->UserContext);
    if (state == nullptr)
    {
        return;
    }
    try
    {
        if (state->StopRequested())
        {
            return;
        }
        if (state->Result.Collected.Visited >= state->Limit)
        {
            state->Stopped = true;
            state->Reason = L"TraceEventLimit";
            return;
        }
        auto row = kncore::EtwHeaderRow(event);
        ULONG size = 0;
        ULONG error = TdhGetEventInformation(event, 0, nullptr, nullptr, &size);
        bool metadata = false;
        if (error == ERROR_INSUFFICIENT_BUFFER && size >= sizeof(TRACE_EVENT_INFO) && size <= 1024 * 1024)
        {
            std::vector<unsigned char> buffer(size);
            error = TdhGetEventInformation(event, 0, nullptr, reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data()), &size);
            if (error == ERROR_SUCCESS && size <= buffer.size() && size >= sizeof(TRACE_EVENT_INFO))
            {
                buffer.resize(size);
                TRACE_EVENT_INFO info = {};
                std::memcpy(&info, buffer.data(), sizeof(info));
                const auto provider = MetadataText(buffer, info.ProviderNameOffset);
                const auto task = MetadataText(buffer, info.TaskNameOffset);
                const auto opcode = MetadataText(buffer, info.OpcodeNameOffset);
                row.Set(L"providerName", provider ? knjson::Value(*provider) : knjson::Value());
                row.Set(L"taskName", task ? knjson::Value(*task) : knjson::Value());
                row.Set(L"opcodeName", opcode ? knjson::Value(*opcode) : knjson::Value());
                row.Set(L"decodingSource", knjson::Value(std::to_wstring(info.DecodingSource)));
                metadata = true;
            }
        }
        row.Set(L"metadataAvailable", knjson::Value(metadata));
        row.Set(L"metadataStatus", knjson::Value(kncore::Hex(error)));
        if (!metadata)
        {
            ++state->MetadataMissing;
        }
        state->Result.Rows.Push(row);
        ++state->Result.Collected.Visited;
        ++state->Result.Collected.Decoded;
    }
    catch (...)
    {
        state->Fault = true;
        state->Stopped = true;
    }
}

ULONG WINAPI TraceBuffer(PEVENT_TRACE_LOGFILEW log)
{
    auto *state = static_cast<TraceRead *>(log->Context);
    ULONG keepReading = FALSE;
    try
    {
        if (state != nullptr)
        {
            state->EventsLost = std::max(state->EventsLost, std::max(log->EventsLost, log->LogfileHeader.EventsLost));
            state->BuffersLost = std::max(state->BuffersLost, log->LogfileHeader.BuffersLost);
        }
        keepReading = state != nullptr && !state->StopRequested();
    }
    catch (...)
    {
        if (state != nullptr)
        {
            state->Fault = true;
            state->Stopped = true;
        }
    }
    return keepReading;
}
} // namespace

void EtlEvidenceCommand(Ctx &ctx)
{
    uint64_t limit = 2048;
    if (ctx.Args.size() > 2 && (!kncore::ParseUnsigned(ctx.Args[2], 10, &limit) || limit == 0 || limit > 16384))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"ETL event limit must be 1..16384");
        return;
    }
    knutil::FileReader file(ctx.Args[1], true);
    if (!file.IsOpen() || file.Size() == 0 || file.Size() > uint64_t(4) * 1024 * 1024 * 1024)
    {
        ctx.Out.Fail(kncore::Status::IOError, L"ETL file unavailable, empty, a reparse point, or larger than 4 GiB");
        return;
    }
    std::wstring path(32768, L'\0');
    const DWORD count = GetFinalPathNameByHandleW(file.NativeHandle(), path.data(), static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED);
    if (count == 0 || count >= path.size())
    {
        ctx.Out.Fail(kncore::Status::IOError, L"ETL final path unavailable");
        return;
    }
    path.resize(count);
    TraceRead state{&ctx, static_cast<size_t>(limit), std::chrono::steady_clock::now() + std::chrono::seconds(10)};
    state.Result.Source = L"host-file:ETL";
    state.Result.Consistency = L"locked-source-path-based-consumer";
    EVENT_TRACE_LOGFILEW log = {};
    log.LogFileName = path.data();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = TraceEvent;
    log.BufferCallback = TraceBuffer;
    log.Context = &state;
    struct TraceHandle
    {
        PROCESSTRACE_HANDLE Value = INVALID_PROCESSTRACE_HANDLE;
        ~TraceHandle()
        {
            if (Value != INVALID_PROCESSTRACE_HANDLE)
            {
                CloseTrace(Value);
            }
        }
    } trace;
    trace.Value = OpenTraceW(&log);
    if (trace.Value == INVALID_PROCESSTRACE_HANDLE)
    {
        ctx.Out.Fail(kncore::Status::IOError, L"OpenTrace failed", {L"Win32", GetLastError(), L"OpenTraceW", path});
        return;
    }
    const ULONG error = ProcessTrace(&trace.Value, 1, nullptr, nullptr);
    const ULONG eventsLost = std::max(state.EventsLost, std::max(log.EventsLost, log.LogfileHeader.EventsLost));
    const ULONG buffersLost = std::max(state.BuffersLost, log.LogfileHeader.BuffersLost);
    auto summary = knjson::Value::MakeObject();
    summary.Set(L"kind", knjson::Value(L"EtlSummary"));
    summary.Set(L"path", knjson::Value(path));
    summary.Set(L"bytes", knjson::Value(std::to_wstring(file.Size())));
    summary.Set(L"eventsLost", knjson::Value(std::to_wstring(eventsLost)));
    summary.Set(L"buffersLost", knjson::Value(std::to_wstring(buffersLost)));
    summary.Set(L"metadataUnavailable", knjson::Value(std::to_wstring(state.MetadataMissing)));
    summary.Set(L"processTraceStatus", knjson::Value(kncore::Hex(error)));
    summary.Set(L"pointerSize", knjson::Value(std::to_wstring(log.LogfileHeader.PointerSize)));
    summary.Set(L"targetAssociation", knjson::Value(L"Unverified; recorded trace source"));
    state.Result.Rows.Push(summary);
    state.Result.Collected.Unknown = state.MetadataMissing + eventsLost + buffersLost;
    state.Result.Collected.Complete = error == ERROR_SUCCESS && !state.Stopped && state.Result.Collected.Unknown == 0;
    state.Result.Collected.StopReason = state.Result.Collected.Complete ? L"TraceHeadersImported"
                                        : state.Reason.empty()          ? L"TraceIncompleteOrMetadataUnavailable"
                                                                        : state.Reason;
    if (state.Fault)
    {
        state.Result.State = kncore::Status::InternalFault;
        state.Result.Error.Message = L"ETL callback failed";
    }
    else if (error != ERROR_SUCCESS && error != ERROR_CANCELLED)
    {
        state.Result.State = kncore::Status::IOError;
        state.Result.Error = {L"Win32", error, L"ProcessTrace", L"ETL processing failed"};
    }
    else if (!state.Result.Collected.Complete && state.Result.State == kncore::Status::Success)
    {
        state.Result.State = kncore::Status::Partial;
    }
    state.Result.Limitations.Push(
        knjson::Value(L"Event headers and size-limited raw previews only; payload fields and WPP/TMF messages are not decoded"));
    ctx.Out.Details = std::move(state.Result);
    for (size_t i = 0; i < ctx.Out.Details.Rows.Items().size() && i < 128; ++i)
    {
        ctx.Out.AddLine(ctx.Out.Details.Rows.Items()[i].Write());
    }
    ctx.Out.AddLine(summary.Write());
}
} // namespace kncmd
