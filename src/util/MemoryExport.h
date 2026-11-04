#pragma once

#include "ArtifactWriter.h"
#include "../core/CollectorRead.h"

namespace knutil
{
struct MemoryExportResult
{
    kncore::Status State = kncore::Status::Unavailable;
    kncore::Coverage Collected;
    kncore::NativeError Error;
    std::wstring Path;
    uint64_t Written = 0;
    uint64_t ReadAddress = 0;
    size_t ReadRequested = 0;
    size_t ReadTransferred = 0;
    std::optional<uint64_t> FirstUnreadAddress;
};

inline MemoryExportResult ExportMemoryRange(kncore::TargetReader &reader, kncore::AddressSpace space, uint64_t address, uint64_t length,
                                            const std::wstring &path, const std::function<bool()> &cancelled = {},
                                            const std::function<bool()> &contextCurrent = {}, ArtifactOperations *operations = nullptr)
{
    using kncore::Status;
    MemoryExportResult result;
    result.Collected.Expected = length;
    result.Collected.Unknown = length;
    ArtifactWriter file(operations, cancelled);
    const auto fail = [&](Status state, const wchar_t *reason, const kncore::NativeError &error = {})
    {
        result.State = state;
        result.Collected.StopReason = reason;
        result.Error = error;
    };
    do
    {
        if (length == 0 || length > 64 * 1024 * 1024 || !kncore::ValidRange(address, length))
        {
            fail(Status::InvalidInput, L"InvalidRange");
            break;
        }
        if (cancelled && cancelled())
        {
            fail(Status::Cancelled, L"Cancelled");
            break;
        }
        if (!file.Open(path))
        {
            fail(Status::IOError, L"OpenFailed", {L"Win32", file.Error(), L"Artifact.Open", L"cannot create output"});
            break;
        }
        result.Path = file.Path();
        uint64_t offset = 0;
        while (offset < length)
        {
            if (cancelled && cancelled())
            {
                fail(Status::Cancelled, L"Cancelled");
                break;
            }
            const size_t take = static_cast<size_t>(std::min<uint64_t>(length - offset, 65536));
            const auto read = reader.Read(space, address + offset, take);
            result.ReadAddress = address + offset;
            result.ReadRequested = take;
            result.ReadTransferred = read.Transferred;
            result.Collected.Visited += take;
            if (read.State != Status::Success && read.State != Status::Partial && read.State != Status::Unavailable)
            {
                fail(read.State, kncore::StatusName(read.State), read.Error);
                break;
            }
            const bool validShape = read.Requested == take && read.Bytes.size() == take && read.Valid.size() == take &&
                                    read.Transferred <= take &&
                                    static_cast<size_t>(std::count_if(read.Valid.begin(), read.Valid.end(),
                                                                      [](unsigned char byte)
                                                                      {
                                                                          return byte != 0;
                                                                      })) == read.Transferred;
            if (!validShape || (read.State == Status::Success && !kncore::ExactBytes(read, take)))
            {
                fail(Status::InternalFault, L"InvalidReadResult", read.Error);
                break;
            }
            result.Collected.Read += read.Transferred;
            // A short block read does not establish which later pages are absent.
            result.Collected.Unknown = length - result.Collected.Read;
            if (read.State != Status::Success)
            {
                const auto missing = std::find(read.Valid.begin(), read.Valid.end(), 0);
                if (missing != read.Valid.end())
                {
                    result.FirstUnreadAddress = address + offset + static_cast<uint64_t>(missing - read.Valid.begin());
                }
                fail(result.Collected.Read != 0 ? Status::Partial : Status::Unavailable, L"ReadFailed", read.Error);
                break;
            }
            if (!file.Write(read.Bytes))
            {
                const bool stopped = file.Error() == ERROR_CANCELLED;
                fail(stopped ? Status::Cancelled : Status::IOError, stopped ? L"Cancelled" : L"WriteFailed",
                     {L"Win32", file.Error(), L"Artifact.Write", L"output write failed"});
                break;
            }
            offset += take;
        }
        if (offset != length)
        {
            break;
        }
        if (contextCurrent && !contextCurrent())
        {
            fail(Status::StaleContext, L"ContextChanged");
            break;
        }
        if (!file.Commit())
        {
            const bool stopped = file.Error() == ERROR_CANCELLED;
            fail(stopped ? Status::Cancelled : Status::IOError, stopped ? L"Cancelled" : L"CommitFailed",
                 {L"Win32", file.Error(), L"Artifact.Commit", L"output commit failed; existing file preserved"});
            break;
        }
        result.State = Status::Success;
        result.Collected.Complete = true;
        result.Collected.StopReason = L"ArtifactCommitted";
    } while (false);
    result.Written = file.Written();
    return result;
}
} // namespace knutil
