#pragma once

#include "FaultRegression.h"
#include "../util/MemoryExport.h"
#include "../core/MappedPe.h"

namespace knself
{
class ExportReader final : public kncore::TargetReader
{
  public:
    uint64_t Base = 0x100000;
    std::vector<unsigned char> Bytes = std::vector<unsigned char>(65568, 0x5a);
    size_t Calls = 0;
    size_t FailCall = 0;
    size_t PartialBytes = 0;
    kncore::Status Failure = kncore::Status::Partial;
    bool MalformedSuccess = false;
    kncore::AddressSpace LastSpace = kncore::AddressSpace::Virtual;

    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t length) override
    {
        ++Calls;
        LastSpace = space;
        kncore::ReadResult result;
        result.Space = space;
        result.Address = address;
        result.Requested = length;
        result.Bytes.resize(length);
        result.Valid.resize(length);
        result.Transferred = address >= Base && address - Base < Bytes.size()
                                 ? std::min<size_t>(length, Bytes.size() - static_cast<size_t>(address - Base))
                                 : 0;
        if (Calls == FailCall)
        {
            result.Transferred = std::min(result.Transferred, PartialBytes);
        }
        if (result.Transferred != 0)
        {
            std::copy_n(Bytes.begin() + static_cast<size_t>(address - Base), result.Transferred, result.Bytes.begin());
            std::fill_n(result.Valid.begin(), result.Transferred, static_cast<unsigned char>(1));
        }
        result.State = Calls == FailCall ? Failure : kncore::TransferStatus(length, result.Transferred, S_OK).State;
        result.Error = {L"HRESULT", 0, L"ReadMemory", L""};
        if (MalformedSuccess)
        {
            result.Valid.back() = 0;
        }
        return result;
    }
};

inline void RunMemoryExportRegression(CheckFn check)
{
    using kncore::AddressSpace;
    using kncore::Status;
    const auto run = [](ExportReader &reader, FaultArtifactOperations &operations, uint64_t length = 65568,
                        const std::function<bool()> &cancelled = {}, const std::function<bool()> &current = {})
    {
        return knutil::ExportMemoryRange(reader, AddressSpace::Physical, reader.Base, length, L"export-fixture.bin", cancelled, current,
                                         &operations);
    };
    {
        ExportReader reader;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations);
        check(result.State == Status::Success && result.Collected.Complete && result.Collected.Read == reader.Bytes.size() &&
                  result.Written == reader.Bytes.size() && result.Collected.Unknown == 0 && reader.Calls == 2 &&
                  reader.LastSpace == AddressSpace::Physical && operations.Bytes == reader.Bytes && operations.Commits == 1 &&
                  operations.Removes == 0,
              "dump.range-crosses-chunk-boundary-and-short-file-writes-preserve-every-byte");
    }
    {
        ExportReader reader;
        reader.FailCall = 2;
        reader.PartialBytes = 3;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations);
        check(result.State == Status::Partial && result.Error.Code == S_OK && result.Collected.Expected == 65568 &&
                  result.Collected.Visited == 65568 && result.Collected.Read == 65539 && result.Collected.Unknown == 29 &&
                  result.Collected.Unreadable == 0 && !result.Collected.Complete && result.Collected.StopReason == L"ReadFailed" &&
                  result.ReadAddress == reader.Base + 65536 && result.ReadRequested == 32 && result.ReadTransferred == 3 &&
                  result.FirstUnreadAddress == reader.Base + 65539 && operations.Commits == 0 && operations.Removes == 1,
              "dump.partial-S_OK-retains-progress-and-first-missing-byte-without-publishing");
    }
    for (const auto status : {Status::Unavailable, Status::Cancelled, Status::InternalFault, Status::StaleContext, Status::EngineError})
    {
        ExportReader reader;
        reader.FailCall = 1;
        reader.Failure = status;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations);
        check(result.State == status && result.Collected.Read == 0 && !result.Collected.Complete && operations.Commits == 0 &&
                  operations.Removes == 1,
              "dump.read-status-is-not-demoted-to-partial");
    }
    {
        ExportReader reader;
        reader.FailCall = 2;
        reader.Failure = Status::InternalFault;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations);
        check(result.State == Status::InternalFault && result.Collected.Read == 65536 && !result.FirstUnreadAddress &&
                  operations.Commits == 0 && operations.Removes == 1,
              "dump.engine-fault-after-readable-prefix-keeps-fault-status");
    }
    {
        ExportReader reader;
        reader.MalformedSuccess = true;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations);
        check(result.State == Status::InternalFault && result.Collected.StopReason == L"InvalidReadResult" && operations.Bytes.empty() &&
                  operations.Commits == 0,
              "dump.inconsistent-success-mask-cannot-publish-zero-filled-bytes");
    }
    for (unsigned failure = 0; failure < 6; ++failure)
    {
        ExportReader reader;
        FaultArtifactOperations operations;
        operations.FailCreate = failure == 0;
        operations.FailWrite = failure == 1;
        operations.ZeroWrite = failure == 2;
        operations.FailFlush = failure == 3;
        operations.FailClose = failure == 4;
        operations.FailCommit = failure == 5;
        const auto result = run(reader, operations, 4);
        check(result.State == Status::IOError && !result.Collected.Complete && operations.Commits == 0 &&
                  operations.Removes == (failure == 0 ? 0 : 1),
              "dump.file-failure-aborts-temporary-output");
    }
    for (unsigned stage = 0; stage < 4; ++stage)
    {
        ExportReader reader;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations, 65568,
                                [&]()
                                {
                                    return stage == 0 || (stage == 1 && reader.Calls != 0) ||
                                           (stage == 2 && operations.Bytes.size() == 65536) || (stage == 3 && operations.Flushed);
                                });
        check(result.State == Status::Cancelled && !result.Collected.Complete && operations.Commits == 0 &&
                  operations.Removes == (stage == 0 ? 0 : 1) &&
                  reader.Calls == (stage == 0   ? 0
                                   : stage == 3 ? 2
                                                : 1),
              "dump.cancellation-before-read-during-write-between-chunks-and-after-flush");
    }
    {
        ExportReader reader;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations, 4, {},
                                []()
                                {
                                    return false;
                                });
        check(result.State == Status::StaleContext && result.Collected.Read == 4 && !result.Collected.Complete && operations.Commits == 0 &&
                  operations.Removes == 1,
              "dump.context-change-prevents-file-commit");
    }
    {
        ExportReader reader;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations, 4,
                                [&]()
                                {
                                    return operations.Commits != 0;
                                });
        check(result.State == Status::Success && result.Collected.Complete && operations.Commits == 1,
              "dump.cancellation-after-commit-does-not-relabel-published-file");
    }
    for (const auto length : {uint64_t(0), uint64_t(64 * 1024 * 1024 + 1), UINT64_MAX})
    {
        ExportReader reader;
        FaultArtifactOperations operations;
        const auto result = run(reader, operations, length);
        check(result.State == Status::InvalidInput && reader.Calls == 0 && operations.Commits == 0,
              "dump.invalid-range-does-not-read-or-open-output");
    }
    for (const bool x64 : {false, true})
    {
        ExportReader reader;
        reader.Bytes = PeFixture(x64);
        const auto shortHeaders = kncore::ReadMappedPeHeaders(reader, reader.Base, 0x3000);
        check(shortHeaders.State == Status::Success && shortHeaders.Image.Is64 == x64 && shortHeaders.LastRead.Requested < 1024,
              "dump.PE-header-validation-does-not-require-unrelated-page-tail");
        const auto original = reader.Bytes;
        reader.Bytes.resize(0x2000);
        std::copy(original.begin() + 0x80, original.end(), reader.Bytes.begin() + 0x1000);
        StoreFixture(reader.Bytes, 0x3c, LONG(0x1000));
        StoreFixture(reader.Bytes, 0x1018 + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders), DWORD(0x2000));
        const auto padded = kncore::ReadMappedPeHeaders(reader, reader.Base, 0x3000);
        check(padded.State == Status::Success && padded.LastRead.Requested > 4096 && padded.Image.Is64 == x64,
              "dump.PE-headers-beyond-first-page-are-readable");
        StoreFixture(reader.Bytes, 0x1006, WORD(97));
        check(kncore::ReadMappedPeHeaders(reader, reader.Base, 0x3000).State == Status::Unavailable,
              "dump.PE-section-count-remains-bounded");
        reader.Bytes = original;
        StoreFixture(reader.Bytes, 0x3c, LONG(0x10000));
        check(kncore::ReadMappedPeHeaders(reader, reader.Base, 0x20000).State == Status::Unsupported, "dump.PE-header-budget-is-explicit");
        check(kncore::ReadMappedPeHeaders(reader, reader.Base, 0x3000).State == Status::Unavailable &&
                  kncore::ReadMappedPeHeaders(reader, UINT64_MAX - 20, 0x3000).State == Status::Unavailable,
              "dump.PE-NT-offset-and-module-overflow-are-rejected");
        reader.Bytes = original;
        check(kncore::ReadMappedPeHeaders(reader, reader.Base, 0x4000).State == Status::Unavailable, "dump.PE-size-must-match-module");
    }
    for (const auto status : {Status::Cancelled, Status::InternalFault, Status::EngineError})
    {
        ExportReader reader;
        reader.Bytes = PeFixture(true);
        reader.FailCall = 2;
        reader.Failure = status;
        check(kncore::ReadMappedPeHeaders(reader, reader.Base, 0x3000).State == status, "dump.PE-header-read-preserves-engine-failure");
    }
}
} // namespace knself
