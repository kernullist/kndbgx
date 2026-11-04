#pragma once

#include "PureRegression.h"
#include "../cmd/CmdTypes.h"
#include "../util/ArtifactWriter.h"
#include "../util/FileReader.h"
#include "../util/HostCollectors.h"
#include "../engine/ContextGuard.h"
#include <future>

namespace knself
{
class FaultArtifactOperations final : public knutil::ArtifactOperations
{
  public:
    bool FailCreate = false;
    bool FailWrite = false;
    bool ZeroWrite = false;
    bool FailFlush = false;
    bool FailClose = false;
    bool FailCommit = false;
    size_t Removes = 0;
    size_t Commits = 0;
    bool Flushed = false;
    std::vector<unsigned char> Bytes;

    HANDLE Create(const std::wstring &, DWORD *error) override
    {
        *error = FailCreate ? ERROR_FILE_EXISTS : ERROR_SUCCESS;
        return FailCreate ? INVALID_HANDLE_VALUE : reinterpret_cast<HANDLE>(1);
    }
    bool Write(HANDLE, std::span<const unsigned char> bytes, DWORD *count, DWORD *error) override
    {
        *count = ZeroWrite ? 0 : static_cast<DWORD>(std::min<size_t>(3, bytes.size()));
        Bytes.insert(Bytes.end(), bytes.begin(), bytes.begin() + *count);
        *error = FailWrite ? ERROR_DISK_FULL : ERROR_SUCCESS;
        return !FailWrite;
    }
    bool Flush(HANDLE, DWORD *error) override
    {
        Flushed = true;
        *error = FailFlush ? ERROR_DISK_FULL : ERROR_SUCCESS;
        return !FailFlush;
    }
    bool Close(HANDLE, DWORD *error) override
    {
        const bool fail = FailClose;
        FailClose = false;
        *error = fail ? ERROR_INVALID_HANDLE : ERROR_SUCCESS;
        return !fail;
    }
    bool Commit(const std::wstring &, const std::wstring &, bool, DWORD *error) override
    {
        *error = FailCommit ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
        if (!FailCommit)
        {
            ++Commits;
        }
        return !FailCommit;
    }
    void Remove(const std::wstring &) override
    {
        ++Removes;
    }
};

class PartialReader final : public kncore::TargetReader
{
  public:
    kncore::ReadResult Read(kncore::AddressSpace, uint64_t, size_t length) override
    {
        kncore::ReadResult result;
        static_cast<kncore::TransferResult &>(result) = kncore::TransferStatus(length, 1, E_FAIL);
        result.Bytes.resize(length, 0);
        result.Valid.resize(length, 0);
        result.Bytes[0] = 7;
        result.Valid[0] = 1;
        return result;
    }
};

inline void RunFaultRegression(CheckFn check)
{
    using kncore::Status;
    size_t fallbackCalls = 0;
    const auto legacy = [&](size_t *count) -> int32_t
    {
        ++fallbackCalls;
        *count = 4;
        return S_OK;
    };
    const auto partial = kncore::PhysicalTransfer(
        4,
        [](size_t *count) -> int32_t
        {
            *count = 1;
            return E_FAIL;
        },
        legacy);
    check(partial.State == Status::Partial && partial.Transferred == 1 && fallbackCalls == 0,
          "T-PARTIAL-01 no retry after physical partial failure");
    kncore::PhysicalTransfer(
        4,
        [](size_t *count) -> int32_t
        {
            *count = 0;
            return E_ACCESSDENIED;
        },
        legacy);
    check(fallbackCalls == 0, "T-PARTIAL-01 access error does not trigger fallback");
    const auto supported = kncore::PhysicalTransfer(
        4,
        [](size_t *count) -> int32_t
        {
            *count = 0;
            return E_NOTIMPL;
        },
        legacy);
    check(supported.State == Status::Success && fallbackCalls == 1, "T-PARTIAL-01 unsupported zero transfer permits legacy path");
    PartialReader reader;
    uint64_t original = 0xfeed;
    check(!reader.ReadExact(kncore::AddressSpace::Virtual, 0, &original) && original == 0xfeed,
          "T-PARTIAL-01 incomplete bytes never become an exact value");
    check(kncore::TransferStatus(4, 5, S_OK).State == Status::InternalFault, "T-PARTIAL-01 invalid engine transfer count rejected");

    knengine::DbgSession session;
    std::vector<std::wstring> args;
    kncmd::CmdText output;
    kncmd::Ctx context = {session, args, output};
    kncmd::ExecuteCollector(
        [](kncmd::Ctx &)
        {
            throw std::runtime_error("fault injection");
        },
        context);
    check(output.Details.State == Status::InternalFault, "T-PARTIAL-01 C++ exception is not success");
    output = {};
    kncmd::ExecuteCollector(
        [](kncmd::Ctx &)
        {
            RaiseException(0xE0424242, 0, 0, nullptr);
        },
        context);
    check(output.Details.State == Status::InternalFault && output.Details.Error.Code == 0xE0424242,
          "T-PARTIAL-01 native exception is not success");
    const unsigned walksBeforeFault = knengine::Epochs().WalksInFlight();
    output = {};
    kncmd::ExecuteCollector(
        [](kncmd::Ctx &ctx)
        {
            knengine::ContextGuard outer(ctx.Session);
            knengine::ContextGuard inner(ctx.Session);
            RaiseException(0xE0424243, 0, 0, nullptr);
        },
        context);
    check(output.Details.State == Status::InternalFault && knengine::Epochs().WalksInFlight() == walksBeforeFault,
          "live.native-fault-releases-only-its-nested-context-walks");
    knengine::Epochs().Reconnect();
    check(knengine::Epochs().WalksInFlight() == walksBeforeFault,
          "live.reconnect-does-not-retain-faulted-walk-suppression");
    std::promise<void> foreignEntered;
    std::promise<void> foreignRelease;
    auto foreignReleased = foreignRelease.get_future();
    auto foreignWalk = std::async(std::launch::async, [&]()
    {
        knengine::SessionWalk owned;
        foreignEntered.set_value();
        foreignReleased.wait();
    });
    foreignEntered.get_future().wait();
    output = {};
    kncmd::ExecuteCollector(
        [](kncmd::Ctx &ctx)
        {
            knengine::ContextGuard guard(ctx.Session);
            RaiseException(0xE0424244, 0, 0, nullptr);
        },
        context);
    check(output.Details.State == Status::InternalFault && knengine::Epochs().WalksInFlight() == walksBeforeFault + 1,
          "live.native-fault-preserves-another-threads-active-walk");
    foreignRelease.set_value();
    foreignWalk.get();
    check(knengine::Epochs().WalksInFlight() == walksBeforeFault && knengine::SessionWalkDepth == 0,
          "live.foreign-walk-finishes-without-underflow-after-fault");
    const auto missing = kncmd::DispatchCommand(session, L"dump-analyze \"Z:\\missing-kndbgx-test.dmp\"");
    check(!missing.Ok && missing.Data.State == Status::IOError, "T-DUMP-01 real handler propagates open failure");

    const std::vector<unsigned char> expected = {1, 2, 3, 4, 5, 6, 7};
    FaultArtifactOperations shortWrites;
    {
        knutil::ArtifactWriter writer(&shortWrites);
        check(writer.Open(L"fault-unit.bin") && writer.Write(expected) && writer.Written() == expected.size() && writer.Commit() &&
                  shortWrites.Bytes == expected,
              "T-FILE-01 short writes finish exactly");
    }
    check(shortWrites.Commits == 1 && shortWrites.Removes == 0, "T-FILE-01 committed output is retained");
    for (int failure = 0; failure < 6; ++failure)
    {
        FaultArtifactOperations fault;
        fault.FailCreate = failure == 0;
        fault.FailWrite = failure == 1;
        fault.ZeroWrite = failure == 2;
        fault.FailFlush = failure == 3;
        fault.FailClose = failure == 4;
        fault.FailCommit = failure == 5;
        bool success = false;
        {
            knutil::ArtifactWriter writer(&fault);
            success = writer.Open(L"fault-unit.bin") && writer.Write(expected) && writer.Commit();
        }
        check(!success && fault.Commits == 0 && fault.Removes == (failure == 0 ? 0 : 1),
              "T-FILE-01 failed operation never commits or deletes foreign file");
    }

    wchar_t temporary[MAX_PATH + 1] = {};
    const DWORD tempCount = GetTempPathW(MAX_PATH, temporary);
    const std::wstring path = std::wstring(temporary) + L"knx-" + knutil::UniqueSuffix() + L" \ud14c\uc2a4\ud2b8.bin";
    bool created = false;
    if (tempCount != 0 && tempCount < MAX_PATH)
    {
        knutil::ArtifactWriter writer;
        created = writer.Open(path) && writer.Write(expected) && writer.Commit();
    }
    check(created, "T-FILE-01 Windows Unicode artifact commit");
    if (created)
    {
        knutil::ArtifactWriter replacement;
        check(replacement.Open(path) && replacement.WriteText(L"replacement") && !replacement.Commit(),
              "T-FILE-01 existing destination preserved by default");
        {
            knutil::FileReader actual(path);
            std::vector<unsigned char> bytes(expected.size());
            check(actual.Size() == expected.size() && actual.Read(0, bytes) && bytes == expected, "T-FILE-01 existing bytes unchanged");
        }
        DeleteFileW(path.c_str());
    }

    for (int mode = 0; mode < 4; ++mode)
    {
        size_t calls = 0;
        const auto hash = knutil::Sha256Stream(
            [&](std::span<unsigned char> buffer, size_t *count, bool *eof) -> DWORD
            {
                ++calls;
                if (mode == 1 || (mode == 2 && calls == 2))
                {
                    return ERROR_READ_FAULT;
                }
                if (mode == 3 || calls == 2)
                {
                    *eof = true;
                    return ERROR_SUCCESS;
                }
                std::memcpy(buffer.data(), "abc", 3);
                *count = 3;
                return ERROR_SUCCESS;
            });
        if (mode == 0)
        {
            check(hash.State == Status::Success && hash.Digest == L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  "T-HASH-01 actual CNG known SHA-256");
        }
        else if (mode == 3)
        {
            check(hash.State == Status::Success && hash.Digest == L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "T-HASH-01 empty stream requires normal EOF");
        }
        else
        {
            check(hash.State == Status::IOError && hash.Digest.empty(), "T-HASH-01 read failure never exposes prefix digest");
        }
    }

    for (const DWORD interrupted : {ERROR_CANCELLED, ERROR_TIMEOUT})
    {
        const auto hash = knutil::Sha256Stream(
            [&](std::span<unsigned char>, size_t *, bool *)
            {
                return interrupted;
            });
        check(hash.Digest.empty() && hash.State == (interrupted == ERROR_CANCELLED ? Status::Cancelled : Status::Partial),
              "T-HASH-02 cancellation and budget never expose a digest");
    }
    size_t nextCalls = 0;
    size_t freed = 0;
    size_t destroyed = 0;
    size_t visited = 0;
    int item = 7;
    const auto create = [](HANDLE, auto, HANDLE *handle) -> DWORD
    {
        *handle = reinterpret_cast<HANDLE>(1);
        return ERROR_SUCCESS;
    };
    const auto next = [&](HANDLE, HANDLE, UINT32, int ***objects, UINT32 *count) -> DWORD
    {
        ++nextCalls;
        *count = nextCalls <= 4 ? 256 : nextCalls == 5 ? 17 : 0;
        if (*count != 0)
        {
            *objects = new int *[*count];
            std::fill_n(*objects, *count, &item);
        }
        return ERROR_SUCCESS;
    };
    const auto destroy = [&](HANDLE, HANDLE) -> DWORD
    {
        ++destroyed;
        return ERROR_SUCCESS;
    };
    const auto free = [&](void **objects)
    {
        delete[] static_cast<int **>(*objects);
        *objects = nullptr;
        ++freed;
    };
    const auto result = knutil::EnumerateWfp<int>(nullptr, create, next, destroy, free,
                                                  [&](int)
                                                  {
                                                      ++visited;
                                                  });
    check(result.State == Status::Success && result.Coverage.Complete && result.Coverage.Read == 1041 && visited == 1041 &&
              nextCalls == 6 && freed == 5 && destroyed == 1,
          "T-WFP-01 multiple pages through empty final page");
    const auto denied = knutil::EnumerateWfp<int>(
        nullptr,
        [](HANDLE, auto, HANDLE *) -> DWORD
        {
            return ERROR_ACCESS_DENIED;
        },
        next, destroy, free,
        [](int)
        {
        });
    check(denied.State == Status::Unavailable && denied.Error == ERROR_ACCESS_DENIED && nextCalls == 6,
          "T-WFP-01 positive DWORD error is failure");
    bool providerCorrect = false;
    const auto acpi = knutil::QueryAcpi(
        0x52414d44,
        [&](DWORD provider, DWORD table, void *, DWORD) -> DWORD
        {
            providerCorrect = provider == 0x41435049 && table == 0x52414d44;
            return 0;
        },
        []() -> DWORD
        {
            return ERROR_ACCESS_DENIED;
        });
    check(providerCorrect && acpi.Bytes == 0 && acpi.Error == ERROR_ACCESS_DENIED, "T-ACPI-01 signature and failure provenance");
}
} // namespace knself
