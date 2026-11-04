#pragma once

#include "FaultRegression.h"
#include "../util/ResultExport.h"
#include "SnapshotRpcRegression.h"
#include "../util/SnapshotStore.h"

namespace knself
{
template <typename Check> void RunResultExportRegression(Check check)
{
    using namespace kncore;
    const auto hashText = [](const std::wstring &text)
    {
        const auto utf8 = knutil::WideToUtf8(text);
        return knutil::Sha256Bytes(std::span(reinterpret_cast<const unsigned char *>(utf8.data()), utf8.size()));
    };
    knjson::Value canonical;
    const bool canonicalParsed =
        knjson::Parse(LR"({"escape":"\u0000\b\f\n\r\t\\\"","values":[true,false,null,1.25],"unicode":"\ud83d\ude80"})", &canonical);
    std::wstring streamed;
    size_t largest = 0;
    check(canonicalParsed && canonical.IsObject() &&
              canonical.WriteStream(
                  [&](std::wstring_view fragment)
                  {
                      largest = std::max(largest, fragment.size());
                      streamed.append(fragment);
                      return true;
                  }) &&
              streamed == canonical.Write() && largest <= 4104,
          "rereview.streaming-json-matches-canonical-types-escapes-and-unicode");
    bool scalarBoundary = true;
    std::wstring unicode(4094, L'x');
    unicode.append(L"\xd83d\xde80");
    unicode.append(9000, wchar_t(0xac00));
    check(knjson::WriteStringStream(unicode,
                                    [&](std::wstring_view fragment)
                                    {
                                        scalarBoundary = scalarBoundary && ValidUtf16(fragment) && fragment.size() <= 4104;
                                        return true;
                                    }) &&
              scalarBoundary,
          "rereview.streaming-json-never-splits-utf16-scalar-at-buffer-boundary");
    check(!knjson::WriteStringStream(std::wstring(1, wchar_t(0xd800)),
                                     [](auto)
                                     {
                                         return true;
                                     }),
          "rereview.streaming-json-rejects-unpaired-surrogate");
    StoredResult exportFixture{L"export-fixture", {}, unicode, 0};
    wchar_t temporary[32768] = {};
    GetTempPathW(_countof(temporary), temporary);
    Result cancelledData;
    auto cancelledRow = knjson::Value::MakeObject();
    cancelledRow.Set(L"payload", knjson::Value(std::wstring(65536, L'c')));
    cancelledData.Rows.Push(cancelledRow);
    const auto cancelledSource = Results().Publish(L"typed-cancelled-export", cancelledData, L"");
    const auto cancelledPath = std::wstring(temporary) + L"kndbgx-cancelled-export-" + knutil::UniqueSuffix() + L".json";
    auto params = knjson::Value::MakeObject();
    params.Set(L"command", knjson::Value(L"result-export typed-cancelled-export \"" + cancelledPath + L"\""));
    unsigned cancellationPolls = 0;
    const auto cancelledReply = knbridge::HandleRequest(FixtureRpc(L"execute", 907, params), nullptr,
                                                        [&]()
                                                        {
                                                            return ++cancellationPolls > 8;
                                                        });
    check(cancelledSource && cancelledReply.Get(L"result").Get(L"data").Get(L"status").AsString(L"") == L"Cancelled" &&
              GetFileAttributesW(cancelledPath.c_str()) == INVALID_FILE_ATTRIBUTES,
          "rereview.typed-offline-export-honors-ui-request-cancellation");

    for (unsigned scenario = 0; scenario < 7; ++scenario)
    {
        FaultArtifactOperations io;
        io.FailCreate = scenario == 0;
        io.FailWrite = scenario == 1;
        io.ZeroWrite = scenario == 2;
        io.FailFlush = scenario == 3;
        io.FailClose = scenario == 4;
        io.FailCommit = scenario == 5;
        const auto result = knutil::ExportStoredResult(
            exportFixture, L"rereview-export-fault.json",
            [&]()
            {
                return scenario == 6 && !io.Bytes.empty();
            },
            &io);
        check(result.State != Status::Success && !result.Collected.Complete && io.Commits == 0 && io.Removes == (scenario == 0 ? 0u : 1u),
              "rereview.export-fault-or-cancel-never-publishes-complete-artifact");
        if (scenario == 1 || scenario == 3)
        {
            check(result.Error.Code == ERROR_DISK_FULL && result.Error.Message.find(L"112") != std::wstring::npos &&
                      result.Error.Message.find(L"free disk space") != std::wstring::npos &&
                      result.Error.Message.find(L"rereview-export-fault.json") != std::wstring::npos &&
                      result.Error.Message.find(L"result-export export-fixture") != std::wstring::npos &&
                      exportFixture.Text == unicode,
                  "live.export-disk-full-identifies-destination-and-recovery-with-source-intact");
        }
    }
    FaultArtifactOperations shortWrites;
    for (bool afterCommit : {false, true})
    {
        FaultArtifactOperations boundary;
        const auto saved = knutil::ExportStoredResult(
            exportFixture, L"third-commit-boundary.json",
            [&]()
            {
                return afterCommit ? boundary.Commits != 0 : boundary.Flushed;
            },
            &boundary);
        check(afterCommit ? saved.State == Status::Success && boundary.Commits == 1
                          : saved.State == Status::Cancelled && boundary.Commits == 0 && boundary.Removes == 1,
              "third.T07.export-cancel-after-flush-prevents-publication-but-after-commit-keeps-success");
    }
    const auto shortResult = knutil::ExportStoredResult(exportFixture, L"rereview-export-short.json", {}, &shortWrites);
    std::wstring decoded;
    knjson::Value smallRoundtrip;
    check(shortResult.State == Status::Success && shortWrites.Commits == 1 && knutil::StrictUtf8(shortWrites.Bytes, decoded) &&
              knjson::Parse(decoded, &smallRoundtrip) && smallRoundtrip.Get(L"output").AsString(L"") == unicode &&
              smallRoundtrip.Get(L"completion").Get(L"outputSha256").AsString(L"") == hashText(knjson::Value(unicode).Write()),
          "rereview.export-short-writes-reassemble-complete-checksummed-unicode-document");

    for (unsigned scenario = 0; scenario < 2; ++scenario)
    {
        ResultStore store;
        Result data;
        auto record = knjson::Value::MakeObject();
        record.Set(L"payload", knjson::Value(std::wstring(scenario == 0 ? 9 * 1024 * 1024 : 0, L'a')));
        data.Rows.Push(record);
        data.Findings.Push(canonical);
        const size_t textUnits = scenario == 0 ? 4 * 1024 * 1024 : 32 * 1024 * 1024 - data.ToJson().Write().size();
        const auto retained = store.Publish(L"large-export", data, std::wstring(textUnits, scenario == 0 ? L'\\' : L'x'));
        const auto path = std::wstring(temporary) + L"kndbgx-export-" + knutil::UniqueSuffix() + L".json";
        const auto exported = retained ? knutil::ExportStoredResult(*retained, path) : Result();
        std::vector<unsigned char> bytes;
        std::wstring contents;
        knjson::Value document;
        knjson::ParseLimits limits;
        limits.MaxInputUnits = 40 * 1024 * 1024;
        limits.MaxStringUnits = 32 * 1024 * 1024;
        const bool parsed = exported.State == Status::Success && knutil::ReadArtifact(path, bytes, 40 * 1024 * 1024) &&
                            knutil::StrictUtf8(bytes, contents) && knjson::Parse(contents, &document, limits);
        check(retained && parsed && document.Get(L"output").AsString(L"") == retained->Text &&
                  document.Get(L"result").Write() == data.ToJson().Write() && document.Get(L"completion").Get(L"complete").AsBool(false) &&
                  document.Get(L"completion").Get(L"resultSha256").AsString(L"") == hashText(data.ToJson().Write()) &&
                  (scenario == 0 || retained->RetainedBytes == 64 * 1024 * 1024),
              scenario == 0 ? "rereview.windows-export-retained-escaped-envelope-over-16m-roundtrips"
                            : "rereview.windows-export-exact-retention-limit-roundtrips");
        if (retained && parsed)
        {
            const auto size = bytes.size();
            const auto digest = knutil::Sha256Bytes(bytes);
            const auto existing = knutil::ExportStoredResult(*retained, path);
            std::vector<unsigned char> preserved;
            check(existing.State == Status::IOError && knutil::ReadArtifact(path, preserved, 40 * 1024 * 1024) &&
                      preserved.size() == size && knutil::Sha256Bytes(preserved) == digest,
                  "rereview.export-existing-final-file-preserved");
        }
        DeleteFileW(path.c_str());
    }
}
} // namespace knself
