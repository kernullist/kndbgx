#pragma once

#include "../core/ModelProjection.h"
#include "SnapshotRpcRegression.h"
#include "../core/DriverEvidence.h"
#include "PureRegression.h"

namespace knself
{
template <typename Check> void RunResultPageRegression(Check check)
{
    using namespace kncore;
    Result data;
    auto finding = knjson::Value::MakeObject();
    finding.Set(L"ruleId", knjson::Value(L"fixture/WritableExecutable"));
    finding.Set(L"severity", knjson::Value(L"warning"));
    finding.Set(L"message", knjson::Value(L"Fixture section is writable and executable"));
    finding.Set(L"evidence", knjson::Value(L"fixture-section"));
    finding.Set(L"provenance", knjson::Value(L"owned PE fixture"));
    for (size_t i = 0; i < 257; ++i)
    {
        data.Findings.Push(finding);
    }
    const auto retained = Results().Publish(L"rereview-findings", data, L"");
    const auto model = ProjectResult(*retained, 0, data.Stamp, 128);
    check(model.Get(L"RowCount").AsString(L"") == L"0" && model.Get(L"FindingCount").AsString(L"") == L"257" &&
              model.Get(L"RowsDelivery").AsString(L"") == L"Empty" && model.Get(L"Findings").Items().size() == 128 &&
              model.Get(L"NextFinding").AsString(L"") == L"256" && model.Get(L"Findings").Items()[0].Write() == finding.Write(),
          "rereview.finding-only-model-preserves-all-fields-and-independent-cursor");
    auto params = knjson::Value::MakeObject();
    params.Set(L"resultId", knjson::Value(retained->Id));
    const auto info = knbridge::HandleRequest(FixtureRpc(L"resultInfo", 501, params));
    check(info.Get(L"result").Get(L"findingCount").AsString(L"") == L"257" &&
              info.Get(L"result").Get(L"findingsDelivery").AsString(L"") == L"NotRequested",
          "rereview.finding-metadata-distinguishes-not-requested-from-empty");
    params.Set(L"collection", knjson::Value(L"findings"));
    params.Set(L"offset", knjson::Value(L"256"));
    const auto last = knbridge::HandleRequest(FixtureRpc(L"resultPage", 502, params));
    check(last.Get(L"ok").AsBool(false) && last.Get(L"result").Get(L"findings").Items().size() == 1 &&
              last.Get(L"result").Get(L"complete").AsBool(false) &&
              last.Get(L"result").Get(L"findings").Items()[0].Write() == finding.Write(),
          "rereview.ui-finding-pagination-preserves-original-record");
    Result importedDump;
    importedDump.Source = L"HostDumpMetadata";
    importedDump.Consistency = L"immutable-file";
    auto importedModule = knjson::Value::MakeObject();
    importedModule.Set(L"kind", knjson::Value(L"DumpModule"));
    importedModule.Set(L"base", knjson::Value(L"0x00007ffb10000000"));
    importedDump.Rows.Push(importedModule);
    const auto importedSource = Results().Publish(L"address-menu-imported-dump", importedDump, L"");
    auto addressParams = knjson::Value::MakeObject();
    addressParams.Set(L"resultId", knjson::Value(importedSource->Id));
    addressParams.Set(L"offset", knjson::Value(L"0"));
    addressParams.Set(L"collection", knjson::Value(L"rows"));
    const auto importedPage = knbridge::HandleRequest(FixtureRpc(L"resultPage", 510, addressParams));
    const auto &importedAddresses = importedPage.Get(L"result").Get(L"addressFields");
    check(importedPage.Get(L"ok").AsBool(false) && importedAddresses.IsArray() && importedAddresses.Items().size() == 1 &&
              importedAddresses.Items()[0].Items().empty() && importedPage.Get(L"result").Get(L"rows").Items()[0].Write() == importedModule.Write(),
          "address-menu.imported-file-projection-is-copy-only-and-keeps-original-record");

    Result dense;
    auto pointers = knjson::Value::MakeObject();
    for (size_t index = 0; index < 32; ++index)
    {
        auto pointer = knjson::Value::MakeObject();
        pointer.Set(L"address", knjson::Value(L"0xffff800000001000"));
        pointers.Set(std::wstring(60, L'a') + std::to_wstring(index), pointer);
    }
    for (size_t index = 0; index < 64; ++index)
    {
        dense.Rows.Push(pointers);
    }
    const auto denseSource = Results().Publish(L"address-menu-dense-projection", dense, L"");
    addressParams.Set(L"resultId", knjson::Value(denseSource->Id));
    size_t addressOffset = 0;
    bool projectionBounded = true;
    bool shrunk = false;
    while (addressOffset < dense.Rows.Items().size())
    {
        addressParams.Set(L"offset", knjson::Value(std::to_wstring(addressOffset)));
        const auto densePage = knbridge::HandleRequest(FixtureRpc(L"resultPage", 511, addressParams));
        const auto &response = densePage.Get(L"result");
        const auto &records = response.Get(L"rows").Items();
        const auto &addresses = response.Get(L"addressFields");
        uint64_t next = 0;
        projectionBounded = projectionBounded && densePage.Get(L"ok").AsBool(false) && !records.empty() &&
            records.size() == addresses.Items().size() && knutil::WideToUtf8(addresses.Write()).size() <= 24000 &&
            knutil::WideToUtf8(densePage.Write()).size() <= 65536 &&
            ParseUnsigned(response.Get(L"next").AsString(L""), 10, &next) && next == addressOffset + records.size();
        if (!projectionBounded)
        {
            break;
        }
        for (const auto &record : records)
        {
            projectionBounded = projectionBounded && record.Write() == pointers.Write();
        }
        shrunk = shrunk || records.size() < PageRecords(*denseSource, L"rows", addressOffset).Records.Items().size();
        addressOffset = static_cast<size_t>(next);
    }
    check(projectionBounded && shrunk && addressOffset == 64, "address-menu.dense-projection-shrinks-pages-without-losing-records");
    knengine::DbgSession detached;
    const auto cli = kncmd::DispatchCommand(detached, L"result-read rereview-findings 0 256");
    check(cli.Data.State == Status::Success && cli.Output.find(L"WritableExecutable") != std::wstring::npos,
          "rereview.cli-finding-only-page-accessible-offline");

    auto pe = PeFixture(true);
    pe.resize(0x600);
    StoreFixture(pe, 0x98 + sizeof(IMAGE_OPTIONAL_HEADER64) + offsetof(IMAGE_SECTION_HEADER, Characteristics),
                 DWORD(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE));
    const auto audit = AuditDriverPe(pe);
    StoredResult peResult{L"pe-wx", audit, L"", 0};
    const auto pePage = ProjectResult(peResult, 0, audit.Stamp);
    check(audit.Findings.Items().size() == 1 && pePage.Get(L"Findings").Items().size() == 1 &&
              pePage.Get(L"Findings").Items()[0].Write() == audit.Findings.Items()[0].Write(),
          "rereview.pe-writable-executable-finding-survives-projection");
    knjson::Value sarif;
    knjson::Parse(LR"({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"fixture"}},"results":[]}]})", &sarif);
    auto run = sarif.Get(L"runs").Items()[0];
    auto artifacts = knjson::Value::MakeArray();
    for (unsigned i = 0; i < 3; ++i)
    {
        auto artifact = knjson::Value::MakeObject();
        auto contents = knjson::Value::MakeObject();
        contents.Set(L"text", knjson::Value(std::wstring(600000, L'x')));
        artifact.Set(L"contents", contents);
        artifacts.Push(artifact);
    }
    run.Set(L"artifacts", artifacts);
    auto runs = knjson::Value::MakeArray();
    runs.Push(run);
    sarif.Set(L"runs", runs);
    const auto imported = ImportSarif(sarif);
    StoredResult sarifResult{L"large-sarif", imported, L"", 0};
    const auto sarifPage = PageRecords(sarifResult, L"rows", 0);
    const auto sarifModel = ProjectResult(sarifResult, 0, imported.Stamp);
    check(imported.State == Status::Success && imported.Rows.Items().size() == 1 && sarifPage.Valid && sarifPage.Next == 1 &&
              sarifPage.Referenced == 1 && sarifModel.Get(L"Next").AsString(L"") == L"1" && PageRecords(sarifResult, L"rows", 1).Valid,
          "rereview.original-sarif-three-large-inline-artifacts-page-advances");

    Result largeMetadata;
    largeMetadata.Limitations.Push(knjson::Value(L""));
    const auto baseUnits = largeMetadata.ToJson().Write().size();
    largeMetadata.Limitations = knjson::Value::MakeArray();
    largeMetadata.Limitations.Push(knjson::Value(std::wstring(16 * 1024 * 1024 - baseUnits, L'x')));
    const auto metadataSource = Results().Publish(L"large-metadata", largeMetadata, L"");
    params = knjson::Value::MakeObject();
    params.Set(L"resultId", knjson::Value(L"large-metadata"));
    const auto metadataReply = knbridge::HandleRequest(FixtureRpc(L"resultInfo", 503, params));
    check(metadataSource && metadataReply.Get(L"ok").AsBool(false) && metadataReply.Write().size() < 65536 &&
              metadataReply.Get(L"result").Get(L"data").Get(L"metadataOmitted").IsString(),
          "rereview.maximum-retained-metadata-produces-bounded-inspection-reply");
    const auto metadataCli = kncmd::DispatchCommand(detached, L"result-read large-metadata");
    knjson::Value metadataPage;
    check(metadataCli.Ok && metadataCli.Data.Collected.Complete && metadataCli.Output.size() < 65536 &&
              knjson::Parse(metadataCli.Output, &metadataPage) &&
              metadataPage.Get(L"Metadata").Get(L"kind").AsString(L"") == L"MetadataReference" &&
              metadataPage.Get(L"MetadataDelivery").AsString(L"") == L"Referenced" && metadataPage.Get(L"PageComplete").AsBool(false) &&
              metadataPage.Get(L"FindingPageComplete").AsBool(false),
          "rereview.maximum-retained-metadata-keeps-cli-model-page-readable");

    auto huge = knjson::Value::MakeObject();
    huge.Set(L"kind", knjson::Value(L"LargeFixture"));
    huge.Set(L"payload", knjson::Value(std::wstring(2 * 1024 * 1024, L'x')));
    for (size_t position = 0; position < 3; ++position)
    {
        StoredResult source{L"oversized", {}, L"", 0};
        for (size_t index = 0; index < 3; ++index)
        {
            source.Data.Rows.Push(index == position ? huge : finding);
        }
        const auto page = PageRecords(source, L"rows", 0, 2 * 1024 * 1024);
        const auto reference = page.Records.Items()[position];
        check(page.Valid && page.Next == 3 && page.Referenced == 1 && reference.Get(L"kind").AsString(L"") == L"RecordReference" &&
                  reference.Get(L"index").AsString(L"") == std::to_wstring(position) &&
                  reference.Get(L"resultId").AsString(L"") == source.Id,
              "rereview.oversized-first-middle-last-records-preserve-reference-and-progress");
    }
    for (wchar_t unit : {L'x', wchar_t(0xac00)})
    {
        StoredResult source{L"boundary", {}, L"", 0};
        auto item = knjson::Value::MakeObject();
        item.Set(L"payload", knjson::Value(std::wstring(512, unit)));
        source.Data.Rows.Push(item);
        const auto exact = knutil::WideToUtf8(source.Data.Rows.Write()).size();
        for (size_t budget : {exact - 1, exact, exact + 1})
        {
            const auto page = PageRecords(source, L"rows", 0, budget);
            check(page.Valid && page.Next == 1 && page.PayloadBytes <= budget && page.Referenced == (budget < exact ? 1u : 0u),
                  "rereview.page-exact-utf8-byte-budget-ascii-and-unicode");
        }
    }
    StoredResult empty{L"empty", {}, L"", 0};
    check(PageRecords(empty, L"findings", 0).Valid && PageRecords(empty, L"findings", 0).Total == 0 &&
              !PageRecords(empty, L"findings", 1).Valid && !PageRecords(empty, L"unknown", 0).Valid,
          "rereview.empty-collection-and-invalid-cursor-distinguished");
    data.Rows.Push(finding);
    StoredResult mixed{L"mixed", data, L"", 0};
    const auto final = ProjectResult(mixed, 0, data.Stamp, 257);
    check(final.Get(L"Rows").Items().size() == 1 && final.Get(L"Findings").Items().empty() &&
              final.Get(L"FindingPageComplete").AsBool(false) && final.Get(L"FindingCount").AsString(L"") == L"257",
          "rereview.independent-observation-and-finding-end-cursors");
}
} // namespace knself
