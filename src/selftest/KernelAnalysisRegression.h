#pragma once

#include "PureRegression.h"
#include "../core/DriverEvidence.h"
#include "../core/IrpAnalysis.h"
#include "../core/EtwEvidence.h"
#include "../util/ArtifactWriter.h"
#include "../cmd/Dispatcher.h"
#include "../cmd/CommandSpec.h"
#include <set>

namespace knself
{
inline knjson::Value SarifFixture()
{
    knjson::Value document;
    knjson::Parse(
        LR"({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL fixture","rules":[{"id":"cpp/test","defaultConfiguration":{"level":"error"}}]}},"results":[{"ruleIndex":0,"message":{"text":"Fixture finding"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"driver.c"},"region":{"startLine":42}}}],"suppressions":[{"kind":"inSource","status":"accepted"}]}]}]})",
        &document);
    return document;
}

inline kncore::IrpLayout IrpFixtureLayout()
{
    kncore::IrpLayout layout;
    layout.HeaderBytes = 128;
    layout.StackBytes = 64;
    auto add = [](auto &fields, const wchar_t *name, uint32_t offset, uint32_t size)
    {
        kncore::FieldInfo field;
        field.Offset = offset;
        field.Size = size;
        fields[name] = field;
    };
    add(layout.Header, L"Type", 0, 2);
    add(layout.Header, L"Size", 2, 2);
    add(layout.Header, L"StackCount", 4, 1);
    add(layout.Header, L"CurrentLocation", 5, 1);
    uint32_t offset = 8;
    for (const wchar_t *name :
         {L"MdlAddress", L"UserBuffer", L"CancelRoutine", L"SystemBuffer", L"Thread", L"CurrentStackLocation", L"Information"})
    {
        add(layout.Header, name, offset, 8);
        offset += 8;
    }
    add(layout.Header, L"Flags", 64, 4);
    add(layout.Header, L"Status", 68, 4);
    add(layout.Header, L"Cancel", 72, 1);
    add(layout.Header, L"PendingReturned", 73, 1);
    add(layout.Header, L"RequestorMode", 74, 1);
    add(layout.Stack, L"MajorFunction", 0, 1);
    add(layout.Stack, L"MinorFunction", 1, 1);
    add(layout.Stack, L"Control", 3, 1);
    offset = 8;
    for (const wchar_t *name : {L"DeviceObject", L"FileObject", L"CompletionRoutine", L"Context", L"Type3InputBuffer"})
    {
        add(layout.Stack, name, offset, 8);
        offset += 8;
    }
    add(layout.Stack, L"IoControlCode", 48, 4);
    add(layout.Stack, L"InputBufferLength", 52, 4);
    add(layout.Stack, L"OutputBufferLength", 56, 4);
    return layout;
}

inline void RunKernelAnalysisRegression(CheckFn check)
{
    using namespace kncore;
    const auto ioctl = DecodeIoctl(0x8000e007u);
    check(ioctl.Get(L"vendorDevice").AsBool(false) && ioctl.Get(L"vendorFunction").AsBool(false) &&
              ioctl.Get(L"function").AsString(L"") == Hex(0x801) && ioctl.Get(L"method").AsString(L"") == L"METHOD_NEITHER" &&
              ioctl.Get(L"access").AsString(L"") == L"FILE_READ_ACCESS | FILE_WRITE_ACCESS",
          "kernel.ioctl-vendor-method-access-bits");
    check(!DecodeIoctl(0).Get(L"vendorDevice").AsBool(true) && DecodeIoctl(0).Get(L"access").AsString(L"") == L"FILE_ANY_ACCESS",
          "kernel.ioctl-zero-is-decodable");
    check(!DecodeNtStatus(0x80000005).Get(L"ntSuccess").AsBool(true) &&
              DecodeNtStatus(0xc0000005).Get(L"severity").AsString(L"") == L"Error" &&
              DecodeNtStatus(0x40000000).Get(L"ntSuccess").AsBool(false),
          "kernel.ntstatus-signed-success-and-severity");
    const auto kasan = DecodeBugcheck(0x1f2, {0xffff800000000123, 8, 0xfffff80012345678, 0x187});
    check(kasan.Get(L"address").AsString(L"") == L"0xffff800000000123" && kasan.Get(L"access").AsString(L"") == L"write" &&
              kasan.Get(L"shadowMeaning").AsString(L"") == L"Freed pool",
          "kernel.kasan-64bit-address-and-shadow");
    check(DecodeBugcheck(0x1f2, {0, 0, 0, 0x200}).Get(L"uninterpretedBits").AsString(L"") == Hex(0x200),
          "kernel.kasan-retains-unknown-bits");
    check(DecodeBugcheck(0xffffffff, {}).Get(L"name").AsString(L"").starts_with(L"Unknown"), "kernel.unknown-bugcheck-not-guessed");
    std::set<std::wstring> names;
    bool recipesValid = true;
    for (const auto &recipe : DiagnosticRecipes())
    {
        const auto operand = recipe.Operand == DiagnosticOperand::Address ? L"ffff800000001234"
                             : recipe.Operand == DiagnosticOperand::None  ? L""
                                                                          : L"driver.sys";
        recipesValid = recipesValid && names.insert(recipe.Name).second && DiagnosticCommand(recipe, operand).has_value();
        for (const wchar_t *bad : {L"0; g", L"0\n!verifier -disable", L"-disable", L"$(evil)", L"x y", L"\"file\"", L"@rip", L"x|g"})
        {
            recipesValid = recipesValid && !DiagnosticCommand(recipe, bad);
        }
    }
    check(recipesValid && names.size() >= 40, "kernel.recipes-unique-and-reject-command-injection");
    check(!DiagnosticCommand(*FindDiagnostic(L"device"), L"0") && !DiagnosticCommand(*FindDiagnostic(L"wdf-driver"), L""),
          "kernel.required-diagnostic-operands");
    check(DiagnosticCommand(*FindDiagnostic(L"wdf-driver"), L"TEST.SYS").value_or(L"") == L"!wdfkd.wdfdriverinfo TEST 0x31",
          "kernel.wdf-module-normalization");
    check(DiagnosticCommand(*FindDiagnostic(L"verifier"), L"").value_or(L"") == L"!verifier 3", "kernel.verifier-fixed-read-only-flags");
    auto layout = IrpFixtureLayout();
    constexpr uint64_t irpAddress = 0xffff800000001000;
    std::vector<unsigned char> irp(256);
    StoreFixture(irp, 0, uint16_t(6));
    StoreFixture(irp, 2, uint16_t(256));
    irp[4] = 2;
    irp[5] = 2;
    StoreFixture(irp, 48, irpAddress + 192);
    irp[128] = 14;
    irp[131] = 0xe0;
    StoreFixture(irp, 176, uint32_t(0x8000e007));
    auto observed = InspectIrpBytes(irpAddress, irp, layout);
    check(observed.State == Status::Success && observed.Rows.Items().size() == 3 && observed.Collected.Complete,
          "kernel.irp-complete-fixture");
    check(observed.Rows.Items()[1].Get(L"ioctl").Get(L"method").AsString(L"") == L"METHOD_NEITHER" &&
              observed.Rows.Items()[1].Get(L"invokeOnCancel").AsBool(false) && observed.Rows.Items()[2].Get(L"current").AsBool(false),
          "kernel.irp-stack-ioctl-and-completion");
    check(InspectIrpBytes(irpAddress, std::span(irp).first(255), layout).State == Status::Unavailable, "kernel.irp-short-read-rejected");
    irp[5] = 3;
    StoreFixture(irp, 48, irpAddress + 256);
    check(InspectIrpBytes(irpAddress, irp, layout).State == Status::Success, "kernel.irp-before-first-stack-slot");
    irp[5] = 0;
    check(InspectIrpBytes(irpAddress, irp, layout).State == Status::Unavailable, "kernel.irp-zero-current-location");
    irp[5] = 2;
    check(InspectIrpBytes(irpAddress, irp, layout).State == Status::Partial, "kernel.irp-stack-pointer-inconsistency");
    StoreFixture(irp, 48, irpAddress + 192);
    layout.Header.erase(L"Status");
    check(InspectIrpBytes(irpAddress, irp, layout).Rows.Items()[0].Get(L"status").IsNull() &&
              InspectIrpBytes(irpAddress, irp, layout).State == Status::Partial,
          "kernel.irp-missing-field-is-null-and-partial");
    check(!ValidIrpGeometry(UINT64_MAX - 10, 6, 256, 128, 64, 2, 2) && !ValidIrpGeometry(0, 6, 256, 128, 64, 255, 1),
          "kernel.irp-overflow-and-stack-budget");
    for (bool is64 : {false, true})
    {
        auto bytes = PeFixture(is64);
        bytes.resize(0x600);
        const auto audit = AuditDriverPe(bytes);
        check(audit.State == Status::Success && audit.Rows.Items()[0].Get(L"is64").AsBool(!is64) == is64,
              is64 ? "kernel.pe64-audit" : "kernel.pe32-audit");
        const size_t section = 0x98 + (is64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));
        std::memcpy(bytes.data() + section, "KASAN", 5);
        StoreFixture(bytes, section + offsetof(IMAGE_SECTION_HEADER, Characteristics),
                     DWORD(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE));
        const auto wx = AuditDriverPe(bytes);
        check(wx.Findings.Items().size() == 1 && wx.Rows.Items()[0].Get(L"kasanSectionPresent").AsBool(false),
              is64 ? "kernel.pe64-kasan-and-wx" : "kernel.pe32-kasan-and-wx");
        bytes.resize(0x400);
        check(AuditDriverPe(bytes).State == Status::InvalidInput, is64 ? "kernel.pe64-truncated-section" : "kernel.pe32-truncated-section");
    }
    auto pe = PeFixture(true);
    pe.resize(0x600);
    const size_t importOffset =
        0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(IMAGE_DATA_DIRECTORY);
    StoreFixture(pe, importOffset, IMAGE_DATA_DIRECTORY{0x1000, 40});
    IMAGE_IMPORT_DESCRIPTOR descriptor = {};
    descriptor.Name = 0x1080;
    descriptor.OriginalFirstThunk = 0x1090;
    descriptor.FirstThunk = 0x1090;
    StoreFixture(pe, 0x400, descriptor);
    std::memcpy(pe.data() + 0x480, "ntoskrnl.exe", 13);
    StoreFixture(pe, 0x490, uint64_t(0x10b0));
    std::memcpy(pe.data() + 0x4b2, "ExAllocatePool2", 16);
    const auto imports = AuditDriverPe(pe);
    check(imports.State == Status::Success && imports.Rows.Items().back().Get(L"name").AsString(L"") == L"ExAllocatePool2",
          "kernel.pe-import-rva-translation");
    StoreFixture(pe, 0x490, uint64_t(UINT64_MAX - 0x8000000000000000ULL));
    check(AuditDriverPe(pe).State == Status::Partial, "kernel.pe-malformed-import-is-partial");
    check(AuditDriverPe(
              pe,
              []()
              {
                  return true;
              }).State == Status::Cancelled,
          "kernel.pe-import-cancellation");
    auto sarif = ImportSarif(SarifFixture());
    check(sarif.State == Status::Success && sarif.Rows.Items().size() == 2, "kernel.sarif-valid-inline-import");
    const auto &finding = sarif.Rows.Items()[1];
    check(finding.Get(L"ruleId").AsString(L"") == L"cpp/test" && finding.Get(L"level").AsString(L"") == L"error" &&
              finding.Get(L"suppressions").Items().size() == 1 && finding.Get(L"rawResult").Get(L"locations").Items().size() == 1,
          "kernel.sarif-rule-default-and-suppression-retained");
    auto invalid = SarifFixture();
    invalid.Set(L"version", knjson::Value(L"1.0.0"));
    check(ImportSarif(invalid).State == Status::InvalidInput, "kernel.sarif-version-rejected");
    check(ImportSarif(
              SarifFixture(),
              []()
              {
                  return true;
              }).State == Status::Cancelled,
          "kernel.sarif-cancellation");
    auto many = SarifFixture();
    auto manyRuns = knjson::Value::MakeArray();
    auto manyRun = many.Get(L"runs").Items()[0];
    auto manyResults = knjson::Value::MakeArray();
    for (unsigned i = 0; i < 4096; ++i)
    {
        manyResults.Push(manyRun.Get(L"results").Items()[0]);
    }
    manyRun.Set(L"results", manyResults);
    manyRuns.Push(manyRun);
    manyRuns.Push(many.Get(L"runs").Items()[0]);
    many.Set(L"runs", manyRuns);
    check(!ImportSarif(many).Collected.Complete, "review.sarif-exact-limit-cannot-hide-later-runs");
    auto badRule = SarifFixture();
    auto badRuleRun = badRule.Get(L"runs").Items()[0];
    auto badRuleResult = badRuleRun.Get(L"results").Items()[0];
    badRuleResult.Set(L"ruleIndex", knjson::Value(12.0));
    auto badItems = knjson::Value::MakeArray();
    badItems.Push(badRuleResult);
    badRuleRun.Set(L"results", badItems);
    auto badRuns = knjson::Value::MakeArray();
    badRuns.Push(badRuleRun);
    badRule.Set(L"runs", badRuns);
    check(ImportSarif(badRule).State == Status::Partial, "review.sarif-invalid-rule-index-is-not-complete");
    auto invalidCertificate = PeFixture(true);
    invalidCertificate.resize(0x600);
    StoreFixture(invalidCertificate,
                 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY),
                 IMAGE_DATA_DIRECTORY{0xfffffff8, 256});
    check(AuditDriverPe(invalidCertificate).State == Status::Partial, "review.pe-invalid-certificate-directory-is-partial");
    check(!ValidIrpGeometry(UINT64_MAX - 255, 6, 256, 128, 64, 2, 3), "review.irp-one-past-pointer-cannot-wrap");
    auto overlap = PeFixture(true);
    overlap.resize(0x600);
    StoreFixture(overlap, 0x98 + sizeof(IMAGE_OPTIONAL_HEADER64) + offsetof(IMAGE_SECTION_HEADER, VirtualAddress), DWORD(0x200));
    check(AuditDriverPe(overlap).State == Status::Partial, "review.pe-section-header-overlap-is-partial");
    auto configPe = PeFixture(true);
    configPe.resize(0x600);
    IMAGE_LOAD_CONFIG_DIRECTORY64 config = {};
    config.Size = sizeof(config);
    config.GuardFlags = 0x100;
    config.GuardCFFunctionCount = 0x20000000000001;
    StoreFixture(configPe, 0x400, config);
    StoreFixture(configPe,
                 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof(IMAGE_DATA_DIRECTORY),
                 IMAGE_DATA_DIRECTORY{0x1000, sizeof(config)});
    check(AuditDriverPe(configPe).Rows.Items()[0].Get(L"guardCfFunctionCount").AsString(L"") == Hex(config.GuardCFFunctionCount),
          "kernel.pe-load-config-exact-64bit-count");
    StoreFixture(configPe, 0x400, DWORD(0xffff));
    check(AuditDriverPe(configPe).State == Status::Partial, "review.pe-load-config-declared-size-bounded");
    StoreFixture(configPe, 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders), DWORD(0x2000));
    check(AuditDriverPe(configPe).State == Status::InvalidInput, "review.pe-file-header-range-bounded");
    size_t index = 1;
    check(!JsonIndex(knjson::Value(0.5), 3, index) && !JsonIndex(knjson::Value(-1.0), 3, index) && !JsonIndex(knjson::Value(3.0), 3, index),
          "kernel.sarif-index-bounds");
    knengine::DbgSession detached;
    check(kncmd::DispatchCommand(detached, L"ioctl 100000000").Data.State == Status::InvalidInput, "kernel.dispatch-32bit-overflow");
    check(kncmd::DispatchCommand(detached, L"bugcheck-decode 1f2 1 2 3 187").Data.State == Status::Success,
          "kernel.dispatch-offline-kasan");
    check(kncmd::DispatchCommand(detached, L"diagnose locks").Data.State == Status::Unavailable,
          "kernel.dispatch-diagnostic-requires-target");
    check(kncmd::DispatchCommand(detached, L"etl-import missing.etl 16385").Data.State == Status::InvalidInput,
          "kernel.etl-row-budget-input");
    check(kncmd::DispatchCommand(detached, L"sarif-import missing.sarif").Data.State == Status::IOError, "kernel.sarif-missing-file");
    check(kncmd::DispatchCommand(detached, L"driver-audit missing.sys").Data.State == Status::IOError, "kernel.driver-missing-file");
    check(kncmd::DispatchCommand(detached, L"diag-catalog").Data.Rows.Items().size() == DiagnosticRecipes().size(),
          "kernel.diagnostic-catalog-dispatch");
    knjson::Value message;
    knjson::Value ruleMessage;
    knjson::Parse(LR"({"id":"diagnostic","arguments":["buffer"]})", &message);
    knjson::Parse(LR"({"messageStrings":{"diagnostic":{"text":"Check {0}: {{bound}}"}}})", &ruleMessage);
    check(SarifMessage(message, ruleMessage, {}).value_or(L"") == L"Check buffer: {bound}",
          "kernel.sarif-message-id-arguments-and-escaping");
    knjson::Parse(LR"({"text":"Value {9}","arguments":["x"]})", &message);
    check(!SarifMessage(message, {}, {}), "kernel.sarif-missing-format-argument");
    message.Set(L"text", knjson::Value(std::wstring(4096, L'x')));
    check(!SarifMessage(message, {}, {}), "kernel.sarif-render-budget-retains-raw-only");
    auto componentDoc = SarifFixture();
    auto componentRun = componentDoc.Get(L"runs").Items()[0];
    auto componentResult = componentRun.Get(L"results").Items()[0];
    knjson::Value ruleReference;
    knjson::Parse(LR"({"toolComponent":{"index":0},"index":0})", &ruleReference);
    componentResult.Set(L"rule", ruleReference);
    auto componentResults = knjson::Value::MakeArray();
    componentResults.Push(componentResult);
    componentRun.Set(L"results", componentResults);
    auto componentRuns = knjson::Value::MakeArray();
    componentRuns.Push(componentRun);
    componentDoc.Set(L"runs", componentRuns);
    const auto externalRule = ImportSarif(componentDoc);
    check(externalRule.State == Status::Partial && externalRule.Rows.Items()[1].Get(L"level").AsString(L"") == L"unknown",
          "review.sarif-extension-rule-never-uses-driver-default");
    std::vector<unsigned char> payload(300, 0xab);
    EVENT_RECORD event = {};
    event.EventHeader.TimeStamp.QuadPart = 0x123456789abcdef;
    event.EventHeader.EventDescriptor.Keyword = UINT64_MAX;
    event.EventHeader.ProcessId = 42;
    event.BufferContext.ProcessorNumber = 7;
    event.BufferContext.Alignment = 255;
    event.UserData = payload.data();
    event.UserDataLength = static_cast<USHORT>(payload.size());
    const auto eventRow = EtwHeaderRow(&event);
    check(eventRow.Get(L"processor").AsString(L"") == L"7", "review.etw-legacy-cpu-does-not-include-alignment-byte");
    check(eventRow.Get(L"timestampFileTime").AsString(L"") == L"81985529216486895" &&
              eventRow.Get(L"keyword").AsString(L"") == Hex(UINT64_MAX),
          "kernel.etw-exact-timestamp-and-keyword");
    check(eventRow.Get(L"payloadPreviewTruncated").AsBool(false) && eventRow.Get(L"payloadPreviewHex").AsString(L"").size() == 512,
          "kernel.etw-bounded-payload-preview");
    event.EventHeader.Flags = EVENT_HEADER_FLAG_PROCESSOR_INDEX;
    event.BufferContext.ProcessorIndex = 511;
    check(EtwHeaderRow(&event).Get(L"processor").AsString(L"") == L"511", "kernel.etw-extended-cpu-index");
    check(DecodeBugcheck(0x1f2, {1, 2, 3, 0}).Get(L"addressSpace").IsNull(), "review.offline-bugcheck-not-associated-with-active-target");
    wchar_t temporary[32768] = {};
    const DWORD temporarySize = GetTempPathW(_countof(temporary), temporary);
    const auto suffix = knutil::UniqueSuffix();
    const std::wstring path = std::wstring(temporary) + L"kndbgx-kernel-evidence-" + suffix + L".bin";
    bool filesValid = temporarySize > 0 && temporarySize < _countof(temporary) && !suffix.empty();
    auto write = [&](std::span<const unsigned char> bytes)
    {
        knutil::ArtifactWriter writer;
        return filesValid && writer.Open(path) && writer.Write(bytes) && writer.Commit();
    };
    const auto fixtureText = knutil::WideToUtf8(SarifFixture().Write());
    filesValid = write(std::span(reinterpret_cast<const unsigned char *>(fixtureText.data()), fixtureText.size()));
    check(filesValid && kncmd::DispatchCommand(detached, L"sarif-import \"" + path + L"\"").Data.State == Status::Success,
          "kernel.sarif-real-file-adapter-positive");
    if (filesValid)
    {
        DeleteFileW(path.c_str());
    }
    auto filePe = PeFixture(true);
    filePe.resize(0x600);
    filesValid = write(filePe);
    const auto fileAudit = filesValid ? kncmd::DispatchCommand(detached, L"driver-audit \"" + path + L"\"") : kncmd::CommandResult{};
    check(filesValid && fileAudit.Data.State == Status::Success &&
              fileAudit.Data.Rows.Items().back().Get(L"sha256").AsString(L"").size() == 64,
          "kernel.driver-file-audit-hash-and-signature-adapter");
    check(filesValid && kncmd::DispatchCommand(detached, L"etl-import \"" + path + L"\"").Data.State == Status::IOError,
          "kernel.etl-corrupt-file-rejected-by-native-reader");
    if (filesValid)
    {
        DeleteFileW(path.c_str());
    }
}
} // namespace knself
