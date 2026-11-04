#pragma once

#include "../util/CodeIntegrity.h"
#include "../cmd/Dispatcher.h"
#include "../cmd/CommandSpec.h"
#include <map>

namespace knself
{
template <typename Check> void RunPlatformPostureRegression(Check check)
{
    using namespace kncore;
    static_assert(CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED == 0x80);
    static_assert(CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED == 0x400);
    static_assert(CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED == 0x800);
    static_assert(CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED == 0x1000);
    static_assert(CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED == 0x2000);
    uint32_t flags = 0;
    uint32_t status = 0;
    ULONG returned = 8;
    ULONG length = 8;
    bool validRequest = false;
    const auto query = [&](ULONG informationClass, void *buffer, ULONG size, ULONG *received)
    {
        auto &information = *static_cast<SYSTEM_CODEINTEGRITY_INFORMATION *>(buffer);
        validRequest = informationClass == 103 && size == 8 && information.Length == 8 && information.CodeIntegrityOptions == 0;
        information.Length = length;
        information.CodeIntegrityOptions = flags;
        *received = returned;
        return static_cast<LONG>(status);
    };
    const auto read = [&]()
    {
        return CodeIntegrityReport(knutil::QueryCodeIntegrityWith(query));
    };
    const auto disabled = read();
    check(validRequest && disabled.State == Status::Success && disabled.Collected.Complete &&
              disabled.Rows.Items()[0].Get(L"raw").AsString(L"") == Hex(0) && disabled.Rows.Items()[0].Get(L"hvciEnabled").IsBool() &&
              !disabled.Rows.Items()[0].Get(L"hvciEnabled").AsBool(true),
          "posture.ci-valid-request-and-known-disabled");
    const wchar_t *names[] = {L"codeIntegrityEnabled", L"testSign",         L"umciEnabled",        L"umciAuditMode",
                              L"umciExclusionPaths",   L"testBuild",        L"preproductionBuild", L"debugMode",
                              L"flightBuild",          L"flightingEnabled", L"hvciEnabled",        L"hvciAuditMode",
                              L"hvciStrictMode",       L"hvciIumEnabled"};
    for (unsigned bit = 0; bit < 14; ++bit)
    {
        flags = 1U << bit;
        const auto observed = read();
        bool isolated = observed.State == Status::Success;
        for (unsigned field = 0; field < 14; ++field)
        {
            const auto &value = observed.Rows.Items()[0].Get(names[field]);
            isolated = isolated && value.IsBool() && value.AsBool(false) == (field == bit);
        }
        check(isolated, "posture.ci-each-public-bit-is-independent");
    }
    flags = 0x80000400;
    const auto future = read();
    check(future.State == Status::Partial && !future.Collected.Complete &&
              future.Rows.Items()[0].Get(L"unknownOptions").AsString(L"") == Hex(0x80000000) &&
              future.Rows.Items()[0].Get(L"hvciEnabled").AsBool(false),
          "posture.ci-future-bits-preserved-with-partial-coverage");
    const auto unknown = [&](const Result &report)
    {
        const auto &row = report.Rows.Items()[0];
        return report.State == Status::Unavailable && !report.Collected.Complete && row.Get(L"raw").IsNull() &&
               row.Get(L"unknownOptions").IsNull() &&
               std::all_of(std::begin(names), std::end(names),
                           [&](const auto *name)
                           {
                               return row.Get(name).IsNull();
                           });
    };
    check(unknown(CodeIntegrityReport(knutil::QueryCodeIntegrity(nullptr))), "posture.ci-missing-api-is-unknown");
    for (const uint32_t failure : {0xc0000022U, 0xc0000004U, 0x80000005U})
    {
        status = failure;
        const auto refused = read();
        check(unknown(refused) && refused.Error.Code == failure, "posture.ci-failed-or-warning-reply-does-not-decode-buffer");
    }
    status = 0;
    for (const ULONG invalid : {0UL, 4UL, 7UL, 9UL, 16UL})
    {
        returned = invalid;
        check(unknown(read()), "posture.ci-rejects-incomplete-or-oversized-return-length");
        returned = 8;
        length = invalid;
        check(unknown(read()), "posture.ci-rejects-incompatible-structure-length");
        length = 8;
    }

    std::map<uint32_t, std::array<uint32_t, 4>> leaves = {{0, {1, 0x756e6547, 0x6c65746e, 0x49656e69}},
                                                          {1, {0, 0, 0x80000000, 0}},
                                                          {0x40000000, {0x40000006, 0x7263694d, 0x666f736f, 0x76482074}},
                                                          {0x40000001, {0x31237648, 0, 0, 0}},
                                                          {0x40000006, {0x80000001, 2, 3, 4}}};
    std::vector<uint32_t> calls;
    const auto cpuidQuery = [&](uint32_t leaf, std::array<uint32_t, 4> &registers)
    {
        calls.push_back(leaf);
        const auto found = leaves.find(leaf);
        if (found != leaves.end())
        {
            registers = found->second;
        }
        return found != leaves.end();
    };
    const auto host = QueryHypervisorCpuid(cpuidQuery);
    const auto hostRow = HypervisorCpuidRow(host);
    check(host.Complete && host.CpuVendor == L"GenuineIntel" && host.HypervisorVendor == L"Microsoft Hv" && host.HardwareFeatures &&
              (*host.HardwareFeatures)[0] == 0x80000001 && hostRow.Get(L"hardwareRegisters").Get(L"edx").AsString(L"") == Hex(4),
          "posture.hv-qualified-interface-retains-all-raw-feature-registers");
    leaves[0x40000000][1] = 0x41414141;
    leaves[0x40000006] = {};
    const auto compatible = QueryHypervisorCpuid(cpuidQuery);
    check(compatible.HardwareFeatures && HypervisorCpuidRow(compatible).Get(L"hardwareFeatures").AsString(L"") == Hex(0),
          "posture.hv-vendor-neutral-interface-and-known-zero-features");
    leaves[0x40000000][1] = 0x7263694d;
    leaves[0x40000001][0] = 0;
    calls.clear();
    const auto incompatible = QueryHypervisorCpuid(cpuidQuery);
    check(incompatible.Complete && incompatible.HardwareStatus == L"InterfaceUnsupported" &&
              HypervisorCpuidRow(incompatible).Get(L"hardwareFeatures").IsNull() &&
              std::find(calls.begin(), calls.end(), 0x40000006U) == calls.end(),
          "posture.hv-microsoft-vendor-without-interface-never-reads-features");
    leaves[0x40000001][0] = 0x31237648;
    for (const uint32_t maximum : {0U, 0x40000000U, 0x40000005U, 0xffffffffU})
    {
        leaves[0x40000000][0] = maximum;
        calls.clear();
        const auto limited = QueryHypervisorCpuid(cpuidQuery);
        check(!limited.HardwareFeatures && std::find(calls.begin(), calls.end(), 0x40000006U) == calls.end() &&
                  limited.Complete == (maximum == 0x40000005),
              "posture.hv-feature-query-requires-valid-advertised-leaf-range");
    }
    leaves[1][2] = 0;
    calls.clear();
    const auto absent = QueryHypervisorCpuid(cpuidQuery);
    check(absent.Complete && absent.Present == false && calls.size() == 2 && !absent.HardwareFeatures,
          "posture.hv-no-advertisement-does-not-probe-hypervisor-leaves");
    leaves[0][0] = 0;
    calls.clear();
    const auto missing = QueryHypervisorCpuid(cpuidQuery);
    check(!missing.Complete && !missing.Present && calls.size() == 1 && HypervisorCpuidRow(missing).Get(L"hypervisorBit").IsNull(),
          "posture.hv-missing-basic-leaf-is-unknown-not-absent");
    leaves[0][0] = 1;
    leaves[1][2] = 0x80000000;
    leaves[0x40000000][0] = 0x40000006;
    leaves.erase(0x40000006);
    check(!QueryHypervisorCpuid(cpuidQuery).Complete, "posture.hv-failed-advertised-feature-read-is-incomplete");
    check(CpuidSignature(0x800a0041, 0, 0).starts_with(L"A\\x00\\x0a\\x80"), "posture.hv-vendor-bytes-do-not-inject-console-controls");

    kncmd::ParsedCommand parsed;
    check(kncmd::ParseCommand(L"!ci", &parsed) && kncmd::ParseCommand(L"!ci /host", &parsed) &&
              kncmd::ParseCommand(L"!CI /HOST", &parsed) && !kncmd::ParseCommand(L"!ci /host extra", &parsed) &&
              !kncmd::ParseCommand(L"!ci /target", &parsed),
          "posture.ci-registered-grammar-is-strict");
    knengine::DbgSession unbound;
    const auto refused = kncmd::DispatchCommand(unbound, L"!ci");
    check(refused.Data.State == Status::Unsupported && refused.Data.Rows.Items().empty(),
          "posture.ci-default-never-substitutes-host-for-unavailable-target");
    const auto live = kncmd::DispatchCommand(unbound, L"!ci /host");
    const auto &liveRows = live.Data.Rows.Items();
    check(liveRows.size() == 1 && live.Data.Source == L"HostSystemCodeIntegrity" &&
              liveRows[0].Get(L"scope").AsString(L"") == L"DebuggerHost" &&
              live.Data.Analysis.Get(L"targetCorrelation").AsString(L"") == L"NotRequested" &&
              (liveRows[0].Get(L"known").AsBool(false) ? liveRows[0].Get(L"raw").IsString() : liveRows[0].Get(L"raw").IsNull()),
          "posture.ci-explicit-host-query-retains-scope-and-native-outcome");

    const SessionStamp stamp{L"posture-local-kernel", 1, 2, 3, 4};
    auto changed = stamp;
    ++changed.TargetGeneration;
    for (const auto state : {Status::Success, Status::Partial})
    {
        auto correlated = live;
        correlated.Data.Stamp = stamp;
        correlated.Data.State = state;
        correlated.Data.Analysis.Set(L"targetCorrelation", knjson::Value(L"VerifiedLocalKernel"));
        kncmd::FinalizeCollection(correlated, kncmd::FindCommand(L"!ci"), changed, false);
        check(correlated.Data.State == Status::StaleContext && !correlated.Data.Collected.Complete &&
                  correlated.Data.Analysis.Get(L"targetCorrelation").AsString(L"") == L"ContextChanged",
              "posture.ci-local-correlation-must-be-fenced-through-dispatch-completion");
    }
    auto explicitHost = live;
    explicitHost.Data.Stamp = stamp;
    explicitHost.Data.State = Status::Success;
    explicitHost.Data.Collected.Complete = true;
    kncmd::FinalizeCollection(explicitHost, kncmd::FindCommand(L"!ci"), changed, false);
    check(explicitHost.Ok && explicitHost.Data.State == Status::Success && explicitHost.Data.Collected.Complete &&
              explicitHost.Data.Analysis.Get(L"targetCorrelation").AsString(L"") == L"NotRequested",
          "posture.ci-explicit-host-remains-independent-of-target-switches");
}
} // namespace knself
