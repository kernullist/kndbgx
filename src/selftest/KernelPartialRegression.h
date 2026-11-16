#pragma once

#include "CollectorRegression.h"
#include "../core/KernelSymbolProfile.h"
#include "../core/NamespaceWalk.h"
#include "../core/TimerDpc.h"

namespace knself
{
template <typename Check> void RunKernelPartialRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xffff800000000000ULL;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    WalkBudget serialBudget;
    const auto start = std::chrono::steady_clock::now();
    StartNamespaceTraversal(serialBudget, start);
    StartNamespaceTraversal(serialBudget, start + std::chrono::seconds(10));
    check(serialBudget.Deadline == start + std::chrono::seconds(120), "alpc.serial-transport-budget-is-shared-and-cannot-be-renewed");
    const TimerDpcKeys keys{0x123456789abcdef1ULL, 0x0f1e2d3c4b5a6978ULL};
    ByteFixture timer;
    const auto type = FixtureField(0, 1);
    timer.Put(base + 0x2000, 0x13, 1);
    // Fixed vectors are generated from the independently reviewed writer.
    constexpr uint64_t rawDpc = 0x7f11c82e62449d2aULL;
    constexpr uint64_t rawNull = 0x7f11c86e1dbb1d3aULL;
    check(DecodeTimerDpc(rawDpc, base + 0x1000, keys) == base + 0x2000 &&
              ValidatedTimerDpc(timer, architecture, base + 0x1000, rawDpc, keys, type) == base + 0x2000,
          "timer.encoded-dpc-agrees-with-writer-vector-and-object-type");
    const auto reads = timer.Reads;
    check(ValidatedTimerDpc(timer, architecture, base + 0x1000, rawNull, keys, type) == 0 && timer.Reads == reads,
          "timer.encoded-null-is-not-dereferenced");
    check(!ValidatedTimerDpc(timer, architecture, base + 0x1000, rawDpc, std::nullopt, type) && timer.Reads == reads,
          "timer.missing-profile-never-guesses-a-plain-pointer");
    timer.Put(base + 0x2000, 0x1a, 1);
    check(ValidatedTimerDpc(timer, architecture, base + 0x1000, rawDpc, keys, type) == base + 0x2000,
          "timer.threaded-dpc-type-is-supported");
    timer.Put(base + 0x2000, 0x14, 1);
    check(!ValidatedTimerDpc(timer, architecture, base + 0x1000, rawDpc, keys, type), "timer.corrupt-type-does-not-produce-a-routine");
    timer.Bytes.clear();
    check(!ValidatedTimerDpc(timer, architecture, base + 0x1000, rawDpc, keys, type), "timer.missing-dpc-page-stays-unknown");
    timer.Put(base + 0x2000, 0x13, 1);
    const TimerDpcKeys zeroRawKeys{0, 0x001000000080ffffULL ^ (base + 0x2000)};
    check(ValidatedTimerDpc(timer, architecture, base + 0x1000, 0, zeroRawKeys, type) == base + 0x2000,
          "timer.raw-zero-must-still-be-decoded");
    const auto beforeInvalid = timer.Reads;
    check(!ValidatedTimerDpc(timer, architecture, base + 0x1000, 0x7f11c86e1dbb1d32ULL, keys, type) && timer.Reads == beforeInvalid,
          "timer.decoded-user-pointer-is-not-dereferenced");
    check(DecodeTimerDpc(0, base, TimerDpcKeys{}) == 0x000000000080ffffULL, "timer.zero-key-rotation-has-no-undefined-shift");

    ByteFixture services;
    constexpr uint64_t table = base + 0x10000;
    for (unsigned i = 0; i < 600; ++i)
    {
        services.Put(table + i * 4, static_cast<uint32_t>(-0x1000 * 16) | (i & 15), 4);
    }
    OwnershipIndex owners({{base, 0x20000, L"fixture", L"fixture"}}, true, {});
    const auto collect = [&](ByteFixture &memory, WalkBudget &budget)
    {
        CollectServiceEntries(memory, architecture, owners, table, 600, L"ShadowSSDT", 0x1000, L"fixture", budget,
                              [&](const knjson::Value &row)
                              {
                                  budget.Report.Rows.Push(row);
                              });
    };
    WalkBudget ssdt;
    collect(services, ssdt);
    check(ssdt.Report.Rows.Items().size() == 600 && services.Reads == 3 && services.LargestRead == 1024 &&
              ssdt.Report.Rows.Items()[599].Get(L"routine").AsString(L"") == Hex(table - 0x1000) &&
              ssdt.Report.Rows.Items()[599].Get(L"serviceId").AsString(L"") == Hex(0x1257),
          "ssdt.batched-signed-entries-preserve-service-id-and-ignore-low-argument-bits");
    auto broken = services;
    broken.Bytes.erase(table + 1030);
    WalkBudget partial;
    collect(broken, partial);
    check(partial.Report.Rows.Items().size() == 600 && partial.Report.Collected.Unreadable == 1 &&
              partial.Report.Rows.Items()[257].Get(L"routine").IsNull() && !partial.Report.Rows.Items()[258].Get(L"routine").IsNull(),
          "ssdt.partial-page-retains-other-slots-without-inventing-zero");
    bool cancelled = false;
    broken = services;
    broken.BeforeRead = [&]()
    {
        cancelled = true;
    };
    WalkBudget cancellation;
    cancellation.Cancelled = [&]()
    {
        return cancelled;
    };
    collect(broken, cancellation);
    check(cancellation.Report.State == Status::Cancelled && cancellation.Report.Rows.Items().empty(),
          "ssdt.cancellation-during-batch-read-does-not-publish-rows");
    check(ServiceDescriptorMatches({table, 0, 1497, table + 0x2000}, table, 1497, table + 0x2000) &&
              !ServiceDescriptorMatches({table, 0, 1496, table + 0x2000}, table, 1497, table + 0x2000) &&
              !ServiceDescriptorMatches({table + 8, 0, 1497, table + 0x2000}, table, 1497, table + 0x2000),
          "ssdt.shadow-descriptor-must-match-independent-table-symbol-and-limit");
    ByteFixture descriptor;
    descriptor.Text(base, "", 32);
    descriptor.Put(base, table);
    descriptor.Put(base + 16, 1497, 4);
    descriptor.Put(base + 24, table + 0x2000);
    WalkBudget stableDescriptor;
    check(RecheckServiceDescriptor(descriptor, base, {table, 0, 1497, table + 0x2000}, stableDescriptor),
          "ssdt.unchanged-descriptor-survives-final-read");
    descriptor.Put(base + 16, 1496, 4);
    WalkBudget movedDescriptor;
    check(!RecheckServiceDescriptor(descriptor, base, {table, 0, 1497, table + 0x2000}, movedDescriptor) &&
              movedDescriptor.Report.State == Status::StaleContext,
          "ssdt.changed-descriptor-invalidates-completeness");
    WalkBudget cancelledDescriptor;
    cancelled = false;
    cancelledDescriptor.Cancelled = [&]()
    {
        return cancelled;
    };
    descriptor.BeforeRead = [&]()
    {
        cancelled = true;
    };
    check(!RecheckServiceDescriptor(descriptor, base, {table, 0, 1497, table + 0x2000}, cancelledDescriptor) &&
              cancelledDescriptor.Report.State == Status::Cancelled,
          "ssdt.cancellation-during-final-read-is-not-misreported-as-stale");

    NamespaceLayout fields;
    const auto field = [](unsigned offset, unsigned size, FieldKind kind = FieldKind::Unsigned)
    {
        auto value = FixtureField(offset, size);
        value.Kind = kind;
        return value;
    };
    fields.Buckets = field(0, 16, FieldKind::Array);
    fields.Buckets->ElementSize = 8;
    fields.Buckets->ArrayCount = 2;
    fields.Next = field(0, 8, FieldKind::Pointer);
    fields.Object = field(8, 8, FieldKind::Pointer);
    fields.Body = field(0x30, 8, FieldKind::Composite);
    fields.Type = field(0x18, 1);
    fields.Mask = field(0x1a, 1);
    fields.Parent = field(0, 8, FieldKind::Pointer);
    fields.Length = field(8, 2);
    fields.Maximum = field(10, 2);
    fields.Buffer = field(16, 8, FieldKind::Pointer);
    fields.NameInfoSize = 32;
    constexpr uint64_t root = base + 0x1000, folder = base + 0x2000, port = base + 0x3000, ignored = base + 0x4000;
    constexpr uint64_t links = base + 0x5000, cookie = base + 0x6000, offsets = base + 0x6100;
    ByteFixture ns;
    ns.Put(cookie, 0xa7, 1);
    ns.Put(offsets, 0x40202000, 4);
    const auto object = [&](uint64_t body, unsigned typeIndex, uint64_t parent, const std::wstring &name)
    {
        ns.Text(body - 0x50, "", 0x50);
        ns.Put(body - 0x18, static_cast<uint8_t>(typeIndex ^ 0xa7 ^ ((body - 0x30) >> 8)), 1);
        ns.Put(body - 0x16, name.empty() ? 0 : 2, 1);
        ns.Put(body - 0x50, parent);
        ns.Put(body - 0x48, name.size() * 2, 2);
        ns.Put(body - 0x46, name.size() * 2, 2);
        ns.Put(body - 0x40, body + 0x100);
        for (size_t i = 0; i < name.size(); ++i)
        {
            ns.Put(body + 0x100 + i * 2, name[i], 2);
        }
    };
    object(root, 3, 0, L"");
    object(folder, 3, root, L"RPC Control");
    object(port, 45, folder, L"TestPort");
    object(ignored, 7, root, L"");
    ns.Put(root, links);
    ns.Put(root + 8, 0);
    ns.Put(folder, links + 32);
    ns.Put(folder + 8, 0);
    ns.Put(links, links + 16);
    ns.Put(links + 8, folder);
    ns.Put(links + 16, 0);
    ns.Put(links + 24, ignored);
    ns.Put(links + 32, 0);
    ns.Put(links + 40, port);
    const auto walk = [&](ByteFixture &memory, WalkBudget &budget, unsigned depth = 16, bool changeCookie = false)
    {
        WalkNamedNamespace(memory, architecture, fields, root, cookie, offsets, 3, 45, depth, budget,
                           [&](uint64_t body, unsigned, unsigned, const std::wstring &path)
                           {
                               auto row = knjson::Value::MakeObject();
                               row.Set(L"name", knjson::Value(path));
                               row.Set(L"address", knjson::Value(Hex(body)));
                               budget.Report.Rows.Push(row);
                               if (changeCookie)
                               {
                                   memory.Put(cookie, 0xa6, 1);
                               }
                               return true;
                           });
    };
    WalkBudget full;
    walk(ns, full);
    check(full.Report.Collected.Complete && full.Report.Collected.Visited == 3 && full.Report.Rows.Items().size() == 1 &&
              full.Report.Rows.Items()[0].Get(L"name").AsString(L"") == L"\\RPC Control\\TestPort" && ns.Reads <= 17,
          "alpc.filtered-batched-walk-finds-nested-port-without-reading-unrelated-names");
    broken = ns;
    broken.Put(links + 32, links + 32);
    WalkBudget cycle;
    walk(broken, cycle);
    check(cycle.Report.Collected.StopReason == L"CycleOrRepeatedNode" && cycle.Report.Rows.Items().size() == 1,
          "alpc.cycle-stops-and-preserves-observed-port");
    broken = ns;
    broken.Put(port - 0x50, root);
    WalkBudget wrongParent;
    walk(broken, wrongParent);
    check(wrongParent.Report.State == Status::Partial && wrongParent.Report.Rows.Items()[0].Get(L"name").AsString(L"missing").empty(),
          "alpc.name-parent-mismatch-cannot-fabricate-a-full-path");
    broken = ns;
    WalkBudget changed;
    walk(broken, changed, 16, true);
    check(changed.Report.State == Status::StaleContext, "alpc.cookie-change-invalidates-completeness");
    broken = ns;
    WalkBudget depth;
    walk(broken, depth, 0);
    check(depth.Report.Collected.StopReason == L"DepthLimit" && depth.Report.Rows.Items().empty(), "alpc.depth-limit-remains-explicit");
    broken = ns;
    broken.Bytes.erase(links);
    WalkBudget unreadable;
    walk(broken, unreadable);
    check(unreadable.Report.State == Status::Partial && !unreadable.Report.Collected.Complete,
          "alpc.unreadable-chain-is-not-an-empty-success");
    broken = ns;
    WalkBudget nodes;
    nodes.MaxNodes = 1;
    walk(broken, nodes);
    check(nodes.Report.Collected.StopReason == L"GlobalWalkBudget", "alpc.global-node-limit-applies-across-directories");
    cancelled = false;
    broken = ns;
    broken.Reads = 0;
    broken.BeforeRead = [&]()
    {
        cancelled = broken.Reads >= 4;
    };
    WalkBudget cancelNs;
    cancelNs.Cancelled = [&]()
    {
        return cancelled;
    };
    walk(broken, cancelNs);
    check(cancelNs.Report.State == Status::Cancelled && cancelNs.Report.Rows.Items().empty(),
          "alpc.cancellation-after-bucket-read-is-observed");
    broken = ns;
    cancelled = false;
    WalkBudget cancelVisitor;
    cancelVisitor.Cancelled = [&]()
    {
        return cancelled;
    };
    WalkNamedNamespace(broken, architecture, fields, root, cookie, offsets, 3, 45, 16, cancelVisitor,
                       [&](uint64_t, unsigned, unsigned, const std::wstring &)
                       {
                           cancelled = true;
                           return false;
                       });
    check(cancelVisitor.Report.State == Status::Cancelled, "alpc.visitor-cancellation-remains-cancelled");
    fields.Type->Offset = 0x19;
    check(!fields.Valid(), "alpc.contradictory-header-layout-rejects-profile-decoder");

    const ModuleIdentity nt{L"{4660396C-2030-4C03-9AF4-5FC6B15ADF98}", 1, 0x8664, 0xe1a9f520, 0x1459000, base, true};
    const ModuleIdentity win32k{L"{2414214E-C1ED-F9F3-CE5F-1595CCD37B1B}", 1, 0x8664, 0xeaa9257b, 0xca000, base, true};
    for (const auto family : {KernelLayoutFamily::TimerDpc, KernelLayoutFamily::ShadowService, KernelLayoutFamily::Win32kService,
                              KernelLayoutFamily::ObjectTypes, KernelLayoutFamily::ObjectNames, KernelLayoutFamily::AlpcPorts,
                              KernelLayoutFamily::FilteredService, KernelLayoutFamily::Win32kDispatch})
    {
        const auto identity = (family == KernelLayoutFamily::Win32kService || family == KernelLayoutFamily::Win32kDispatch) ? win32k : nt;
        ByteFixture code;
        std::map<std::wstring, uint64_t> symbols;
        for (const auto &[name, rva] : KernelProfileSymbols(family, true))
        {
            symbols[name] = base + rva;
        }
        for (const auto &window : KernelProfileWindows(family, true))
        {
            symbols[window.Symbol] = base + window.SymbolRva;
            const std::wstring bytes(window.Bytes);
            for (size_t i = 0; i < bytes.size(); i += 2)
            {
                code.Put(base + window.SymbolRva + window.Offset + i / 2, std::stoul(bytes.substr(i, 2), nullptr, 16), 1);
            }
        }
        if (family == KernelLayoutFamily::Win32kDispatch)
        {
            // Independent target bytes include padding skipped by control-flow disassembly.
            const std::string lookup = "83f901720f488b05443e0800ffc9488b04c8c3cc8bc1488d0d6b3e0800488b04c1c3";
            for (size_t i = 0; i < lookup.size(); i += 2)
            {
                code.Put(base + 0x5e50 + i / 2, std::stoul(lookup.substr(i, 2), nullptr, 16), 1);
            }
        }
        const auto resolve = [&](const wchar_t *name) -> std::optional<uint64_t>
        {
            return symbols.contains(name) ? std::optional<uint64_t>(symbols.at(name)) : std::nullopt;
        };
        check(std::wstring_view(VerifyKernelProfile(code, identity, family, resolve)) == L"Verified",
              "kernel.partial-profiles-accept-matching-identity-symbols-and-code");
        auto mismatch = identity;
        mismatch.Timestamp ^= 1;
        const auto before = code.Reads;
        check(std::wstring_view(VerifyKernelProfile(code, mismatch, family, resolve)) == L"NoMatchingKernelProfile" && code.Reads == before,
              "kernel.partial-profiles-refuse-other-images-before-reading");
        const auto window = KernelProfileWindows(family, true).front();
        code.Bytes[base + window.SymbolRva + window.Offset] ^= 1;
        check(std::wstring_view(VerifyKernelProfile(code, identity, family, resolve)) == L"KernelProfileBytesMismatch",
              "kernel.partial-profiles-refuse-changed-code");
    }
}
} // namespace knself
