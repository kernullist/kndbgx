#pragma once

#include "CollectorRegression.h"
#include "../core/AlpcPorts.h"
#include "../core/ResultAddress.h"

namespace knself
{
template <typename Check> void RunAlpcRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xffff800000000000ULL;
    constexpr uint64_t head = base + 0x1000, root = base + 0x2000, directory = base + 0x3000;
    constexpr uint64_t connection = base + 0x4000, client = base + 0x5000, server = base + 0x6000;
    constexpr uint64_t owner = base + 0x7000, info = base + 0x8000, cookie = base + 0x9000, offsets = base + 0x9100;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    const auto field = [](unsigned offset, unsigned size, FieldKind kind = FieldKind::Unsigned)
    {
        auto result = FixtureField(offset, size);
        result.Kind = kind;
        return result;
    };
    AlpcPortLayout layout;
    layout.Names.Buckets = field(0, 16, FieldKind::Array);
    layout.Names.Buckets->ElementSize = 8;
    layout.Names.Buckets->ArrayCount = 2;
    layout.Names.Next = field(0, 8, FieldKind::Pointer);
    layout.Names.Object = field(8, 8, FieldKind::Pointer);
    layout.Names.Body = field(0x30, 8, FieldKind::Composite);
    layout.Names.Type = field(0x18, 1);
    layout.Names.Mask = field(0x1a, 1);
    layout.Names.Parent = field(0, 8, FieldKind::Pointer);
    layout.Names.Length = field(8, 2);
    layout.Names.Maximum = field(10, 2);
    layout.Names.Buffer = field(16, 8, FieldKind::Pointer);
    layout.Names.NameInfoSize = 32;
    layout.Links = field(0, 16, FieldKind::Composite);
    layout.Communication = field(0x10, 8, FieldKind::Pointer);
    layout.Owner = field(0x18, 8, FieldKind::Pointer);
    layout.State = field(0x1a0, 4);
    layout.Initialized = layout.State;
    layout.Initialized->BitOffset = 0;
    layout.Initialized->BitWidth = 1;
    layout.Type = layout.State;
    layout.Type->BitOffset = 1;
    layout.Type->BitWidth = 2;
    layout.Connection = field(0, 8, FieldKind::Pointer);
    layout.Server = field(8, 8, FieldKind::Pointer);
    layout.Client = field(16, 8, FieldKind::Pointer);
    ByteFixture memory;
    memory.Put(cookie, 0xa7, 1);
    memory.Put(offsets, 0x40202000, 4);
    const auto object = [&](uint64_t body, unsigned type, uint64_t parent, const std::wstring &name)
    {
        memory.Text(body - 0x50, "", 0x70);
        memory.Put(body - 0x18, static_cast<uint8_t>(type ^ 0xa7 ^ ((body - 0x30) >> 8)), 1);
        memory.Put(body - 0x16, name.empty() ? 0 : 2, 1);
        memory.Put(body - 0x50, parent);
        memory.Put(body - 0x48, name.size() * 2, 2);
        memory.Put(body - 0x46, name.size() * 2, 2);
        memory.Put(body - 0x40, body + 0x400);
        for (size_t i = 0; i < name.size(); ++i)
        {
            memory.Put(body + 0x400 + i * 2, name[i], 2);
        }
    };
    object(root, 3, 0, L"");
    object(directory, 3, root, L"RPC Control");
    object(connection, 45, directory, L"TestPort");
    object(client, 45, 0, L"");
    object(server, 45, 0, L"");
    memory.Put(head, connection);
    memory.Put(head + 8, server);
    memory.Put(info, connection);
    memory.Put(info + 8, server);
    memory.Put(info + 16, client);
    const uint64_t ports[] = {head, connection, client, server, head};
    for (size_t i = 1; i <= 3; ++i)
    {
        memory.Put(ports[i], ports[i + 1]);
        memory.Put(ports[i] + 8, ports[i - 1]);
        memory.Put(ports[i] + 0x10, info);
        memory.Put(ports[i] + 0x18, owner);
        memory.Put(ports[i] + 0x1a0, i * 2 + 1, 4);
    }
    const auto collect = [&](ByteFixture &source, WalkBudget &budget, const std::function<void()> &onRow = {})
    {
        CollectAlpcPorts(source, architecture, layout, head, root, cookie, offsets, 45, 3, budget,
                         [&](const knjson::Value &row)
                         {
                             budget.Report.Rows.Push(row);
                             if (onRow)
                             {
                                 onRow();
                             }
                         });
        AttachAlpcConnectionNames(budget.Report);
    };
    WalkBudget full;
    collect(memory, full);
    check(full.Report.State == Status::Success && full.Report.Collected.Complete && full.Report.Rows.Items().size() == 3 &&
              full.Report.Analysis.Get(L"namedPorts").AsString(L"") == L"1" &&
              full.Report.Analysis.Get(L"unnamedPorts").AsString(L"") == L"2",
          "alpc.global-list-includes-both-unnamed-endpoints");
    const auto &rows = full.Report.Rows.Items();
    check(rows[0].Get(L"name").AsString(L"") == L"\\RPC Control\\TestPort" && rows[1].Get(L"name").IsNull() &&
              rows[1].Get(L"nameState").AsString(L"") == L"Unnamed" &&
              rows[1].Get(L"connectionName").AsString(L"") == rows[0].Get(L"name").AsString(L""),
          "alpc.connection-name-never-becomes-an-unnamed-endpoint-name");
    check(rows[1].Get(L"portType").AsString(L"") == L"Client communication" &&
              rows[2].Get(L"portType").AsString(L"") == L"Server communication" && rows[1].Get(L"peerPort").AsString(L"") == Hex(server) &&
              rows[2].Get(L"peerPort").AsString(L"") == Hex(client),
          "alpc.client-server-directions-and-peers-are-distinct");
    check(memory.LargestRead <= 0x38 && memory.Reads < 40, "alpc.small-field-reads-avoid-speculative-page-fetches");
    for (const auto *name : {L"peerPort", L"serverPort", L"clientPort", L"communicationInfo"})
    {
        check(AddressFieldSpace(rows[1], name, L"virtual") == L"virtual", "alpc.endpoint-addresses-remain-navigable");
    }
    check(!AddressFieldSpace(rows[1], L"portStateRaw", L"virtual"), "alpc.state-bits-are-not-addresses");

    auto broken = memory;
    broken.Put(head, head);
    broken.Put(head + 8, head);
    WalkBudget empty;
    collect(broken, empty);
    check(empty.Report.Collected.Complete && empty.Report.Rows.Items().empty(), "alpc.verified-empty-global-list-is-success");
    broken = memory;
    broken.Put(server, client);
    WalkBudget cycle;
    collect(broken, cycle);
    check(cycle.Report.Collected.StopReason == L"CycleOrRepeatedNode" && cycle.Report.Rows.Items().size() == 3,
          "alpc.global-list-cycle-preserves-observed-ports");
    broken = memory;
    broken.Put(client + 8, root);
    WalkBudget backlink;
    collect(broken, backlink);
    check(backlink.Report.Collected.StopReason == L"InconsistentAlpcPortBacklink" && backlink.Report.Rows.Items().size() == 1,
          "alpc.corrupt-backlink-stops-before-publishing-invalid-member");
    broken = memory;
    broken.Bytes.erase(client - 0x16);
    WalkBudget missingMask;
    collect(broken, missingMask);
    check(missingMask.Report.State == Status::Partial && missingMask.Report.Rows.Items()[1].Get(L"nameState").AsString(L"") == L"Unknown",
          "alpc.unreadable-name-mask-is-not-an-unnamed-port");
    broken = memory;
    broken.Put(client - 0x18, static_cast<uint8_t>(7 ^ 0xa7 ^ ((client - 0x30) >> 8)), 1);
    WalkBudget wrongType;
    collect(broken, wrongType);
    check(wrongType.Report.State == Status::Partial && wrongType.Report.Rows.Items().size() == 2,
          "alpc.non-port-list-member-is-not-decoded-as-alpc");
    broken = memory;
    broken.Put(directory - 0x50, directory);
    WalkBudget ancestry;
    collect(broken, ancestry);
    check(ancestry.Report.State == Status::Partial && ancestry.Report.Rows.Items()[0].Get(L"nameState").AsString(L"") == L"Unknown",
          "alpc.parent-cycle-cannot-fabricate-a-full-name");
    broken = memory;
    broken.Put(client + 0x1a0, 0, 4);
    WalkBudget noState;
    collect(broken, noState);
    check(noState.Report.State == Status::Partial && noState.Report.Rows.Items()[1].Get(L"portType").IsNull() &&
              noState.Report.Rows.Items()[1].Get(L"peerPort").IsNull(),
          "alpc.invalid-kind-does-not-invent-an-endpoint-direction");
    broken = memory;
    broken.Put(client + 0x10, 0x1000);
    WalkBudget badInfo;
    collect(broken, badInfo);
    check(badInfo.Report.State == Status::Partial && badInfo.Report.Rows.Items()[1].Get(L"connectionPort").IsNull(),
          "alpc.user-space-communication-pointer-is-rejected");
    broken = memory;
    WalkBudget changed;
    collect(broken, changed,
            [&]()
            {
                broken.Put(head, client);
            });
    check(changed.Report.State == Status::StaleContext, "alpc.changed-list-head-invalidates-completeness");
    broken = memory;
    WalkBudget changedCookie;
    collect(broken, changedCookie,
            [&]()
            {
                broken.Put(cookie, 0xa6, 1);
            });
    check(changedCookie.Report.State == Status::StaleContext, "alpc.changed-object-cookie-invalidates-completeness");
    broken = memory;
    WalkBudget limited;
    limited.MaxNodes = 1;
    collect(broken, limited);
    check(limited.Report.Rows.Items().size() == 1 && limited.Report.Collected.StopReason == L"GlobalWalkBudget",
          "alpc.port-count-bound-is-global");
    broken = memory;
    WalkBudget timed;
    timed.StartTraversal(std::chrono::steady_clock::now() - std::chrono::seconds(121), std::chrono::seconds(120));
    const auto before = broken.Reads;
    collect(broken, timed);
    check(timed.Report.Collected.StopReason == L"GlobalWalkBudget" && broken.Reads == before, "alpc.expired-budget-is-not-renewed");
    for (const unsigned cancelRead : {1u, 5u, 8u})
    {
        broken = memory;
        broken.Reads = 0;
        bool cancelled = false;
        broken.BeforeRead = [&]()
        {
            cancelled = broken.Reads >= cancelRead;
        };
        WalkBudget cancel;
        cancel.Cancelled = [&]()
        {
            return cancelled;
        };
        collect(broken, cancel);
        check(cancel.Report.State == Status::Cancelled && !cancel.Report.Collected.Complete,
              "alpc.cancellation-during-metadata-or-record-reads-is-preserved");
    }
    layout.Type->BitOffset = 2;
    WalkBudget conflict;
    broken = memory;
    collect(broken, conflict);
    check(conflict.Report.State == Status::Unavailable && conflict.Report.Rows.Items().empty(),
          "alpc.contradictory-pdb-bitfield-refuses-decoding");
}
} // namespace knself
