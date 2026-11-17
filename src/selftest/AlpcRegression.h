#pragma once

#include "CollectorRegression.h"
#include "../core/AlpcPorts.h"
#include "../core/ResultAddress.h"
#include "../core/ReadTelemetry.h"

namespace knself
{
class AlpcShortRecordReader final : public kncore::TargetReader
{
  public:
    AlpcShortRecordReader(kncore::TargetReader &source, size_t prefix) : source_(source), prefix_(prefix)
    {
    }

    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t length) override
    {
        auto result = source_.Read(space, address, length);
        if (length == 0x1bc)
        {
            result.Bytes.resize(prefix_);
            result.Valid.resize(prefix_);
            result.Transferred = std::count(result.Valid.begin(), result.Valid.end(), 1);
            result.State = prefix_ == 0 ? kncore::Status::Unavailable : kncore::Status::Partial;
        }
        return result;
    }

  private:
    kncore::TargetReader &source_;
    size_t prefix_;
};

template <typename Check> void RunAlpcRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xffff800000000000ULL;
    constexpr uint64_t head = base + 0x1000, root = base + 0x2000, directory = base + 0x3000;
    constexpr uint64_t connection = base + 0x4000, client = base + 0x5000, server = base + 0x6000;
    constexpr uint64_t owner = base + 0x7000, info = base + 0x8000, cookie = base + 0x9000, offsets = base + 0x9100;
    ReadLatency latency;
    ReadResult sample;
    sample.State = Status::Success;
    sample.Transferred = 4;
    for (const int64_t us : {100, 999, 1000, 10000, 50000, 249999, 250000, 999999, 1000000})
    {
        latency.Observe(AddressSpace::Virtual, client, 4, sample, std::chrono::microseconds(us));
    }
    const auto histogram = latency.ToJson();
    const auto &buckets = histogram.Get(L"buckets").Items();
    check(buckets.size() == 6 && buckets[0].Get(L"count").AsString(L"") == L"2" &&
        buckets[1].Get(L"count").AsString(L"") == L"1" && buckets[2].Get(L"count").AsString(L"") == L"1" &&
        buckets[3].Get(L"count").AsString(L"") == L"2" && buckets[4].Get(L"count").AsString(L"") == L"2" &&
        buckets[5].Get(L"count").AsString(L"") == L"1" && buckets[5].Get(L"upperExclusiveUs").IsNull(),
        "alpc.latency-buckets-use-exclusive-microsecond-boundaries");
    sample.State = Status::Partial;
    sample.Transferred = 2;
    sample.Error.Code = 0x80004005;
    for (unsigned i = 0; i < 11; ++i)
    {
        latency.Observe(AddressSpace::Physical, info, 4, sample, std::chrono::microseconds(1500000));
    }
    const auto slow = latency.ToJson();
    check(slow.Get(L"slowReadCount").AsString(L"") == L"14" &&
        slow.Get(L"slowReadElapsedUs").AsString(L"") == L"18749999" &&
        slow.Get(L"maximumReadUs").AsString(L"") == L"1500000" &&
        slow.Get(L"firstSlowReads").Items().size() == 8 && slow.Get(L"slowSamplesTruncated").AsBool(false),
        "alpc.latency-sampling-is-bounded-with-untruncated-aggregate-cost");
    const auto &partialSample = slow.Get(L"firstSlowReads").Items()[3];
    check(partialSample.Get(L"space").AsString(L"") == L"physical" &&
        partialSample.Get(L"address").AsString(L"") == Hex(info) &&
        partialSample.Get(L"requestedBytes").AsString(L"") == L"4" &&
        partialSample.Get(L"transferredBytes").AsString(L"") == L"2" &&
        partialSample.Get(L"status").AsString(L"") == L"Partial" &&
        partialSample.Get(L"errorCode").AsString(L"") == Hex(0x80004005) &&
        partialSample.Get(L"readOrdinal").AsString(L"") == L"10",
        "alpc.slow-read-evidence-preserves-error-and-transfer-extent");
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    ReadTelemetry outerReads, innerReads;
    {
        ReadTelemetryScope outerScope(outerReads);
        try
        {
            ReadTelemetryScope innerScope(innerReads);
            ReadTiming timing;
            timing.StartedUtc100ns = 123456789;
            timing.ProcessId = 456;
            timing.ThreadId = 123;
            timing.EngineElapsed = std::chrono::microseconds(5500000);
            CurrentReadTelemetry->Observe(AddressSpace::Virtual, client, 4, sample,
                std::chrono::microseconds(5500010), timing);
            throw 1;
        }
        catch (int)
        {
            check(CurrentReadTelemetry == &outerReads, "read-telemetry.nested-scope-restored-on-exception");
        }
    }
    check(CurrentReadTelemetry == nullptr && outerReads.Requests == 0 && innerReads.Requests == 1 &&
        sample.State == Status::Partial && sample.Transferred == 2,
        "read-telemetry.scope-and-result-do-not-leak");
    const auto timingJson = innerReads.ToJson();
    const auto &timedSample = timingJson.Get(L"latency").Get(L"firstSlowReads").Items()[0];
    check(timingJson.Get(L"requestedBytes").AsString(L"") == L"4" &&
        timingJson.Get(L"readElapsedUs").AsString(L"") == L"5500010" &&
        timingJson.Get(L"engineElapsedUs").AsString(L"") == L"5500000" &&
        !timingJson.Get(L"evidenceIncomplete").AsBool(true) &&
        timedSample.Get(L"startedUtc100ns").AsString(L"") == L"123456789" &&
        timedSample.Get(L"processId").AsString(L"") == L"456" &&
        timedSample.Get(L"threadId").AsString(L"") == L"123" &&
        timedSample.Get(L"engineElapsedUs").AsString(L"") == L"5500000" &&
        timedSample.Get(L"outsideEngineUs").AsString(L"") == L"10",
        "read-telemetry.correlates-engine-wait-with-host-time-and-thread");
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
    const auto collect = [&](TargetReader &source, WalkBudget &budget, const std::function<void()> &onRow = {})
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
    check(memory.LargestRead == 0x1bc && memory.Reads < 30,
        "alpc.bounded-record-combines-header-and-state-without-page-fetches");
    for (const auto *name : {L"peerPort", L"serverPort", L"clientPort", L"communicationInfo"})
    {
        check(AddressFieldSpace(rows[1], name, L"virtual") == L"virtual", "alpc.endpoint-addresses-remain-navigable");
    }
    check(!AddressFieldSpace(rows[1], L"portStateRaw", L"virtual"), "alpc.state-bits-are-not-addresses");

    WalkBudget sharedDeadline;
    const auto start = std::chrono::steady_clock::now();
    StartAlpcTraversal(sharedDeadline, start);
    StartAlpcTraversal(sharedDeadline, start + std::chrono::seconds(30));
    check(sharedDeadline.Deadline == start + std::chrono::seconds(180) && sharedDeadline.MaxNodes == 65536 &&
        full.Report.Analysis.Get(L"traversalLimitMs").AsString(L"") == L"180000",
        "alpc.extended-serial-deadline-is-shared-and-never-renewed");
    check(full.Report.Analysis.Get(L"record").Get(L"readRequests").AsString(L"") == L"3" &&
        full.Report.Analysis.Get(L"record").Get(L"requestedBytes").AsString(L"") == L"1332" &&
        full.Report.Analysis.Get(L"state").Get(L"readRequests").AsString(L"") == L"0" &&
        full.Report.Analysis.Get(L"name").Get(L"readRequests").AsString(L"") == L"5" &&
        full.Report.Analysis.Get(L"communication").Get(L"readRequests").AsString(L"") == L"3" &&
        full.Report.Analysis.Get(L"name").Get(L"readElapsedMs").IsString(),
        "alpc.phase-metrics-count-single-descriptor-name-reads");
    for (const size_t prefix : {size_t(0), size_t(0x38)})
    {
        auto shortMemory = memory;
        shortMemory.Reads = 0;
        AlpcShortRecordReader shortReader(shortMemory, prefix);
        WalkBudget recovered;
        collect(shortReader, recovered);
        check(recovered.Report.State == Status::Success && recovered.Report.Collected.Complete &&
            recovered.Report.Rows.Write() == full.Report.Rows.Write() &&
            recovered.Report.Analysis.Get(L"record").Get(L"readRequests").AsString(L"") == (prefix == 0 ? L"6" : L"3") &&
            recovered.Report.Analysis.Get(L"state").Get(L"readRequests").AsString(L"") == L"3",
            "alpc.failed-or-short-record-falls-back-with-identical-fields");
        for (const unsigned cancelRead : {5u, 6u, 7u})
        {
            shortMemory.Reads = 0;
            WalkBudget cancelled;
            cancelled.Cancelled = [&]()
            {
                return shortMemory.Reads >= cancelRead;
            };
            collect(shortReader, cancelled);
            check(cancelled.Report.State == Status::Cancelled && shortMemory.Reads == cancelRead &&
                !cancelled.Report.Collected.Complete, "alpc.record-recovery-stops-without-extra-reads-after-cancellation");
        }
    }
    auto cachedMemory = memory;
    cachedMemory.Reads = 0;
    WalkBudget cached;
    cached.Report.Consistency = L"stopped";
    collect(cachedMemory, cached);
    check(cached.Report.Rows.Write() == full.Report.Rows.Write() && cachedMemory.Reads + 2 == memory.Reads &&
        cached.Report.Analysis.Get(L"communicationCacheHits").AsString(L"") == L"2" &&
        cached.Report.Analysis.Get(L"communicationCacheEntries").AsString(L"") == L"1" &&
        cached.Report.Analysis.Get(L"communication").Get(L"readRequests").AsString(L"") == L"1",
        "alpc.stopped-collection-reuses-complete-shared-endpoints-with-identical-rows");
    cachedMemory.Put(info, 0);
    WalkBudget nextCapture;
    nextCapture.Report.Consistency = L"dump";
    collect(cachedMemory, nextCapture);
    check(nextCapture.Report.Rows.Items()[0].Get(L"connectionPort").AsString(L"") == Hex(0) &&
        nextCapture.Report.Analysis.Get(L"communication").Get(L"readRequests").AsString(L"") == L"1",
        "alpc.communication-cache-is-never-reused-across-collections");

    cachedMemory = memory;
    WalkBudget running;
    running.Report.Consistency = L"live-nonatomic";
    collect(cachedMemory, running,
        [&]()
        {
            cachedMemory.Put(info, 0);
        });
    check(running.Report.Rows.Items()[0].Get(L"connectionPort").AsString(L"") == Hex(connection) &&
        running.Report.Rows.Items()[1].Get(L"connectionPort").AsString(L"") == Hex(0) &&
        running.Report.Analysis.Get(L"communicationCacheHits").AsString(L"") == L"0" &&
        running.Report.Analysis.Get(L"communication").Get(L"readRequests").AsString(L"") == L"3",
        "alpc.running-target-rereads-shared-communication-fields");

    cachedMemory = memory;
    cachedMemory.Bytes.erase(info + 8);
    WalkBudget partialInfo;
    partialInfo.Report.Consistency = L"stopped";
    collect(cachedMemory, partialInfo,
        [&]()
        {
            cachedMemory.Put(info + 8, server);
        });
    check(partialInfo.Report.State == Status::Partial && partialInfo.Report.Rows.Items()[0].Get(L"serverPort").IsNull() &&
        partialInfo.Report.Rows.Items()[1].Get(L"serverPort").AsString(L"") == Hex(server) &&
        partialInfo.Report.Analysis.Get(L"communication").Get(L"readRequests").AsString(L"") == L"2" &&
        partialInfo.Report.Analysis.Get(L"communicationCacheHits").AsString(L"") == L"1",
        "alpc.partial-communication-read-is-not-cached-or-filled-with-zero");

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
    broken.Bytes.erase(client + 0x1a0);
    WalkBudget missingState;
    collect(broken, missingState);
    check(missingState.Report.State == Status::Partial && missingState.Report.Rows.Items()[1].Get(L"portStateRaw").IsNull() &&
        missingState.Report.Rows.Items()[1].Get(L"portType").IsNull() && missingState.Report.Rows.Items()[1].Get(L"peerPort").IsNull() &&
        missingState.Report.Analysis.Get(L"state").Get(L"readRequests").AsString(L"") == L"1",
        "alpc.unreadable-state-remains-unknown-after-narrow-retry");
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
    StartAlpcTraversal(timed, std::chrono::steady_clock::now() - std::chrono::seconds(181));
    const auto before = broken.Reads;
    collect(broken, timed);
    check(timed.Report.Collected.StopReason == L"GlobalWalkBudget" && broken.Reads == before, "alpc.expired-budget-is-not-renewed");
    for (const unsigned cancelRead : {1u, 5u, 6u, 7u, 8u, 9u})
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
        check(cancel.Report.State == Status::Cancelled && !cancel.Report.Collected.Complete && broken.Reads == cancelRead,
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
