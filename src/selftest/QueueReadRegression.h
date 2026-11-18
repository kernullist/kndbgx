#pragma once

#include "CollectorRegression.h"
#include "../core/QueueRead.h"
#include "../core/TimerDpc.h"

namespace knself
{
template <typename Check> void RunQueueReadRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xffff800000000000ULL;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    ByteFixture memory;
    memory.Text(base, "", 4096);
    for (unsigned bank = 0; bank < 128; ++bank)
    {
        const auto head = base + bank * 32 + 8;
        memory.Put(head, head);
        memory.Put(head + 8, head);
    }
    WalkBudget empty;
    QueueReadMeter meter(memory);
    QueueReadCache cached(meter, empty, architecture, true);
    cached.Prepare(QueueReadCache::Heads, base, 4096);
    unsigned complete = 0;
    for (unsigned bank = 0; bank < 128; ++bank)
    {
        complete += WalkList(cached, base + bank * 32 + 8, architecture, empty,
            [](uint64_t)
            {
                return VisitDecision::Failed;
            }) ? 1 : 0;
    }
    check(complete == 128 && !empty.Stopped && empty.Report.Collected.Visited == 0 &&
        meter.Requests == 1 && meter.Bytes == 4096 && cached.CacheHits == 256,
        "timer.batched-heads-complete-empty-queues-with-one-target-read");

    constexpr uint64_t object = base + 0x1000;
    constexpr uint64_t dpc = base + 0x2000;
    const auto links = FixtureField(0x20, 16);
    const auto rawField = FixtureField(0x30, 8);
    const auto due = FixtureField(0x18, 8);
    const auto period = FixtureField(0x38, 4);
    const auto signal = FixtureField(4, 4);
    const auto type = FixtureField(0, 1);
    const auto routine = FixtureField(0x18, 8);
    memory.Text(object, "", 0x40);
    memory.Text(dpc, "", 0x20);
    memory.Put(base + 8, object + links.Offset);
    memory.Put(base + 16, object + links.Offset);
    memory.Put(object + links.Offset, base + 8);
    memory.Put(object + links.Offset + 8, base + 8);
    memory.Put(object + due.Offset, 0x123456789abcULL);
    memory.Put(object + period.Offset, 2040, 4);
    memory.Put(object + rawField.Offset, 0x7f11c82e62449d2aULL);
    memory.Put(dpc, 0x13, 1);
    memory.Put(dpc + routine.Offset, base + 0x3000);
    const TimerDpcKeys keys{0x123456789abcdef1ULL, 0x0f1e2d3c4b5a6978ULL};
    WalkBudget active;
    QueueReadMeter activeMeter(memory);
    QueueReadCache records(activeMeter, active, architecture, true);
    records.Prepare(QueueReadCache::Heads, base, 4096);
    bool observed = false;
    const bool walked = WalkList(records, base + 8, architecture, active,
        [&](uint64_t node)
        {
            const auto timer = node - links.Offset;
            const auto decoded = ValidatedTimerDpc(records, architecture, timer, ReadField(records, timer, rawField), keys, type,
                [&](uint64_t address)
                {
                    records.PrepareRecord(QueueReadCache::Dpc, address, {type, routine});
                });
            observed = decoded == dpc && ReadField(records, dpc, routine) == base + 0x3000 &&
                ReadField(records, timer, due) == 0x123456789abcULL && ReadField(records, timer, period) == 2040 &&
                ReadField(records, timer, signal) == 0;
            return VisitDecision::Continue;
        },
        [&](uint64_t node)
        {
            records.PrepareRecord(QueueReadCache::Timer, node - links.Offset, {links, rawField, due, period, signal});
        });
    check(walked && observed && activeMeter.Requests == 3 && active.Report.Collected.Decoded == 1,
        "timer.batched-records-retain-links-metadata-and-verified-dpc");

    unsigned preparedDpcs = 0;
    const auto rejectPrepare = [&](uint64_t)
    {
        ++preparedDpcs;
    };
    const auto readsBeforeNull = activeMeter.Requests;
    check(ValidatedTimerDpc(records, architecture, object, 0x7f11c86e1dbb1d3aULL, keys, type, rejectPrepare) == 0 &&
        !ValidatedTimerDpc(records, architecture, object, 0x7f11c82e62449d2aULL, std::nullopt, type, rejectPrepare) &&
        !ValidatedTimerDpc(records, architecture, object, 0x7f11c86e1dbb1d32ULL, keys, type, rejectPrepare) &&
        preparedDpcs == 0 && activeMeter.Requests == readsBeforeNull,
        "timer.null-or-unverified-dpc-never-triggers-speculative-io");

    memory.Put(object + links.Offset + 8, object);
    WalkBudget broken;
    QueueReadCache corrupt(memory, broken, architecture, true);
    corrupt.Prepare(QueueReadCache::Heads, base, 4096);
    const auto badList = WalkList(corrupt, base + 8, architecture, broken,
        [](uint64_t)
        {
            return VisitDecision::Continue;
        },
        [&](uint64_t node)
        {
            corrupt.PrepareRecord(QueueReadCache::Timer, node - links.Offset, {links});
        });
    check(!badList && broken.Report.Collected.StopReason == L"InconsistentBacklink",
        "timer.batching-preserves-backlink-corruption-detection");

    ByteFixture sparse;
    sparse.Put(object, 7);
    sparse.Put(object + 16, 9);
    WalkBudget partial;
    QueueReadCache fallback(sparse, partial, architecture, true);
    fallback.Prepare(QueueReadCache::Timer, object, 24);
    check(ReadField(fallback, object, FixtureField(0, 8)) == 7 &&
        ReadField(fallback, object, FixtureField(16, 8)) == 9 && sparse.Reads == 3 && !partial.Stopped,
        "timer.unreadable-batch-padding-falls-back-to-readable-fields");
    check(!ReadField(fallback, object, FixtureField(8, 8)), "timer.unreadable-field-is-never-a-cached-zero");

    WalkBudget live;
    QueueReadCache unbuffered(sparse, live, architecture, false);
    const auto beforeLive = sparse.Reads;
    unbuffered.Prepare(QueueReadCache::Timer, object, 8);
    const auto old = ReadField(unbuffered, object, FixtureField(0, 8));
    sparse.Put(object, 11);
    check(old == 7 && ReadField(unbuffered, object, FixtureField(0, 8)) == 11 && sparse.Reads == beforeLive + 2,
        "timer.running-target-does-not-reuse-prefetched-memory");

    WalkBudget bounds;
    QueueReadCache bounded(sparse, bounds, architecture, true);
    const auto beforeBounds = sparse.Reads;
    bounded.Prepare(QueueReadCache::Timer, UINT64_MAX - 7, 16);
    bounded.Prepare(QueueReadCache::Timer, 0x1000, 8);
    bounded.Prepare(QueueReadCache::Timer, object, 4097);
    bounded.PrepareRecord(QueueReadCache::Timer, object, {FixtureField(0, 8), FixtureField(512, 8)});
    check(sparse.Reads == beforeBounds, "timer.prefetch-rejects-overflow-user-addresses-and-unbounded-spans");
    bounded.Prepare(QueueReadCache::Timer, object, 8);
    const auto afterPrepare = sparse.Reads;
    bounded.Read(AddressSpace::Physical, object, 8);
    check(sparse.Reads == afterPrepare + 1, "timer.virtual-cache-cannot-satisfy-physical-reads");
    bounded.Prepare(QueueReadCache::Timer, object, 4097);
    sparse.Put(object, 13);
    check(ReadField(bounded, object, FixtureField(0, 8)) == 13,
        "timer.rejected-new-window-invalidates-the-old-record");

    WalkBudget cancellation;
    bool cancelled = false;
    cancellation.Cancelled = [&]()
    {
        return cancelled;
    };
    QueueReadCache stopped(sparse, cancellation, architecture, true);
    sparse.BeforeRead = [&]()
    {
        cancelled = true;
    };
    stopped.Prepare(QueueReadCache::Timer, object, 8);
    const auto beforeStopped = sparse.Reads;
    check(!ReadField(stopped, object, FixtureField(0, 8)) && sparse.Reads == beforeStopped &&
        cancellation.Report.State == Status::Cancelled, "timer.cancellation-during-prefetch-discards-read-and-stops-io");

    WalkBudget timeout;
    QueueReadCache expired(sparse, timeout, architecture, true);
    sparse.BeforeRead = [&]()
    {
        timeout.Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    };
    expired.Prepare(QueueReadCache::Timer, object, 8);
    const auto beforeExpired = sparse.Reads;
    check(!ReadField(expired, object, FixtureField(0, 8)) && sparse.Reads == beforeExpired &&
        timeout.Report.State == Status::Partial && timeout.Report.Collected.StopReason == L"CollectionBudget",
        "timer.blocking-read-over-deadline-cannot-publish-or-renew-budget");

    ByteFixture keyMemory;
    const uint64_t never = base + 0x6000, always = base + 0x6100;
    keyMemory.Put(never, keys.Never);
    keyMemory.Put(always, keys.Always);
    for (const auto state : {Status::Cancelled, Status::StaleContext, Status::InternalFault})
    {
        for (size_t at = 1; at <= 2; ++at)
        {
            WalkBudget initial;
            TerminalReadFixture initialFault(keyMemory, state, at);
            check(!ReadTimerDpcKeys(initialFault, never, always, initial) && initial.Stopped &&
                      initial.Report.State == state && initialFault.Requests == at, "timer.initial-key-read-preserves-terminal-cause");
            WalkBudget final;
            TerminalReadFixture fault(keyMemory, state, at);
            RecheckTimerDpcKeys(fault, never, always, keys, final);
            check(final.Stopped && final.Report.State == state && final.Report.Collected.StopReason != L"TimerDpcKeysChanged" &&
                      fault.Requests == at, "timer.final-key-read-preserves-terminal-cause");
        }
        WalkBudget stoppedWalk;
        stoppedWalk.Stop(state, L"InterruptedQueueRead");
        const auto before = keyMemory.Reads;
        RecheckTimerDpcKeys(keyMemory, never, always, keys, stoppedWalk);
        check(stoppedWalk.Report.State == state && stoppedWalk.Report.Collected.StopReason == L"InterruptedQueueRead" &&
                  keyMemory.Reads == before, "timer.no-validation-reads-after-interrupted-queue");
    }
    WalkBudget lateKeys;
    lateKeys.StartTraversal();
    const auto beforeLate = keyMemory.Reads;
    keyMemory.BeforeRead = [&]()
    {
        lateKeys.Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    };
    RecheckTimerDpcKeys(keyMemory, never, always, keys, lateKeys);
    check(lateKeys.Stopped && lateKeys.Report.State == Status::Partial && keyMemory.Reads == beforeLate + 1,
          "timer.final-key-read-cannot-outlive-shared-deadline");
    keyMemory.BeforeRead = {};
    WalkBudget stableKeys;
    RecheckTimerDpcKeys(keyMemory, never, always, keys, stableKeys);
    check(!stableKeys.Stopped, "timer.equal-observed-key-pair-verifies");
    keyMemory.Put(always, keys.Always ^ 1);
    WalkBudget changedKeys;
    RecheckTimerDpcKeys(keyMemory, never, always, keys, changedKeys);
    check(changedKeys.Report.State == Status::StaleContext && changedKeys.Report.Collected.StopReason == L"TimerDpcKeysChanged",
          "timer.changed-observed-key-pair-invalidates-decoding");
    keyMemory.Bytes.erase(always);
    WalkBudget missingKeys;
    RecheckTimerDpcKeys(keyMemory, never, always, keys, missingKeys);
    check(missingKeys.Stopped && missingKeys.Report.State == Status::StaleContext &&
              missingKeys.Report.Collected.StopReason == L"TimerDpcKeysUnreadable", "timer.missing-key-is-not-evidence-of-change");
}
} // namespace knself
