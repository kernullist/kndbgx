#pragma once

#include "../core/Layout.h"
#include "../core/Walker.h"
#include "../core/Ownership.h"
#include "../core/Epochs.h"
#include "../engine/PageWalk.h"
#include "../core/CpuMap.h"
#include <cstring>

namespace knself
{
class ChainFixture final : public kncore::TargetReader
{
  public:
    std::map<uint64_t, uint64_t> Links;
    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t length) override
    {
        kncore::ReadResult result;
        result.Address = address;
        result.Space = space;
        result.Requested = length;
        const auto found = Links.find(address);
        if (found != Links.end() && length == 8)
        {
            result.Bytes.resize(8);
            std::memcpy(result.Bytes.data(), &found->second, 8);
            result.Transferred = 8;
            result.Valid.assign(8, 1);
            result.State = kncore::Status::Success;
        }
        else
        {
            result.State = kncore::Status::Unavailable;
        }
        return result;
    }
};

template <typename Check> void RunLayoutRegression(Check check)
{
    kncore::TargetArchitecture x64{0x8664, 8, 48, 52};
    kncore::TargetArchitecture la57{0x8664, 8, 57, 52};
    kncore::TargetArchitecture unknown{0x8664, 8, {}, {}};
    check(x64.Canonical(0x7fffffffffff) && !x64.Canonical(0x800000000000) && x64.KernelPointer(0xffff800000000000),
          "arch.x64-sign-extension-boundary");
    check(la57.KernelPointer(0xff00000000000000) && !x64.KernelPointer(0xff00000000000000) && !unknown.Canonical(0x1000),
          "arch.la57-and-unknown-not-conflated");
    kncore::FieldInfo field;
    field.Offset = 0;
    field.Size = 4;
    field.Kind = kncore::FieldKind::Unsigned;
    check(field.ValidFor(8) && field.SimpleWritable(), "layout.offset-zero-valid");
    field.BitOffset = 0;
    field.BitWidth = 3;
    check(field.ValidFor(8) && !field.SimpleWritable(), "layout.bitfield-not-whole-storage-write");
    field.BitWidth = 33;
    check(!field.ValidFor(8), "layout.bitfield-overflow-rejected");
    field.BitWidth = 3;
    auto engineField = field;
    engineField.BitOffset.reset();
    engineField.BitWidth.reset();
    check(kncore::CorroborateField(field, engineField, 8) && !kncore::CorroborateField(std::nullopt, engineField, 8),
          "symbols.storage-only-engine-metadata-cannot-substitute-for-bit-layout");
    check(kncore::CorroborateField(field, std::nullopt, 8), "symbols.matched-dia-field-does-not-require-redundant-engine-type");
    engineField.Offset = 4;
    check(!kncore::CorroborateField(field, engineField, 8), "symbols.conflicting-engine-and-dia-offset-rejected");
    engineField.Offset = 0;
    engineField.Size = 8;
    check(!kncore::CorroborateField(field, engineField, 8), "symbols.conflicting-engine-and-dia-size-rejected");
    field = {};
    field.Size = 296;
    field.Kind = kncore::FieldKind::Array;
    field.ArrayCount = 37;
    field.ElementSize = 8;
    check(field.ValidFor(352), "layout.array-count-independent-of-container-remainder");
    field.ArrayCount = UINT32_MAX;
    check(!field.ValidFor(352), "layout.array-multiplication-bounded");
    kncore::ModuleIdentity identity{L"pdb", 1, 0x8664, 2, 4096, 0x1000, true};
    const auto key = identity.Key();
    ++identity.PdbAge;
    check(identity.Key() != key, "layout.cache-key-pdb-age-sensitive");
    kncore::SessionStamp stamp{L"owner", 1, 1, 1, 1};
    kncore::EpochValue<uint64_t> dtb;
    dtb.Set(0x12345000, stamp);
    check(dtb.Get(stamp) == uint64_t(0x12345000), "context.logical-dtb-independent-of-client-lifetime");
    auto changed = stamp;
    ++changed.ContextGeneration;
    check(!dtb.Get(changed), "context.logical-dtb-invalidated-by-context-epoch");
    kncore::OwnershipIndex owners({{0x2000, 0x100, L"b", L"b-id"}, {0x1000, 0x100, L"a", L"a-id"}}, true, stamp);
    const auto owner = owners.Find(0x1004, stamp);
    check(owner.State == kncore::OwnershipState::Owned && owner.Image->Name == L"a" && owner.Rva == 4, "ownership.sorted-range-and-rva");
    check(owners.Find(0x1100, stamp).State == kncore::OwnershipState::OutsideCollectedImages &&
              owners.Find(0x1004, changed).State == kncore::OwnershipState::Unknown,
          "ownership.exclusive-end-and-stale-context");
    kncore::OwnershipIndex incomplete({{0x1000, 0x100, L"a", L"id"}}, false, stamp);
    check(incomplete.Find(0x2000, stamp).State == kncore::OwnershipState::Unknown, "ownership.missing-in-incomplete-inventory-is-unknown");
    kncore::OwnershipIndex overlap({{0x1000, 0x100, L"a", L"id"}, {0x1040, 0x80, L"b", L"id"}}, true, stamp);
    check(overlap.Find(0x1044, stamp).State == kncore::OwnershipState::Unknown, "ownership.overlapping-ranges-ambiguous");
    kncore::OwnershipIndex top({{UINT64_MAX - 0xfff, 0x1000, L"top", L"top-id"}}, true, stamp);
    const auto topOwner = top.Find(UINT64_MAX, stamp);
    check(topOwner.State == kncore::OwnershipState::Owned && topOwner.Rva == 0xfff, "review.ownership-range-ending-at-uint64-max");

    ChainFixture memory;
    memory.Links = {{0xffff800000001000ULL, 0xffff800000001010ULL}, {0xffff800000001010ULL, 0}, {0xffff800000002000ULL, 0}};
    const auto visit = [](uint64_t)
    {
        return kncore::VisitDecision::Continue;
    };
    kncore::WalkBudget complete;
    check(kncore::WalkChain(memory, 0xffff800000001000ULL, 0, 0, x64, complete, visit), "walk.actual-reader-reaches-end");
    complete.Complete();
    check(complete.Report.Collected.Complete && complete.Report.Collected.Decoded == 2, "walk.coverage-exact");
    kncore::WalkBudget limit;
    limit.MaxNodes = 2;
    kncore::WalkChain(memory, 0xffff800000001000ULL, 0, 0, x64, limit, visit);
    check(!kncore::WalkChain(memory, 0xffff800000002000ULL, 0, 0, x64, limit, visit) && limit.Report.Collected.Visited == 2,
          "walk.budget-shared-across-buckets");
    kncore::WalkBudget stopped;
    unsigned visits = 0;
    const auto stop = [&](uint64_t)
    {
        ++visits;
        return kncore::VisitDecision::Stop;
    };
    kncore::WalkChain(memory, 0xffff800000001000ULL, 0, 0, x64, stopped, stop);
    kncore::WalkChain(memory, 0xffff800000002000ULL, 0, 0, x64, stopped, stop);
    check(visits == 1 && !stopped.Report.Collected.Complete, "walk.visitor-stop-is-global");
    memory.Links[0xffff800000001010ULL] = 0xffff800000001000ULL;
    kncore::WalkBudget cycle;
    check(!kncore::WalkChain(memory, 0xffff800000001000ULL, 0, 0, x64, cycle, visit) &&
              cycle.Report.Collected.StopReason == L"CycleOrRepeatedNode",
          "walk.cycle-detected");
    kncore::WalkBudget holes;
    check(!kncore::WalkChain(memory, 0xffff800000003000ULL, 0, 0, x64, holes, visit) && holes.Report.Collected.Unreadable == 1,
          "walk.unreadable-not-empty-success");
    kncore::WalkBudget cancellation;
    cancellation.Cancelled = []()
    {
        return true;
    };
    check(!kncore::WalkChain(memory, 0xffff800000001000ULL, 0, 0, x64, cancellation, visit) &&
              cancellation.Report.State == kncore::Status::Cancelled && cancellation.Report.Collected.Read == 0,
          "walk.cancellation-before-read");

    ChainFixture pages;
    pages.Links = {{0x1000, 0x2003}, {0x2000, 0x3003}, {0x3000, 0x4003}, {0x4008, 0x9003}};
    knengine::PageWalkResult translated;
    check(knengine::WalkPageTables(pages, x64, 0x1234, 0x1000, &translated) && translated.PhysicalAddress == 0x9234 &&
              translated.LevelCount == 4 && translated.ContiguousBytes == 0xdcc,
          "paging.actual-reader-4k-translation");
    pages.Links[0x4008] |= uint64_t(1) << 63;
    check(knengine::WalkPageTables(pages, x64, 0x1234, 0x1000, &translated) && !translated.EffectiveExecutable,
          "paging.nx-inherits-from-entry");
    pages.Links[0x3000] = 0x200083;
    check(knengine::WalkPageTables(pages, x64, 0x1234, 0x1000, &translated) && translated.PhysicalAddress == 0x201234 &&
              translated.PageSize == 0x200000,
          "paging.actual-reader-large-page");
    pages.Links[0x3000] |= 0x2000;
    check(!knengine::WalkPageTables(pages, x64, 0x1234, 0x1000, &translated), "paging.reserved-large-page-alignment-rejected");
    check(!knengine::WalkPageTables(pages, unknown, 0x1234, 0x1000, &translated), "paging.unknown-mode-rejected");
    pages.Links[0x3000] = 0x4003;
    pages.Links[0x4008] = (uint64_t(1) << 40) | 3;
    auto narrowPhysical = x64;
    narrowPhysical.PhysicalAddressBits = 36;
    check(!knengine::WalkPageTables(pages, narrowPhysical, 0x1234, 0x1000, &translated), "paging.target-physical-width-enforced");
    const auto cpus = kncore::MapProcessors(2, {41, 77},
                                            [](uint32_t cpu, uint32_t *thread)
                                            {
                                                *thread = cpu == 0 ? 77 : 41;
                                                return true;
                                            });
    check(cpus.Complete && cpus.Entries[0].EngineThread == 77 && cpus.Entries[1].Processor == 1,
          "cpu.processor-number-is-not-engine-thread-index");
    const auto missing = kncore::MapProcessors(2, {41, 77},
                                               [](uint32_t cpu, uint32_t *thread)
                                               {
                                                   *thread = 41;
                                                   return cpu == 1;
                                               });
    check(!missing.Complete && missing.Entries.size() == 1 && missing.Entries[0].Processor == 1,
          "cpu.missing-first-processor-retains-actual-second-identity");
}
} // namespace knself
