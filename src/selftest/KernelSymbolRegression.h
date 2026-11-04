#pragma once

#include "CollectorRegression.h"
#include "SnapshotRpcRegression.h"
#include "../core/KernelSymbolProfile.h"
#include "../core/EtwRead.h"
#include "../cmd/Dispatcher.h"
#include "../ui/Bridge.h"

namespace knself
{
template <typename Check> void RunKernelSymbolRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xfffff8008ee00000ULL;
    const ModuleIdentity identity{L"{11D7FE79-CC24-5612-0555-03EE86BB0E3E}", 1, 0x8664, 0x90b083da, 0x1450000, base, true};
    for (const auto family :
         {KernelLayoutFamily::ObjectTypes, KernelLayoutFamily::ObjectNames, KernelLayoutFamily::VadProtection, KernelLayoutFamily::HostSilo,
          KernelLayoutFamily::Nmi, KernelLayoutFamily::Unloaded, KernelLayoutFamily::Firmware})
    {
        ByteFixture memory;
        std::map<std::wstring, uint64_t> symbols;
        for (const auto &[name, rva] : KernelProfileSymbols(family))
        {
            symbols[name] = base + rva;
        }
        for (const auto &window : KernelProfileWindows(family))
        {
            symbols[window.Symbol] = base + window.SymbolRva;
            const std::wstring bytes(window.Bytes);
            for (size_t i = 0; i < bytes.size(); i += 2)
            {
                memory.Put(base + window.SymbolRva + window.Offset + i / 2, std::stoul(bytes.substr(i, 2), nullptr, 16), 1);
            }
        }
        const auto resolve = [&](const wchar_t *name) -> std::optional<uint64_t>
        {
            const auto found = symbols.find(name);
            return found == symbols.end() ? std::nullopt : std::optional<uint64_t>(found->second);
        };
        check(std::wstring_view(VerifyKernelProfile(memory, identity, family, resolve)) == L"Verified",
              "symbols.profile-identity-addresses-and-reviewed-windows-agree");
        auto wrong = identity;
        wrong.PdbAge += 1;
        const auto reads = memory.Reads;
        check(std::wstring_view(VerifyKernelProfile(memory, wrong, family, resolve)) == L"NoMatchingKernelProfile" && memory.Reads == reads,
              "symbols.different-kernel-rejected-before-reading-private-layout");
        const auto name = KernelProfileSymbols(family).front().first;
        symbols[name] += 8;
        check(std::wstring_view(VerifyKernelProfile(memory, identity, family, resolve)) == L"KernelProfileSymbolMismatch" &&
                  memory.Reads == reads,
              "symbols.neighbor-address-never-used-as-global-storage-proof");
        symbols[name] -= 8;
        const auto &window = KernelProfileWindows(family).front();
        const auto address = base + window.SymbolRva + window.Offset;
        memory.Bytes[address] ^= 1;
        check(std::wstring_view(VerifyKernelProfile(memory, identity, family, resolve)) == L"KernelProfileBytesMismatch",
              "symbols.changed-target-code-or-protection-data-rejects-profile");
        memory.Bytes.erase(address);
        check(std::wstring_view(VerifyKernelProfile(memory, identity, family, resolve)) == L"KernelProfileBytesUnavailable",
              "symbols.missing-dump-page-does-not-activate-private-layout");
    }
    std::optional<FieldInfo> missing;
    check(ProfilePointerStorageAllowed(missing, true, 8) && !ProfilePointerStorageAllowed(missing, false, 8),
          "symbols.unloaded-profile-requires-proof-that-data-type-is-absent");
    auto storage = FixtureField(0, 8);
    storage.Kind = FieldKind::Pointer;
    check(ProfilePointerStorageAllowed(storage, false, 8) && !ProfilePointerStorageAllowed(storage, false, 4),
          "symbols.profile-pointer-storage-must-match-target-width");
    storage.Kind = FieldKind::Unsigned;
    const bool rejectsScalar = !ProfilePointerStorageAllowed(storage, true, 8);
    storage.Kind = FieldKind::Pointer;
    storage.BitOffset = 0;
    storage.BitWidth = 4;
    check(rejectsScalar && !ProfilePointerStorageAllowed(storage, true, 8),
          "symbols.profile-does-not-replace-contradictory-storage-metadata");
    check(ApplyKernelProfileField(missing, 8, 8) && missing->Source == KernelSymbolProfileId && !missing->SimpleWritable(),
          "symbols.private-profile-fields-do-not-enable-typed-writes");
    auto conflict = missing;
    conflict->Offset = 16;
    check(!ApplyKernelProfileField(conflict, 8, 8) && conflict->Offset == 16, "symbols.existing-conflicting-field-is-never-overwritten");
    conflict = missing;
    conflict->BitOffset = 0;
    conflict->BitWidth = 4;
    check(!ApplyKernelProfileField(conflict, 8, 8), "symbols.bitfield-cannot-be-reinterpreted-as-profile-pointer");
    ByteFixture port;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    auto blockField = FixtureField(16, 8);
    auto connection = FixtureField(0, 8);
    blockField.Kind = FieldKind::Pointer;
    connection.Kind = FieldKind::Pointer;
    port.Put(base + 16, base + 0x1000);
    port.Put(base + 0x1000, base + 0x2000);
    check(ReadIndirectKernelPointer(port, architecture, base, blockField, connection) == base + 0x2000,
          "symbols.pointer-member-path-dereferences-pdb-described-block");
    port.Put(base + 16, 0);
    const auto before = port.Reads;
    check(ReadIndirectKernelPointer(port, architecture, base, blockField, connection) == 0 && port.Reads == before + 1,
          "symbols.null-communication-block-does-not-read-a-null-field");
    port.Put(base + 16, 0x800000000000ULL);
    check(!ReadIndirectKernelPointer(port, architecture, base, blockField, connection) && port.Reads == before + 2,
          "symbols.noncanonical-pointer-member-is-never-dereferenced");
    port.Put(base + 16, base + 0x1000);
    port.Bytes.erase(base + 0x1007);
    check(!ReadIndirectKernelPointer(port, architecture, base, blockField, connection),
          "symbols.short-indirect-pointer-read-cannot-become-null");
    blockField.Kind = FieldKind::Unsigned;
    const auto reads = port.Reads;
    check(!ReadIndirectKernelPointer(port, architecture, base, blockField, connection) && port.Reads == reads,
          "symbols.scalar-member-is-not-an-implicit-pointer-chain");

    ByteFixture etw;
    auto siloField = FixtureField(16, 8);
    auto arrayField = FixtureField(24, 8);
    const auto countField = FixtureField(32, 4);
    siloField.Kind = FieldKind::Pointer;
    arrayField.Kind = FieldKind::Pointer;
    etw.Put(base + 16, base + 0x1000);
    etw.Put(base + 0x1018, base + 0x2000);
    etw.Put(base + 0x1020, 128, 4);
    const auto table = ReadEtwLoggerTable(etw, architecture, base, siloField, arrayField, countField);
    check(table && table->Address == base + 0x2000 && table->Count == 128 && etw.Reads == 3,
          "review.etw-table-follows-validated-pointer-fields");
    for (const uint64_t invalidSilo : {0ULL, 0x1000ULL, 0x800000000000ULL})
    {
        etw.Put(base + 16, invalidSilo);
        const auto beforeEtw = etw.Reads;
        check(!ReadEtwLoggerTable(etw, architecture, base, siloField, arrayField, countField) && etw.Reads == beforeEtw + 1,
              "review.etw-invalid-silo-never-reads-child-count");
    }
    etw.Put(base + 16, base + 0x1000);
    siloField.Kind = FieldKind::Unsigned;
    const auto beforeEtw = etw.Reads;
    check(!ReadEtwLoggerTable(etw, architecture, base, siloField, arrayField, countField) && etw.Reads == beforeEtw,
          "review.etw-scalar-storage-is-not-a-pointer");
    siloField.Kind = FieldKind::Pointer;
    etw.Put(base + 0x1020, 4097, 4);
    check(!ReadEtwLoggerTable(etw, architecture, base, siloField, arrayField, countField), "review.etw-table-count-is-bounded");
    etw.Put(base + 0x1020, 128, 4);
    etw.Put(base + 0x1018, UINT64_MAX - 7);
    check(!ReadEtwLoggerTable(etw, architecture, base, siloField, arrayField, countField), "review.etw-table-extent-overflow-rejected");

    auto clockField = FixtureField(24, 8);
    auto clockType = FixtureField(32, 4);
    etw.Put(base + 24, 3);
    etw.Put(base + 32, 1, 4);
    auto clock = ReadEtwClock(etw, architecture, base, clockField, {}, true, true);
    check(clock.Known && clock.Raw == 3 && !clock.Type && std::wstring_view(clock.Representation) == L"IntegerSelector",
          "review.etw-proven-optional-field-absence-keeps-observation");
    clock = ReadEtwClock(etw, architecture, base, clockField, {}, false, true);
    check(!clock.Known && clock.Raw == 3, "review.etw-field-resolution-failure-is-not-absence");
    clock = ReadEtwClock(etw, architecture, base, clockField, clockType, false, true);
    check(clock.Known && clock.Type == 1, "review.etw-present-optional-field-is-read");
    etw.Bytes.erase(base + 35);
    check(!ReadEtwClock(etw, architecture, base, clockField, clockType, false, true).Known,
          "review.etw-unreadable-optional-field-reduces-coverage");
    clockType.Kind = FieldKind::Pointer;
    check(!ReadEtwClock(etw, architecture, base, clockField, clockType, true, true).Known,
          "review.etw-declared-invalid-field-cannot-use-absence-proof");
    etw.Put(base + 24, 4);
    const auto rawClock = ReadEtwClock(etw, architecture, base, clockField, {}, true, false);
    check(!ReadEtwClock(etw, architecture, base, clockField, {}, true, true).Known && rawClock.Known &&
              std::wstring_view(rawClock.Representation) == L"RawInteger",
          "review.etw-selector-range-applies-only-to-verified-profile");
    clockField.Kind = FieldKind::Composite;
    check(!ReadEtwClock(etw, architecture, base, clockField, {}, true, false).Known,
          "review.etw-unknown-clock-representation-is-not-decoded");
    clockField.Kind = FieldKind::Pointer;
    clockField.FunctionPointer = true;
    etw.Put(base + 24, 0);
    check(!ReadEtwClock(etw, architecture, base, clockField, {}, true, false).Known, "review.etw-null-function-clock-is-not-decoded");
    etw.Put(base + 24, base + 0x3000);
    check(ReadEtwClock(etw, architecture, base, clockField, {}, true, false).Known &&
              !ReadEtwClock(etw, architecture, base, clockField, {}, true, true).Known,
          "review.etw-function-clock-requires-compatible-metadata");
    Result original;
    original.Collected.Complete = true;
    const auto retained = Results().Publish(L"symbol-poll-retention-regression", original, L"original observation");
    knengine::DbgSession detached;
    bool ephemeral = true;
    for (unsigned i = 0; i < 24; ++i)
    {
        const auto polled = kncmd::DispatchCommand(detached, i % 2 == 0 ? L"jobs" : L"job absent");
        ephemeral = ephemeral && polled.ResultId.empty();
    }
    check(retained && Results().Find(retained->Id) && ephemeral, "symbols.cli-job-polling-cannot-evict-paged-result");
    auto parameters = knjson::Value::MakeObject();
    parameters.Set(L"command", knjson::Value(L"jobs"));
    bool uiEphemeral = true;
    for (unsigned i = 0; i < 24; ++i)
    {
        const auto reply = knbridge::HandleRequest(FixtureRpc(L"execute", 900 + i, parameters), &detached);
        uiEphemeral = uiEphemeral && reply.Get(L"ok").AsBool(false) && reply.Get(L"result").Get(L"ok").AsBool(false) &&
                      reply.Get(L"result").Get(L"ephemeral").AsBool(false) && reply.Get(L"result").Get(L"resultId").IsNull();
    }
    check(retained && Results().Find(retained->Id) && uiEphemeral, "symbols.ui-job-inspection-does-not-republish-history");
}
} // namespace knself
