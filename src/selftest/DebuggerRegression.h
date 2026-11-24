#pragma once
#include "../core/Navigation.h"
#include "../core/ResultAction.h"
#include "../core/ProcessAction.h"
#include "../core/MemoryView.h"
#include "../core/DisassemblyView.h"
#include "../core/BreakpointView.h"
#include "../core/ModelProjection.h"
#include "../core/DebugAction.h"
#include "../core/EventContext.h"
#include "CollectorRegression.h"
#include "../cmd/Dispatcher.h"
#include "SnapshotRpcRegression.h"

namespace knself
{
template <typename Check> void RunDebuggerRegression(Check check)
{
    using namespace kncore;
    {
        ByteFixture memory;
        const uint64_t thread = 0xffff800000001000;
        const uint64_t process = 0xffff800000002000;
        const TargetArchitecture architecture{0x8664, 8, 48, {}};
        EventThreadLayout fields;
        fields.Tcb = FixtureField(0x10, 0x80);
        fields.Tcb->Kind = FieldKind::Composite;
        fields.Tid = FixtureField(0x90, 8);
        fields.OwnerPid = FixtureField(0x98, 8);
        fields.Process = FixtureField(0x30, 8);
        fields.Process->Kind = FieldKind::Pointer;
        fields.Pcb = FixtureField(0x20, 0x40);
        fields.Pcb->Kind = FieldKind::Composite;
        fields.Owner.Pid = FixtureField(0x70, 8);
        fields.Owner.Image = FixtureField(0x80, 16);
        memory.Put(thread + 0x90, 13144);
        memory.Put(thread + 0x98, 824);
        memory.Put(thread + 0x30, process + 0x20);
        memory.Put(process + 0x70, 824);
        memory.Text(process + 0x80, "fixture.exe", 16);
        auto observed = ReadEventThread(memory, thread + 0x10, architecture, fields);
        check(observed.Get(L"pid").AsString(L"") == L"824" && observed.Get(L"tid").AsString(L"") == L"13144" &&
                  observed.Get(L"image").AsString(L"") == L"fixture.exe" &&
                  observed.Get(L"ethread").AsString(L"") == Hex(thread) && observed.Get(L"eprocess").AsString(L"") == Hex(process) &&
                  observed.Get(L"reason").AsString(L"missing").empty(), "event-context.system-ids-and-nonzero-embedded-offsets");
        memory.Put(process + 0x70, 999);
        observed = ReadEventThread(memory, thread + 0x10, architecture, fields);
        check(observed.Get(L"pid").AsString(L"") == L"824" && observed.Get(L"image").IsNull() &&
                  observed.Get(L"eprocess").IsNull(), "event-context.inconsistent-owner-does-not-mix-process-identity");
        memory.Put(process + 0x70, 824);
        memory.Bytes.erase(thread + 0x90);
        observed = ReadEventThread(memory, thread + 0x10, architecture, fields);
        check(observed.Get(L"tid").IsNull() && observed.Get(L"pid").AsString(L"") == L"824" &&
                  !observed.Get(L"reason").AsString(L"").empty(), "event-context.unreadable-tid-is-not-zero-or-engine-id");
        memory.Put(thread + 0x90, UINT64_MAX);
        check(ReadEventThread(memory, thread + 0x10, architecture, fields).Get(L"tid").IsNull(),
              "event-context.invalid-system-id-is-unavailable");
        memory.Put(thread + 0x90, 0);
        memory.Put(thread + 0x98, 0);
        memory.Put(process + 0x70, 0);
        observed = ReadEventThread(memory, thread + 0x10, architecture, fields);
        check(observed.Get(L"tid").AsString(L"") == L"0" && observed.Get(L"pid").AsString(L"") == L"0",
              "event-context.idle-zero-ids-remain-known");
        auto missing = fields;
        missing.Tcb.reset();
        const auto reads = memory.Reads;
        check(ReadEventThread(memory, thread + 0x10, architecture, missing).Get(L"ethread").IsNull() && memory.Reads == reads,
              "event-context.missing-layout-does-not-guess-offsets");
        check(ReadEventThread(memory, 0x1000, architecture, fields).Get(L"ethread").IsNull() && memory.Reads == reads,
              "event-context.invalid-kernel-pointer-is-not-read");
    }
    {
        std::vector<unsigned char> bytes(17, 0xff);
        std::vector<unsigned char> valid(17, 1);
        bytes[0] = 0;
        valid[1] = 0;
        const auto rows = MemoryByteRows(0xffffffffffffffeFULL, AddressSpace::Virtual, bytes, valid);
        check(rows.Items().size() == 2 && rows.Items()[0].Get(L"address").AsString(L"") == L"0xffffffffffffffef" &&
                  rows.Items()[1].Get(L"address").AsString(L"") == L"0xffffffffffffffff" &&
                  rows.Items()[1].Get(L"bytes").Items().size() == 1, "memory-view.exact-high-address-and-last-byte");
        check(rows.Items()[0].Get(L"bytes").Items()[0].AsDouble(-1) == 0 &&
                  rows.Items()[0].Get(L"bytes").Items()[1].IsNull() &&
                  rows.Items()[0].Get(L"bytes").Items()[2].AsDouble(-1) == 255, "memory-view.unreadable-is-distinct-from-zero");
        check(MemoryByteRows(UINT64_MAX, AddressSpace::Virtual, bytes, valid).Items().empty(), "memory-view.overflow-rejected");
        valid.pop_back();
        check(MemoryByteRows(0, AddressSpace::Virtual, bytes, valid).Items().empty(), "memory-view.mismatched-validity-rejected");
        bytes.resize(16);
        std::fill(valid.begin(), valid.end(), static_cast<unsigned char>(0));
        const auto missing = MemoryByteRows(0, AddressSpace::Physical, bytes, valid);
        check(missing.Items()[0].Get(L"addressSpace").AsString(L"") == L"physical" &&
                  std::all_of(missing.Items()[0].Get(L"bytes").Items().begin(), missing.Items()[0].Get(L"bytes").Items().end(),
                      [](const auto &value)
                      {
                          return value.IsNull();
                      }), "memory-view.physical-unreadable-range-keeps-every-byte");
    }
    SessionStamp stamp{L"navigation-fixture", 1, 2, 3, 4};
    {
        auto parameters = knjson::Value::MakeObject();
        parameters.Set(L"operation", knjson::Value(L"step-over"));
        parameters.Set(L"expectedStamp", stamp.ToJson());
        std::wstring reason;
        check(RpcNeedsWorker(L"debuggerAction") && RpcShape(FixtureRpc(L"debuggerAction", 1, parameters), reason),
              "execution-control.rpc-binds-context-on-owned-worker");
        check(ExecutionOperation(L"go") && ExecutionOperation(L"step-into") && ExecutionOperation(L"step-over") &&
                  !ExecutionOperation(L"go; .shell cmd") && !ExecutionOperation(L"breakpoint-remove") && !ExecutionOperation(L""),
              "execution-control.only-fixed-execution-operations-accepted");
        parameters.Set(L"command", knjson::Value(L"g"));
        check(!RpcShape(FixtureRpc(L"debuggerAction", 2, parameters), reason), "execution-control.cannot-override-command");
        parameters = knjson::Value::MakeObject();
        parameters.Set(L"operation", knjson::Value(L"step-into"));
        parameters.Set(L"expectedStamp", knjson::Value(L"stale"));
        check(!RpcShape(FixtureRpc(L"debuggerAction", 3, parameters), reason), "execution-control.context-cannot-be-coerced");
        parameters = knjson::Value::MakeObject();
        parameters.Set(L"expectedStamp", stamp.ToJson());
        check(!RpcNeedsWorker(L"breakExecution") && RpcShape(FixtureRpc(L"breakExecution", 4, parameters), reason),
              "execution-control.break-bypasses-worker-and-requires-context");
        check(!knbridge::HandleRequest(FixtureRpc(L"breakExecution", 4, parameters)).Get(L"ok").AsBool(true),
              "execution-control.break-rejects-unrelated-target");
        const auto current = knengine::Epochs().Stamp();
        parameters.Set(L"expectedStamp", current.ToJson());
        auto request = FixtureRpc(L"breakExecution", 5, parameters);
        request.Set(L"sessionId", knjson::Value(current.SessionId));
        request.Set(L"expectedTargetGeneration", knjson::Value(std::to_wstring(current.TargetGeneration)));
        check(!knbridge::HandleRequest(request).Get(L"ok").AsBool(true), "execution-control.break-refuses-without-live-capability");
        parameters.Set(L"command", knjson::Value(L"g"));
        check(!RpcShape(FixtureRpc(L"breakExecution", 6, parameters), reason), "execution-control.break-rejects-command-injection");
        parameters = knjson::Value::MakeObject();
        parameters.Set(L"expectedStamp", knjson::Value(L"stale"));
        check(!RpcShape(FixtureRpc(L"breakExecution", 7, parameters), reason), "execution-control.break-requires-typed-context");
    }
    {
        auto parameters = knjson::Value::MakeObject();
        parameters.Set(L"expression", knjson::Value(L"@rip + 10"));
        parameters.Set(L"space", knjson::Value(L"virtual"));
        parameters.Set(L"length", knjson::Value(L"256"));
        parameters.Set(L"source", knjson::Value::MakeObject());
        parameters.Set(L"expectedStamp", stamp.ToJson());
        check(MemoryViewCommand(parameters) == L"db \"@rip + 10\" L0x0000000000000100", "memory-view.expression-is-one-command-operand");
        std::wstring reason;
        check(RpcNeedsWorker(L"memoryRead") && RpcShape(FixtureRpc(L"memoryRead", 1, parameters), reason),
              "memory-view.rpc-binds-full-context-on-owned-worker");
        bool refused = true;
        for (const auto *expression : {L"@rip;g", L"\"@rip\"", L"@rip\ng", L"@rip\\", L"", L"{g}"})
        {
            parameters.Set(L"expression", knjson::Value(expression));
            refused = refused && !MemoryViewCommand(parameters);
        }
        check(refused, "memory-view.command-separators-and-quoting-cannot-escape-address");
        parameters.Set(L"expression", knjson::Value(L"0"));
        parameters.Set(L"space", knjson::Value(L"physical"));
        check(MemoryViewCommand(parameters) == L"!db \"0\" L0x0000000000000100", "memory-view.physical-scope-is-explicit");
        parameters.Set(L"length", knjson::Value(L"65536"));
        check(!MemoryViewCommand(parameters), "memory-view.rpc-read-size-is-bounded");
        parameters.Set(L"length", knjson::Value(L"64"));
        parameters.Set(L"space", knjson::Value(L"other"));
        check(!MemoryViewCommand(parameters), "memory-view.unknown-address-space-refused");
    }
    {
        auto parameters = knjson::Value::MakeObject();
        parameters.Set(L"expression", knjson::Value(L"@$ip + 10"));
        parameters.Set(L"count", knjson::Value(L"32"));
        parameters.Set(L"source", knjson::Value::MakeObject());
        parameters.Set(L"expectedStamp", stamp.ToJson());
        check(DisassemblyViewCommand(parameters) == L"u \"@$ip + 10\" L0x0000000000000020",
              "disassembly-view.expression-is-one-command-operand");
        std::wstring reason;
        check(RpcNeedsWorker(L"disassemblyRead") && RpcShape(FixtureRpc(L"disassemblyRead", 1, parameters), reason),
              "disassembly-view.rpc-binds-full-context-on-owned-worker");
        bool refused = true;
        for (const auto *expression : {L"@$ip;g", L"\"@$ip\"", L"@$ip\ng", L"@$ip\\", L"", L"   ", L"{g}"})
        {
            parameters.Set(L"expression", knjson::Value(expression));
            refused = refused && !DisassemblyViewCommand(parameters);
        }
        check(refused, "disassembly-view.address-cannot-inject-another-command");
        parameters.Set(L"expression", knjson::Value(L"@$ip"));
        refused = true;
        for (const auto *count : {L"0", L"8", L"65", L"32;g", L"18446744073709551616"})
        {
            parameters.Set(L"count", knjson::Value(count));
            refused = refused && !DisassemblyViewCommand(parameters);
        }
        check(refused, "disassembly-view.count-is-bounded-and-cannot-inject");
        parameters.Set(L"count", knjson::Value(32.0));
        check(!RpcShape(FixtureRpc(L"disassemblyRead", 2, parameters), reason), "disassembly-view.count-retains-wire-type");
        check(InstructionBody(L"fffff803`9c344700  CC  int3\r\n", 0xfffff8039c344700, L"cc") == L"int3",
              "disassembly-view.instruction-body-removes-only-verified-prefix");
        check(InstructionBody(L"00000000`00001000 488bc4 mov rax,rsp\n", 0x1000, L"488bc4") == L"mov rax,rsp",
              "disassembly-view.multibyte-instruction-body");
        check(InstructionBody(L"0033:00007ffb`b42c2af0 4c8bd1 mov r10,rcx\r\n", 0x00007ffbb42c2af0, L"4c8bd1") == L"mov r10,rcx" &&
                  InstructionBody(L"0023:00001000 CC int3\n", 0x1000, L"cc") == L"int3" &&
                  InstructionBody(L"  aBcD:1000 cc int3  ", 0x1000, L"cc") == L"int3" &&
                  InstructionBody(L"0:1000 cc int3", 0x1000, L"cc") == L"int3",
              "disassembly-view.segmented-user-instruction-body");
        check(InstructionBody(L"0033:00007ffb`b165749b 48FF15F6651900 call qword ptr [ds:00007ffb`b17eda98]\n",
                              0x00007ffbb165749b, L"48ff15f6651900") == L"call qword ptr [ds:00007ffb`b17eda98]",
              "disassembly-view.segment-selector-does-not-strip-operand-segments");
        bool preserveSegmented = true;
        for (const auto *line : {L"10033:1000 cc int3", L"003x:1000 cc int3", L":1000 cc int3", L"0033::1000 cc int3",
                                L"0033:1001 cc int3", L"0033:1000 90 nop", L"0x33:1000 cc int3",
                                L"0n33:1000 cc int3", L"00`33:1000 cc int3", L"0033: cc int3"})
        {
            preserveSegmented = preserveSegmented && InstructionBody(line, 0x1000, L"cc") == line;
        }
        check(preserveSegmented, "disassembly-view.segmented-prefix-still-requires-selector-address-and-byte-match");
        const std::wstring unexpected = L"symbol!label:\nfffff803`9c344700 cc int3\n";
        check(InstructionBody(unexpected, 0xfffff8039c344700, L"cc") == unexpected &&
                  InstructionBody(L"1001 cc int3", 0x1000, L"cc") == L"1001 cc int3" &&
                  InstructionBody(L"1000 90 nop", 0x1000, L"cc") == L"1000 90 nop",
              "disassembly-view.unrecognized-text-is-preserved");
    }
    NavigationStore history;
    NavigationPoint first{stamp, L"virtual", 0x1000, {}, knjson::Value::MakeObject(), L""};
    check(!history.Move(-1) && !history.Bookmark(L"empty"), "T-NAV.empty-history-is-unavailable");
    check(history.Push(first) && !history.Move(1), "T-NAV.initial-point-boundaries");
    auto second = first;
    second.Address = 0x2000;
    second.Space = L"physical";
    history.Push(second);
    check(history.Move(-1)->Space == L"virtual" && history.Move(1)->Space == L"physical", "T-NAV.address-space-not-lost");
    history.Move(-1);
    second.Address = 0x3000;
    history.Push(second);
    check(!history.Move(1) && history.Current()->Address == 0x3000, "T-NAV.branch-discards-forward-history");
    history.Bookmark(L"observed before reconnect");
    auto changed = stamp;
    ++changed.TargetGeneration;
    check(history.List(changed, true).Items()[0].Get(L"historical").AsBool(false), "T-NAV.bookmark-remains-historical");
    check(!history.Bookmark(std::wstring(1025, L'x')), "T-NAV.note-budget");
    for (unsigned i = 0; i < 300; ++i)
    {
        history.Push(first);
    }
    check(history.List(stamp, false).Items().size() == 256, "T-NAV.history-budget");

    DebugActions plans;
    DebugAction plan{L"a", L"secret", L"go", 0, stamp, L"", std::chrono::steady_clock::now() + std::chrono::seconds(60)};
    plans.Add(plan);
    check(!plans.Consume(plan.Id, plan.Token, changed), "T-ACTION.stale-stamp-rejected");
    check(!plans.Consume(plan.Id, plan.Token, stamp), "T-ACTION.stale-attempt-consumed");
    plans.Add(plan);
    check(plans.Consume(plan.Id, plan.Token, stamp).has_value(), "T-ACTION.approval-needs-no-global-switch");
    plans.Add(plan);
    check(!plans.Consume(plan.Id, L"wrong", stamp), "T-ACTION.wrong-token-rejected");
    plans.Add(plan);
    check(!plans.Consume(plan.Id, plan.Token, stamp, plan.Expires), "T-ACTION.expiry-boundary-rejected");
    plans.Add(plan);
    check(plans.Consume(plan.Id, plan.Token, stamp).has_value() && !plans.Consume(plan.Id, plan.Token, stamp),
          "T-ACTION.one-use-approval");
    check(RevalidateDebugAction(plan, stamp, false, plan.Expires - std::chrono::seconds(1)) == Status::Success &&
              RevalidateDebugAction(plan, stamp, false, plan.Expires) == Status::StaleContext &&
              RevalidateDebugAction(plan, changed, false) == Status::StaleContext &&
              RevalidateDebugAction(plan, stamp, true) == Status::Cancelled,
          "review.action-rechecks-expiry-context-and-cancellation-before-effect");

    Result value;
    value.CommandId = L"fixture";
    value.Stamp = stamp;
    auto row = knjson::Value::MakeObject();
    row.Set(L"unknown", knjson::Value());
    row.Set(L"address", knjson::Value(L"0xffff800012345678"));
    for (unsigned i = 0; i < 257; ++i)
    {
        value.Rows.Push(row);
    }
    StoredResult stored{L"projection", value, L"console", 0};
    auto bound = stored;
    bound.Data.Stamp.Context = {0, 0, 0, 0x1000, 0x2000, 0x8664, 0x3000, 0x4000, 0x5000, 0};
    auto boundRow = row;
    boundRow.Set(L"addressSpace", knjson::Value(L"virtual"));
    bound.Data.Rows = knjson::Value::MakeArray();
    bound.Data.Rows.Push(boundRow);
    auto navigation = knjson::Value::MakeObject();
    navigation.Set(L"resultId", knjson::Value(bound.Id));
    navigation.Set(L"collection", knjson::Value(L"rows"));
    navigation.Set(L"index", knjson::Value(L"0"));
    navigation.Set(L"action", knjson::Value(L"navigate"));
    navigation.Set(L"expectedStamp", bound.Data.Stamp.ToJson());
    check(BoundResultCommand(bound, navigation, bound.Data.Stamp) == L"navigate va 0xffff800012345678",
          "rereview.navigation-resolves-immutable-source-address");
    {
        auto source = bound;
        auto bytes = knjson::Value::MakeArray();
        for (unsigned i = 0; i < 16; ++i)
        {
            bytes.Push(knjson::Value(static_cast<double>(i)));
        }
        auto memory = boundRow;
        memory.Set(L"kind", knjson::Value(L"MemoryBytes"));
        memory.Set(L"bytes", bytes);
        source.Data.Rows = knjson::Value::MakeArray();
        source.Data.Rows.Push(memory);
        auto binding = navigation;
        binding.Set(L"byteOffset", knjson::Value(L"8"));
        check(BoundResultCommand(source, binding, source.Data.Stamp) == L"navigate va 0xffff800012345680",
              "workspace.memory-eight-byte-row-keeps-source-binding");
        auto dump = knjson::Value::MakeObject();
        source.Data.CommandId = L"db";
        dump.Set(L"source", binding);
        dump.Set(L"path", knjson::Value(L"C:\\dump files\\a;b.bin"));
        dump.Set(L"length", knjson::Value(L"56"));
        dump.Set(L"operation", knjson::Value(L"dump-raw"));
        std::wstring dumpReason;
        check(RpcNeedsWorker(L"memoryDump") && RpcShape(FixtureRpc(L"memoryDump", 1, dump), dumpReason) &&
                  MemoryDumpCommand(dump, source, source.Data.Stamp, true) == L"dump-raw 0xffff800012345680 0x0000000000000038 \"C:\\dump files\\a;b.bin\"",
              "memory-dump.raw-resolves-stored-byte-and-quotes-file");
        auto userDump = source;
        userDump.Data.Stamp.Context.ImplicitProcess.reset();
        userDump.Data.Stamp.Context.ImplicitThread.reset();
        userDump.Data.Stamp.Context.ScopeFrame.reset();
        auto userBinding = binding;
        userBinding.Set(L"expectedStamp", userDump.Data.Stamp.ToJson());
        auto userParams = dump;
        userParams.Set(L"source", userBinding);
        check(MemoryDumpCommand(userParams, userDump, userDump.Data.Stamp, false).has_value() &&
                  !MemoryDumpCommand(userParams, userDump, userDump.Data.Stamp, true) &&
                  !BoundResultAddress(userDump, userBinding, userDump.Data.Stamp),
              "memory-dump.user-process-does-not-require-kernel-objects-or-frame");
        dump.Set(L"length", knjson::Value(L"67108865"));
        check(!MemoryDumpCommand(dump, source, source.Data.Stamp, true), "memory-dump.rejects-oversized-range");
        dump.Set(L"operation", knjson::Value(L"dump-pe"));
        dump.Set(L"length", knjson::Value(L""));
        check(MemoryDumpCommand(dump, source, source.Data.Stamp, true) == L"dump-pe 0xffff800012345680 \"C:\\dump files\\a;b.bin\"" &&
                  !MemoryDumpCommand(dump, source, changed, true), "memory-dump.pe-preserves-interior-address-and-rejects-stale-stamp");
        auto physical = source;
        physical.Data.CommandId = L"!db";
        auto physicalRow = memory;
        physicalRow.Set(L"addressSpace", knjson::Value(L"physical"));
        physical.Data.Rows = knjson::Value::MakeArray();
        physical.Data.Rows.Push(physicalRow);
        check(!MemoryDumpCommand(dump, physical, physical.Data.Stamp, true), "memory-dump.no-physical-pe");
        dump.Set(L"length", knjson::Value(L"1"));
        dump.Set(L"operation", knjson::Value(L"dump-raw"));
        check(MemoryDumpCommand(dump, physical, physical.Data.Stamp, true) == L"dump-raw 0xffff800012345680 0x0000000000000001 \"C:\\dump files\\a;b.bin\" /phys",
              "memory-dump.raw-keeps-physical-space");
        dump.Set(L"path", knjson::Value(L"x\";g"));
        check(!MemoryDumpCommand(dump, source, source.Data.Stamp, true), "memory-dump.rejects-embedded-quote");
        dump.Set(L"path", knjson::Value(L"C:/captures/"));
        check(!MemoryDumpCommand(dump, source, source.Data.Stamp, true), "memory-dump.rejects-directory-path");
        binding.Set(L"byteOffset", knjson::Value(L"16"));
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "workspace.memory-offset-cannot-leave-retained-row");
        binding.Set(L"byteOffset", knjson::Value(8.0));
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "workspace.memory-offset-retains-wire-type");
        binding.Set(L"byteOffset", knjson::Value(L"8"));
        check(!BoundResultAddress(bound, binding, bound.Data.Stamp), "workspace.memory-offset-rejects-other-record-kinds");
        memory.Set(L"address", knjson::Value(L"0xffffffffffffffff"));
        source.Data.Rows = knjson::Value::MakeArray();
        source.Data.Rows.Push(memory);
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "workspace.memory-offset-rejects-address-overflow");
    }
    {
        auto source = bound;
        auto entry = knjson::Value::MakeObject();
        entry.Set(L"kind", knjson::Value(L"PageTranslation"));
        entry.Set(L"va", knjson::Value(L"0xffff800011110000"));
        entry.Set(L"pa", knjson::Value(L"0x0000000000000000"));
        entry.Set(L"flags", knjson::Value(L"0xffff800033330000"));
        auto process = knjson::Value::MakeObject();
        process.Set(L"eprocess", knjson::Value(L"0xffff800022220000"));
        entry.Set(L"process", process);
        const auto setEntry = [&](const knjson::Value &value)
        {
            source.Data.Rows = knjson::Value::MakeArray();
            source.Data.Rows.Push(value);
        };
        setEntry(entry);
        check(ResultAddressFields(entry).Items().size() == 3, "address-menu.projects-addresses-without-hex-flags");
        auto binding = knjson::Value::MakeObject();
        binding.Set(L"resultId", knjson::Value(source.Id));
        binding.Set(L"collection", knjson::Value(L"rows"));
        binding.Set(L"index", knjson::Value(L"0"));
        binding.Set(L"expectedStamp", source.Data.Stamp.ToJson());
        const auto path = [&](std::initializer_list<const wchar_t *> parts)
        {
            auto result = knjson::Value::MakeArray();
            for (const auto *part : parts)
            {
                result.Push(knjson::Value(part));
            }
            return result;
        };
        binding.Set(L"path", path({L"va"}));
        auto address = BoundResultAddress(source, binding, source.Data.Stamp);
        check(address && address->Address == 0xffff800011110000 && address->Space == L"virtual",
              "address-menu.virtual-field-resolves-retained-value");
        binding.Set(L"path", path({L"process", L"eprocess"}));
        address = BoundResultAddress(source, binding, source.Data.Stamp);
        check(address && address->Address == 0xffff800022220000, "address-menu.nested-field-resolves-without-expression-evaluation");
        binding.Set(L"path", path({L"flags"}));
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.non-address-hex-is-not-navigable");
        binding.Set(L"path", path({L"pa"}));
        binding.Set(L"action", knjson::Value(L"memory"));
        auto memory = knjson::Value::MakeObject();
        memory.Set(L"source", binding);
        memory.Set(L"expression", knjson::Value(L"nt!Other"));
        memory.Set(L"space", knjson::Value(L"physical"));
        memory.Set(L"length", knjson::Value(L"64"));
        check(MemoryViewCommand(memory, &source, &source.Data.Stamp) == L"!db \"0x0000000000000000\" L0x0000000000000040",
              "address-menu.physical-zero-remains-physical");
        binding.Set(L"action", knjson::Value(L"disassemble"));
        auto code = knjson::Value::MakeObject();
        code.Set(L"source", binding);
        code.Set(L"expression", knjson::Value(L"nt!Other"));
        code.Set(L"count", knjson::Value(L"16"));
        check(!DisassemblyViewCommand(code, &source, &source.Data.Stamp), "address-menu.physical-field-cannot-be-decoded-as-virtual");
        binding.Set(L"path", path({L"va"}));
        binding.Set(L"field", knjson::Value(L"address"));
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.ambiguous-field-and-path-refused");
        binding = navigation;
        binding.Set(L"path", path({L"va"}));
        auto user = entry;
        user.Set(L"va", knjson::Value(L"0x0000000012340000"));
        setEntry(user);
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.user-address-in-other-process-refused");
        process.Set(L"eprocess", knjson::Value(L"0x0000000000001000"));
        user.Set(L"process", process);
        setEntry(user);
        check(BoundResultAddress(source, binding, source.Data.Stamp).has_value(), "address-menu.user-address-in-attached-process-accepted");
        source.Data.Stamp.Context.EffectiveArchitecture = 0x14c;
        binding.Set(L"expectedStamp", source.Data.Stamp.ToJson());
        process.Set(L"eprocess", knjson::Value(L"0x0000000000002000"));
        user.Set(L"process", process);
        user.Set(L"va", knjson::Value(L"0xa0000000"));
        setEntry(user);
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.x86-high-user-range-requires-owning-process");
        source.Data.Stamp.Context.EffectiveArchitecture = 0x8664;
        binding.Set(L"expectedStamp", source.Data.Stamp.ToJson());
        auto snapshot = entry;
        snapshot.Set(L"kind", knjson::Value(L"SnapshotDifference"));
        setEntry(snapshot);
        check(ResultAddressFields(snapshot).Items().empty() && !BoundResultAddress(source, binding, source.Data.Stamp),
              "address-menu.snapshot-differences-do-not-borrow-current-context");
        entry.Set(L"historical", knjson::Value(true));
        setEntry(entry);
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.historical-fields-refused");
        binding.Set(L"path", knjson::Value());
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.explicit-null-path-is-not-default-address");
        auto physical = knjson::Value::MakeObject();
        physical.Set(L"addressSpace", knjson::Value(L"physical"));
        auto range = knjson::Value::MakeObject();
        range.Set(L"start", knjson::Value(L"0x1000"));
        range.Set(L"va", knjson::Value(L"0xffff800000002000"));
        physical.Set(L"range", range);
        const auto descriptors = ResultAddressFields(physical);
        check(descriptors.Items().size() == 2 && descriptors.Items()[0].Get(L"space").AsString(L"") == L"physical" &&
                  descriptors.Items()[1].Get(L"space").AsString(L"") == L"virtual",
              "address-menu.nested-fields-inherit-space-and-explicit-va-stays-virtual");
        physical.Set(L"addressSpace", knjson::Value(L"file"));
        check(ResultAddressFields(physical).Items().empty(), "address-menu.file-address-space-does-not-read-target-memory");
        auto registerValue = knjson::Value::MakeObject();
        registerValue.Set(L"kind", knjson::Value(L"Register"));
        registerValue.Set(L"name", knjson::Value(L"rip"));
        registerValue.Set(L"value", knjson::Value(L"0xffff800000003000"));
        check(ResultAddressFields(registerValue).Items().size() == 1, "address-menu.instruction-register-is-an-address");
        registerValue.Set(L"name", knjson::Value(L"efl"));
        check(ResultAddressFields(registerValue).Items().empty(), "address-menu.flags-register-is-not-an-address");
        auto numericSlot = knjson::Value::MakeObject();
        numericSlot.Set(L"kind", knjson::Value(L"IoStackLocation"));
        numericSlot.Set(L"slot", knjson::Value(L"1"));
        check(ResultAddressFields(numericSlot).Items().empty(), "address-menu.decimal-stack-slot-is-not-a-pointer");

        auto imported = knjson::Value::MakeObject();
        imported.Set(L"kind", knjson::Value(L"DumpModule"));
        imported.Set(L"base", knjson::Value(L"0x00007ffb10000000"));
        imported.Set(L"source", knjson::Value(L"DumpFileModuleList"));
        source.Data.Source = L"HostDumpMetadata";
        source.Data.Consistency = L"immutable-file";
        setEntry(imported);
        binding = navigation;
        binding.Set(L"path", path({L"base"}));
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.imported-dump-base-cannot-borrow-attached-target");
        bool fileSourcesRefused = true;
        for (const auto *provenance : {L"host-file:PE", L"host-file:SARIF", L"host-file:ETL", L"HostFiles:Sha256Catalog", L"SnapshotArtifacts"})
        {
            source.Data.Source = provenance;
            source.Data.Consistency = L"unknown";
            fileSourcesRefused = fileSourcesRefused && ResultAddressFields(imported, &source.Data).Items().empty() &&
                !BoundResultAddress(source, binding, source.Data.Stamp);
        }
        check(fileSourcesRefused, "address-menu.file-and-snapshot-provenance-cannot-borrow-attached-target");

        auto ownedAddress = knjson::Value::MakeObject();
        ownedAddress.Set(L"kind", knjson::Value(L"Address"));
        ownedAddress.Set(L"address", knjson::Value(L"0x0000000012340000"));
        ownedAddress.Set(L"addressSpace", knjson::Value(L"virtual"));
        ownedAddress.Set(L"process", process);
        source.Data.Source = L"target";
        source.Data.Consistency = L"StoppedTargetBestEffort";
        setEntry(ownedAddress);
        binding = navigation;
        check(!BoundResultAddress(source, binding, source.Data.Stamp), "address-menu.legacy-address-binding-cannot-bypass-owning-process");
        process.Set(L"eprocess", knjson::Value(Hex(source.Data.Stamp.Context.ImplicitProcess.value_or(0))));
        ownedAddress.Set(L"process", process);
        setEntry(ownedAddress);
        check(BoundResultAddress(source, binding, source.Data.Stamp).has_value(), "address-menu.legacy-address-binding-retains-matching-process-navigation");
    }
    {
        auto callbacks = bound;
        callbacks.Data.CommandId = L"!callbacks";
        auto callback = knjson::Value::MakeObject();
        callback.Set(L"kind", knjson::Value(L"ObjectCallbackRegistration"));
        callback.Set(L"preRoutine", knjson::Value(L"0xffff800011112222"));
        callback.Set(L"postRoutine", knjson::Value(L"0xffff800033334444"));
        callbacks.Data.Rows = knjson::Value::MakeArray();
        callbacks.Data.Rows.Push(callback);
        auto binding = navigation;
        binding.Set(L"action", knjson::Value(L"memory"));
        auto memory = knjson::Value::MakeObject();
        memory.Set(L"expression", knjson::Value(L"0xdead"));
        memory.Set(L"space", knjson::Value(L"virtual"));
        memory.Set(L"length", knjson::Value(L"64"));
        auto code = knjson::Value::MakeObject();
        code.Set(L"expression", knjson::Value(L"0xdead"));
        code.Set(L"count", knjson::Value(L"16"));
        for (const auto *field : {L"preRoutine", L"postRoutine"})
        {
            binding.Set(L"field", knjson::Value(field));
            memory.Set(L"source", binding);
            const auto address = callback.Get(field).AsString(L"");
            check(MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp) == L"db \"" + address + L"\" L0x0000000000000040",
                  "callback-navigation.memory-uses-selected-immutable-field");
            auto disassembly = binding;
            disassembly.Set(L"action", knjson::Value(L"disassemble"));
            code.Set(L"source", disassembly);
            check(DisassemblyViewCommand(code, &callbacks, &callbacks.Data.Stamp) == L"u \"" + address + L"\" L0x0000000000000010",
                  "callback-navigation.code-uses-selected-immutable-field");
        }
        auto stale = callbacks.Data.Stamp;
        ++stale.ContextGeneration;
        check(!MemoryViewCommand(memory, &callbacks, &stale) && !MemoryViewCommand(memory) &&
                  !DisassemblyViewCommand(code, &callbacks, &stale), "callback-navigation.stale-and-expired-sources-refused");
        memory.Set(L"space", knjson::Value(L"physical"));
        check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp), "callback-navigation.virtual-callback-cannot-become-physical");
        memory.Set(L"space", knjson::Value(L"virtual"));
        auto physicalCallback = callback;
        physicalCallback.Set(L"addressSpace", knjson::Value(L"physical"));
        callbacks.Data.Rows = knjson::Value::MakeArray();
        callbacks.Data.Rows.Push(physicalCallback);
        auto callbackPath = knjson::Value::MakeArray();
        callbackPath.Push(knjson::Value(L"preRoutine"));
        auto pathBinding = navigation;
        pathBinding.Set(L"path", callbackPath);
        check(!BoundResultAddress(callbacks, pathBinding, callbacks.Data.Stamp), "address-menu.path-cannot-reinterpret-callback-as-physical");
        callbacks.Data.Rows = knjson::Value::MakeArray();
        callbacks.Data.Rows.Push(callback);
        bool refused = true;
        for (const auto *field : {L"slot", L"post.routine", L"postRoutine;g", L""})
        {
            binding.Set(L"field", knjson::Value(field));
            memory.Set(L"source", binding);
            refused = refused && !MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp);
        }
        check(refused, "callback-navigation.only-schema-defined-callback-fields-accepted");
        binding.Set(L"field", knjson::Value(1.0));
        memory.Set(L"source", binding);
        check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp), "callback-navigation.field-retains-wire-type");
        binding.Set(L"field", knjson::Value(L"postRoutine"));
        memory.Set(L"source", binding);
        const auto setCallback = [&](const knjson::Value &entry)
        {
            callbacks.Data.Rows = knjson::Value::MakeArray();
            callbacks.Data.Rows.Push(entry);
        };
        for (const auto &address : {knjson::Value(L"0x0000000000000000"), knjson::Value(), knjson::Value(L"0x10000000000000000"),
                                    knjson::Value(L"0x1000;g")})
        {
            auto invalid = callback;
            invalid.Set(L"postRoutine", address);
            setCallback(invalid);
            check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp), "callback-navigation.null-unknown-overflow-and-injection-refused");
        }
        auto historical = callback;
        historical.Set(L"historical", knjson::Value(true));
        setCallback(historical);
        check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp), "callback-navigation.historical-row-refused");
        callback.Set(L"kind", knjson::Value(L"RoutineObservation"));
        callback.Set(L"routine", knjson::Value(L"0xffff800055556666"));
        setCallback(callback);
        check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp), "callback-navigation.field-must-match-record-kind");
        binding.Set(L"field", knjson::Value(L"routine"));
        memory.Set(L"source", binding);
        check(MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp) == L"db \"0xffff800055556666\" L0x0000000000000040",
              "callback-navigation.notify-and-registry-routine-supported");
        for (const auto *kind : {L"RegistryHive", L"KernelTimer", L"QueuedDpc"})
        {
            callback.Set(L"kind", knjson::Value(kind));
            setCallback(callback);
            check(MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp) == L"db \"0xffff800055556666\" L0x0000000000000040",
                  "record-navigation.semantic-routine-retains-bound-memory-action");
            auto disassembly = binding;
            disassembly.Set(L"action", knjson::Value(L"disassemble"));
            code.Set(L"source", disassembly);
            check(DisassemblyViewCommand(code, &callbacks, &callbacks.Data.Stamp) == L"u \"0xffff800055556666\" L0x0000000000000010",
                  "record-navigation.semantic-routine-retains-bound-code-action");
            auto invalid = callback;
            invalid.Set(L"routine", knjson::Value(L"0x0"));
            setCallback(invalid);
            check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp), "record-navigation.null-routine-refused");
            invalid = callback;
            invalid.Set(L"addressSpace", knjson::Value(L"physical"));
            setCallback(invalid);
            auto routinePath = knjson::Value::MakeArray();
            routinePath.Push(knjson::Value(L"routine"));
            auto pathSource = navigation;
            pathSource.Set(L"path", routinePath);
            check(!MemoryViewCommand(memory, &callbacks, &callbacks.Data.Stamp) &&
                !BoundResultAddress(callbacks, pathSource, callbacks.Data.Stamp),
                "record-navigation.routine-cannot-be-reinterpreted-as-physical");
            setCallback(callback);
            check(!MemoryViewCommand(memory, &callbacks, &stale), "record-navigation.stale-source-refused");
        }
    }
    {
        auto parameters = knjson::Value::MakeObject();
        parameters.Set(L"operation", knjson::Value(L"breakpoint-add"));
        parameters.Set(L"expression", knjson::Value(L"nt!Function + 10"));
        parameters.Set(L"source", knjson::Value::MakeObject());
        parameters.Set(L"expectedStamp", bound.Data.Stamp.ToJson());
        check(BreakpointPlanCommand(parameters, nullptr, bound.Data.Stamp) == L"debug-plan breakpoint-add \"nt!Function + 10\"",
              "breakpoint-ui.address-expression-is-one-operand");
        std::wstring reason;
        check(RpcNeedsWorker(L"breakpointPlan") && RpcShape(FixtureRpc(L"breakpointPlan", 1, parameters), reason),
              "breakpoint-ui.plan-runs-on-owned-worker");
        bool refused = true;
        for (const auto *expression : {L"", L"   ", L"nt;g", L"\"nt\"", L"nt\ng", L"nt\\", L"{g}"})
        {
            parameters.Set(L"expression", knjson::Value(expression));
            refused = refused && !BreakpointPlanCommand(parameters, nullptr, bound.Data.Stamp);
        }
        check(refused, "breakpoint-ui.expression-cannot-inject-a-command");
        parameters.Set(L"expression", knjson::Value(std::wstring(1025, L'a')));
        check(!BreakpointPlanCommand(parameters, nullptr, bound.Data.Stamp), "breakpoint-ui.expression-length-is-bounded");
        auto binding = knjson::Value::MakeObject();
        binding.Set(L"resultId", knjson::Value(bound.Id));
        binding.Set(L"index", knjson::Value(L"0"));
        parameters.Set(L"source", binding);
        auto instructions = bound;
        instructions.Data.CommandId = L"u";
        check(BreakpointPlanCommand(parameters, &instructions, bound.Data.Stamp) == L"debug-plan breakpoint-add 0xffff800012345678",
              "breakpoint-ui.instruction-action-uses-retained-address");
        auto stale = bound.Data.Stamp;
        ++stale.StopEpoch;
        check(!BreakpointPlanCommand(parameters, &instructions, stale) && !BreakpointPlanCommand(parameters, nullptr, bound.Data.Stamp),
              "breakpoint-ui.stale-or-expired-source-is-refused");
        auto list = bound;
        list.Data.CommandId = L"breakpoints";
        auto entry = knjson::Value::MakeObject();
        entry.Set(L"kind", knjson::Value(L"Breakpoint"));
        entry.Set(L"id", knjson::Value(L"19"));
        entry.Set(L"identity", knjson::Value(L"guid-and-settings"));
        list.Data.Rows = knjson::Value::MakeArray();
        list.Data.Rows.Push(entry);
        refused = true;
        for (const auto *operation : {L"breakpoint-remove", L"breakpoint-enable", L"breakpoint-disable"})
        {
            parameters.Set(L"operation", knjson::Value(operation));
            refused = refused && BreakpointPlanCommand(parameters, &list, bound.Data.Stamp) == std::wstring(L"debug-plan ") + operation + L" 19";
        }
        check(refused, "breakpoint-ui.edit-uses-retained-decimal-id");
        parameters.Set(L"operation", knjson::Value(L"go"));
        check(!BreakpointPlanCommand(parameters, &list, bound.Data.Stamp), "breakpoint-ui.execution-control-is-not-an-edit-operation");
        parameters.Set(L"operation", knjson::Value(L"breakpoint-remove"));
        binding.Set(L"index", knjson::Value(L"1"));
        parameters.Set(L"source", binding);
        check(!BreakpointPlanCommand(parameters, &list, bound.Data.Stamp), "breakpoint-ui.out-of-range-row-is-refused");
        DebugActions actionPlans;
        DebugAction action{L"id", L"token", L"breakpoint-disable", 19, bound.Data.Stamp, L"identity",
                           std::chrono::steady_clock::now() + std::chrono::seconds(60)};
        check(actionPlans.Add(action) && actionPlans.Find(L"id", L"token").has_value() && !actionPlans.Find(L"id", L"wrong"),
              "breakpoint-ui.preview-lookup-requires-token");
        actionPlans.Discard(L"id", L"wrong");
        check(actionPlans.Find(L"id", L"token").has_value(), "breakpoint-ui.wrong-token-cannot-discard-plan");
        actionPlans.Discard(L"id", L"token");
        check(!actionPlans.Consume(L"id", L"token", bound.Data.Stamp), "breakpoint-ui.cancel-discards-plan");
    }
    {
        auto parameters = knjson::Value::MakeObject();
        parameters.Set(L"expression", knjson::Value(L"0"));
        parameters.Set(L"count", knjson::Value(L"64"));
        auto source = navigation;
        source.Set(L"action", knjson::Value(L"disassemble"));
        parameters.Set(L"source", source);
        check(DisassemblyViewCommand(parameters, &bound, &bound.Data.Stamp) ==
                  L"u \"0xffff800012345678\" L0x0000000000000040",
              "disassembly-view.inspector-uses-immutable-source-address");
        auto stale = bound.Data.Stamp;
        ++stale.ContextGeneration;
        check(!DisassemblyViewCommand(parameters, &bound, &stale) && !DisassemblyViewCommand(parameters),
              "disassembly-view.stale-or-expired-source-rejected");
        source.Set(L"action", knjson::Value(L"navigate"));
        parameters.Set(L"source", source);
        check(!DisassemblyViewCommand(parameters, &bound, &bound.Data.Stamp), "disassembly-view.only-code-action-is-accepted");
        source.Set(L"action", knjson::Value(L"disassemble"));
        parameters.Set(L"source", source);
        auto physical = bound;
        auto physicalRow = boundRow;
        physicalRow.Set(L"addressSpace", knjson::Value(L"physical"));
        physical.Data.Rows = knjson::Value::MakeArray();
        physical.Data.Rows.Push(physicalRow);
        check(!DisassemblyViewCommand(parameters, &physical, &physical.Data.Stamp), "disassembly-view.physical-source-is-refused");
    }
    bool denied = true;
    for (unsigned change = 0; change < 6; ++change)
    {
        auto current = bound.Data.Stamp;
        switch (change)
        {
        case 0:
            ++current.StopEpoch;
            break;
        case 1:
            ++current.ContextGeneration;
            break;
        case 2:
            ++current.SymbolGeneration;
            break;
        case 3:
            current.Context.ImplicitProcess = 0x6000;
            break;
        case 4:
            current.Context.EffectiveArchitecture = 0x14c;
            break;
        case 5:
            current.Context.ScopeIndex = 1;
            break;
        }
        denied = denied && !BoundResultCommand(bound, navigation, current);
    }
    check(denied, "rereview.navigation-full-context-changes-rejected-before-command-dispatch");
    navigation.Set(L"expectedStamp", stamp.ToJson());
    check(!BoundResultCommand(bound, navigation, bound.Data.Stamp), "rereview.navigation-forged-source-stamp-rejected");
    navigation.Set(L"expectedStamp", bound.Data.Stamp.ToJson());
    navigation.Set(L"index", knjson::Value(L"9007199254740993"));
    check(!BoundResultCommand(bound, navigation, bound.Data.Stamp), "rereview.navigation-invalid-row-identity-rejected");
    navigation.Set(L"index", knjson::Value(L"0"));
    auto oldProtocol = FixtureRpc(L"navigateResult", 92, navigation);
    oldProtocol.Set(L"schema", knjson::Value(L"kndbgx.rpc.v2"));
    std::wstring reason;
    check(!RpcShape(oldProtocol, reason) && RpcShape(FixtureRpc(L"navigateResult", 93, navigation), reason),
          "rereview.rpc-old-navigation-protocol-rejected");
    boundRow.Set(L"historical", knjson::Value(true));
    bound.Data.Rows = knjson::Value::MakeArray();
    bound.Data.Rows.Push(boundRow);
    check(!BoundResultCommand(bound, navigation, bound.Data.Stamp), "rereview.navigation-history-row-cannot-rebind-to-fresh-result");
    {
        auto processes = bound;
        processes.Data.CommandId = L"!dml_proc";
        processes.Data.State = Status::Partial;
        ProcessRow process;
        process.Eprocess = 0xffff800012345000;
        process.Pid = 42;
        process.DirectoryTableBase = 0x12345000;
        process.CreateTime = 0x123456789abcdef;
        process.PidKnown = process.DtbKnown = process.CreateTimeKnown = true;
        processes.Data.Rows = knjson::Value::MakeArray();
        processes.Data.Rows.Push(process.ToJson());
        auto parameters = navigation;
        parameters.Set(L"action", knjson::Value(L"attach"));
        check(BoundProcessRow(processes, parameters, processes.Data.Stamp) != nullptr &&
                  SameProcessIdentity(processes.Data.Rows.Items()[0], process), "process-action.observed-partial-row-has-exact-identity");
        auto currentStamp = processes.Data.Stamp;
        ++currentStamp.StopEpoch;
        check(!BoundProcessRow(processes, parameters, currentStamp), "process-action-resume-rejects-old-inventory");
        parameters.Set(L"index", knjson::Value(L"1"));
        check(!BoundProcessRow(processes, parameters, processes.Data.Stamp), "process-action-invalid-index-rejected");
        parameters.Set(L"index", knjson::Value(L"0"));
        parameters.Set(L"expectedStamp", currentStamp.ToJson());
        check(!BoundProcessRow(processes, parameters, processes.Data.Stamp), "process-action-forged-stamp-rejected");
        parameters.Set(L"expectedStamp", processes.Data.Stamp.ToJson());
        processes.Data.CommandId = L"sarif-import";
        check(!BoundProcessRow(processes, parameters, processes.Data.Stamp), "process-action-import-cannot-impersonate-inventory");
        const auto original = process.ToJson();
        ++process.CreateTime;
        check(!SameProcessIdentity(original, process), "process-action-reused-eprocess-rejected");
        --process.CreateTime;
        ++process.DirectoryTableBase;
        check(!SameProcessIdentity(original, process), "process-action-changed-dtb-rejected");
        --process.DirectoryTableBase;
        process.PidKnown = false;
        check(!SameProcessIdentity(original, process), "process-action-unknown-identity-rejected");
        uint64_t active = 0x1000;
        unsigned writes = 0;
        const auto read = [&]() -> std::optional<uint64_t>
        {
            return active;
        };
        const auto write = [&](uint64_t address)
        {
            ++writes;
            active = address;
            return true;
        };
        check(SwitchImplicitProcess(0x2000, read, write) == ProcessSwitchResult::Success && active == 0x2000 && writes == 1,
              "process-action-switch-readback-verified");
        check(SwitchImplicitProcess(0x2000, read, write) == ProcessSwitchResult::Success && writes == 1,
              "process-action-current-context-is-idempotent");
        check(SwitchImplicitProcess(0x3000, []() -> std::optional<uint64_t>
        {
            return std::nullopt;
        }, write) ==
                  ProcessSwitchResult::Unavailable && writes == 1, "process-action-unreadable-context-never-written");
        check(SwitchImplicitProcess(0x3000, read, [](uint64_t)
        {
            return false;
        }) == ProcessSwitchResult::Rejected && active == 0x2000,
              "process-action-rejected-switch-preserves-context");
        writes = 0;
        check(SwitchImplicitProcess(0x3000, read, [&](uint64_t address)
        {
            ++writes;
            active = address;
            return writes > 1;
        }) == ProcessSwitchResult::Rejected && active == 0x2000 && writes == 2, "process-action-partial-failure-restores-context");
        check(SwitchImplicitProcess(0x3000, read, [&](uint64_t)
        {
            active = 0x4000;
            return false;
        }) == ProcessSwitchResult::RestoreFailed, "process-action-rollback-failure-is-distinct");
        auto actionParams = knjson::Value::MakeObject();
        for (const auto *field : {L"resultId", L"index", L"action", L"expectedStamp"})
        {
            actionParams.Set(field, parameters.Get(field));
        }
        check(RpcNeedsWorker(L"processAction") && RpcShape(FixtureRpc(L"processAction", 94, actionParams), reason),
              "process-action-uses-owned-worker-and-strict-rpc-schema");
        actionParams.Set(L"eprocess", knjson::Value(L"0xffff800000000000"));
        check(!RpcShape(FixtureRpc(L"processAction", 95, actionParams), reason), "process-action-cannot-override-retained-address");
    }
    const auto projection = ProjectResult(stored, 128, stamp);
    check(projection.Get(L"Rows").Items().size() == 128 && projection.Get(L"Next").AsString(L"") == L"256" &&
              !projection.Get(L"PageComplete").AsBool(true),
          "T-MODEL.explicit-page-boundary");
    check(projection.Get(L"Rows").Items()[0].Write() == row.Write() && projection.Get(L"Rows").Items()[0].Get(L"unknown").IsNull(),
          "T-MODEL.same-rows-precision-and-unknown");
    check(ProjectResult(stored, 256, changed).Get(L"HistoricalAtPublication").AsBool(false) &&
              ProjectResult(stored, 256, stamp).Get(L"PageComplete").AsBool(false),
          "T-MODEL.stale-result-remains-addressable");
    knengine::DbgSession detached;
    {
        kncore::ExecutionLease lease(knengine::Coordinator());
        knengine::Coordinator().Cancel();
        const auto cancelledBookmark = kncmd::DispatchCommand(detached, L"bookmark cancelled");
        check(cancelledBookmark.Data.State == Status::Cancelled && !cancelledBookmark.Data.Collected.Complete,
              "review.cancelled-dispatch-never-retains-complete-coverage");
        const auto offlineHistory = kncmd::DispatchCommand(detached, L"history");
        check(offlineHistory.Data.State == Status::Success && offlineHistory.Data.Collected.Complete,
              "rereview.offline-history-works-while-engine-cancelled");
    }
    const auto dispatched = kncmd::DispatchCommand(detached, L"version");
    const auto retained = Results().Find(dispatched.ResultId);
    check(retained && retained->Data.ToJson().Write() == dispatched.Data.ToJson().Write(),
          "T-RESULT.dispatch-publishes-same-immutable-object");
    auto parameters = knjson::Value::MakeObject();
    parameters.Set(L"resultId", knjson::Value(dispatched.ResultId));
    const auto ui = knbridge::HandleRequest(FixtureRpc(L"resultInfo", 87, parameters), &detached);
    check(ui.Get(L"ok").AsBool(false) && ui.Get(L"result").Get(L"data").Get(L"target").Write() == retained->Data.Stamp.ToJson().Write(),
          "T-RESULT.cli-ui-share-id-and-target");
    value.Limitations.Push(knjson::Value(std::wstring(100000, L'x')));
    const auto huge = Results().Publish(L"huge-metadata-fixture", value, L"text");
    parameters.Set(L"resultId", knjson::Value(huge->Id));
    const auto bounded = knbridge::HandleRequest(FixtureRpc(L"resultInfo", 88, parameters), &detached);
    check(knutil::WideToUtf8(bounded.Write()).size() <= 65536 && bounded.Get(L"result").Get(L"resultId").AsString(L"") == huge->Id,
          "T-RPC.reply-metadata-is-bounded-with-result-retained");
    check(kncmd::FindCommand(L"debug-approve") != nullptr &&
              kncmd::HasEffect(kncmd::FindCommand(L"debug-approve")->Effects, kncmd::Effect::ExecutionControl),
          "T-ACTION.execution-effect-registered");
}
} // namespace knself
