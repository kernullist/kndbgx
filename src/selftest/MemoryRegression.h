#pragma once

#include "../core/MemoryString.h"
#include "../core/DisplayCursor.h"
#include "../core/MemoryOperands.h"
#include "../core/MemoryView.h"
#include "../cmd/CmdTypes.h"
#include "../cmd/Dispatcher.h"
#include "../engine/ModuleList.h"

namespace knself
{
template <typename Check> void RunMemoryRegression(Check check)
{
    using namespace kncore;
    DisplayCursorStore cursors;
    SessionStamp stamp;
    stamp.SessionId = L"cursor-fixture";
    stamp.TargetGeneration = 1;
    stamp.StopEpoch = 1;
    stamp.ContextGeneration = 1;
    stamp.Context.ImplicitProcess = 0x1000;
    check(!cursors.Next(DisplayKind::VirtualMemory, stamp, {}), "memory.cursor-empty-has-no-address");
    cursors.Remember(DisplayKind::VirtualMemory, stamp, {}, 0x2003);
    cursors.Remember(DisplayKind::PhysicalMemory, stamp, {}, 0x800);
    check(cursors.Next(DisplayKind::VirtualMemory, stamp, {}) == 0x2003 &&
              cursors.Next(DisplayKind::PhysicalMemory, stamp, {}) == 0x800 && !cursors.Next(DisplayKind::Disassembly, stamp, {}),
          "memory.cursor-address-spaces-and-disassembly-independent");
    auto changed = stamp;
    ++changed.SymbolGeneration;
    check(cursors.Next(DisplayKind::VirtualMemory, changed, {}) == 0x2003, "memory.cursor-symbol-load-preserves-address");
    bool invalidated = true;
    for (unsigned change = 0; change < 6; ++change)
    {
        changed = stamp;
        cursors.Remember(DisplayKind::VirtualMemory, stamp, {}, 0x2003);
        if (change == 0)
        {
            changed.SessionId = L"other";
        }
        else if (change == 1)
        {
            ++changed.TargetGeneration;
        }
        else if (change == 2)
        {
            ++changed.StopEpoch;
        }
        else if (change == 3)
        {
            ++changed.ContextGeneration;
        }
        else if (change == 4)
        {
            changed.Context.ImplicitProcess = 0x3000;
        }
        invalidated = !cursors.Next(DisplayKind::VirtualMemory, changed,
                                   change == 5 ? std::optional<uint64_t>(0x5000) : std::nullopt) && invalidated;
        invalidated = !cursors.Next(DisplayKind::VirtualMemory, stamp, {}) && invalidated;
    }
    check(invalidated, "memory.cursor-target-stop-context-dtb-change-drops-history");
    const auto decode = [](std::initializer_list<unsigned char> bytes, bool wide)
    {
        return DecodeMemoryString(std::span(bytes.begin(), bytes.size()), wide);
    };
    const auto ascii = decode({0x41, 0x80, 0xff, 1, 0, 0x42}, false);
    check(ascii.Text == L"A\\x80\\xff\\x01" && ascii.Terminated && ascii.Consumed == 5 && ascii.InvalidUnits == 0,
          "memory.ascii-unsigned-escaped-and-bounded-by-terminator");
    const auto empty = decode({0, 0, 0, 0xd8}, true);
    check(empty.Text.empty() && empty.Terminated && empty.Consumed == 2 && empty.InvalidUnits == 0,
          "memory.utf16-empty-does-not-inspect-trailing-garbage");
    const auto pair = decode({0x3d, 0xd8, 0, 0xde, 0, 0}, true);
    check(pair.Text == L"\U0001f600" && pair.Terminated && pair.InvalidUnits == 0 && ValidUtf16(pair.Text),
          "memory.utf16-surrogate-pair-positive");
    const auto broken = decode({0, 0xdc, 0, 0xd8, 0x41, 0, 0, 0xd8, 0, 0}, true);
    check(broken.Text == L"\ufffd\ufffdA\ufffd" && broken.Terminated && broken.InvalidUnits == 3 && ValidUtf16(broken.Text),
          "memory.utf16-invalid-units-retain-valid-neighbors-and-terminator");
    const auto odd = decode({0x41, 0, 0xff}, true);
    check(odd.Text == L"A\\xff" && !odd.Terminated && odd.InvalidUnits == 1 && odd.Consumed == 3, "memory.utf16-odd-tail-is-explicit");
    const auto truncatedPair = decode({0, 0xd8}, true);
    check(truncatedPair.Text == L"\ufffd" && !truncatedPair.Terminated && truncatedPair.InvalidUnits == 1,
          "memory.utf16-high-surrogate-at-read-boundary");
    const auto bounded = decode({0x41, 0x42}, false);
    check(bounded.Text == L"AB" && !bounded.Terminated && bounded.Consumed == 2, "memory.unterminated-prefix-is-preserved");
    const auto evaluate = [](const std::wstring &text, uint64_t *value)
    {
        return ParseUnsigned(text, 16, value);
    };
    const auto explicitDtb = ParseMemoryOperands({L"vtop", L"ffff800012345678", L"123000"}, evaluate);
    check(explicitDtb.Error.empty() && explicitDtb.Address == 0xffff800012345678 && explicitDtb.Extra == 0x123000,
          "vtop.positional-dtb-does-not-replace-virtual-address");
    const auto zeroDtb = ParseMemoryOperands({L"vtop", L"1000", L"0"}, evaluate);
    check(zeroDtb.Extra.has_value() && *zeroDtb.Extra == 0, "vtop.explicit-zero-is-not-implicit-context");
    const auto query = ParseMemoryOperands({L"query", L"1000", L"30"}, evaluate);
    check(query.Address == 0x1000 && query.Extra == 0x30 && query.Error.empty(), "query.optional-length-is-evaluated");
    check(!ParseMemoryOperands({L"vtop", L"1000", L"bad-symbol"}, evaluate).Error.empty() &&
              !ParseMemoryOperands({L"vtop", L"bad-symbol", L"1000"}, evaluate).Error.empty() &&
              !ParseMemoryOperands({L"vtop"}, evaluate).Error.empty() &&
              !ParseMemoryOperands({L"vtop", L"1", L"2", L"3"}, evaluate).Error.empty() &&
              !ParseMemoryOperands({L"query", L"1000"}, evaluate).Extra,
          "memory.operands-reject-invalid-input-and-preserve-optional-default");
    knengine::DbgSession detached;
    const auto capture = detached.MemoryCaptureInfo();
    check(capture.Get(L"kind").AsString(L"") == L"Unknown" && capture.Get(L"class").IsNull() &&
              capture.Get(L"dumpFlags").IsNull(), "memory.evidence-unavailable-capture-is-not-live-or-dump");
    ReadResult shortRead;
    static_cast<TransferResult &>(shortRead) = TransferStatus(64, 7, 0);
    shortRead.Address = 0x1234;
    auto attempts = knjson::Value::MakeArray();
    attempts.Push(MemoryReadAttempt(shortRead));
    const auto shortEvidence = MemoryReadEvidence(0x1234, AddressSpace::Virtual, 64, 7, attempts, capture);
    check(shortEvidence.Get(L"attempts").Items()[0].Get(L"status").AsString(L"") == L"Partial" &&
              shortEvidence.Get(L"attempts").Items()[0].Get(L"nativeError").Get(L"code").AsString(L"") == Hex(0) &&
              shortEvidence.Get(L"read").AsString(L"") == L"7" && shortEvidence.Get(L"length").AsString(L"") == L"64" &&
              shortEvidence.Get(L"mapping").AsString(L"") == L"Unobserved" &&
              shortEvidence.Get(L"unreadableCause").AsString(L"") == L"Unknown",
          "memory.evidence-short-success-retains-counts-without-inferring-a-cause");
    static_cast<TransferResult &>(shortRead) = TransferStatus(64, 0, static_cast<int32_t>(0x80004005U));
    const auto failedEvidence = MemoryReadAttempt(shortRead);
    check(failedEvidence.Get(L"read").AsString(L"") == L"0" &&
              failedEvidence.Get(L"nativeError").Get(L"code").AsString(L"") == Hex(0x80004005U) &&
              failedEvidence.Get(L"status").AsString(L"") == L"Unavailable",
          "memory.evidence-unavailable-preserves-native-failure");
    ReadResult cancelledRead;
    cancelledRead.State = Status::Cancelled;
    cancelledRead.Address = 0x1000;
    cancelledRead.Requested = 16;
    check(MemoryReadAttempt(cancelledRead).Get(L"nativeError").IsNull(),
          "memory.evidence-no-native-call-does-not-invent-success-hresult");
    const auto physicalEvidence = MemoryReadEvidence(0, AddressSpace::Physical, 64, 7, attempts, capture);
    check(physicalEvidence.Get(L"addressSpace").AsString(L"") == L"physical" &&
              physicalEvidence.Get(L"address").AsString(L"") == Hex(0),
          "memory.evidence-physical-zero-address-remains-explicit");
    const std::vector<std::wstring> showContext{L"procctx", L"show"};
    kncmd::CmdText contextOutput;
    kncmd::Ctx context{detached, showContext, contextOutput};
    kncmd::ProcessContextCmd(context);
    check(contextOutput.Details.State == Status::Unavailable && contextOutput.Text().find(L"00000000`00000000") == std::wstring::npos,
          "procctx.unavailable-cr3-is-not-zero");
    const std::vector<knengine::KernelModuleInfo> ambiguousModules{{L"first", L"first.sys", 0x1000, 0x2000, 1},
                                                                   {L"second", L"second.sys", 0x2000, 0x1000, 2}};
    check(knengine::FindModuleForAddress(ambiguousModules, 0x2000) == nullptr &&
              knengine::FindModuleForAddress(ambiguousModules, 0x1000) == &ambiguousModules[0],
          "dump.module-owner-must-be-unique");
    for (const auto command : {L"dump-raw", L"dump-pe", L".dump"})
    {
        kncmd::CmdText out;
        const std::vector<std::wstring> args{command};
        kncmd::Ctx ctx{detached, args, out};
        kncmd::RecordDumpArtifact(ctx, L"fixture.dmp", 4096, L"Fixture");
        kncmd::CommandResult result;
        result.Data = out.Details;
        kncmd::FinalizeCollection(result, kncmd::FindCommand(command), result.Data.Stamp, true);
        check(result.Data.State == Status::Success && result.Data.Collected.Complete &&
                  result.Data.Analysis.Get(L"artifactCommitted").AsBool(false) &&
                  result.Data.Rows.Items()[0].Get(L"bytes").AsString(L"") == L"4096",
              "dump.committed-receipt-survives-late-cancellation");
    }
}
} // namespace knself
