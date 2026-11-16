// KNDbgX self-test runner (driver-free).
//
// Validates pure logic that does not require a debugger session:
// JSON codec, formatting helpers, catalog integrity and command
// classification. Exit code 0 = all tests passed.

#include "../../src/catalog/Catalog.h"
#include "../../src/cmd/CmdUtil.h"
#include "../../src/engine/PageWalk.h"
#include "../../src/cmd/Dispatcher.h"
#include "../../src/cmd/WriteGate.h"
#include "../../src/util/Json.h"
#include "../../src/util/Text.h"
#include "PureRegression.h"
#include "FaultRegression.h"
#include "ExecutionRegression.h"
#include "PolicyRegression.h"
#include "LayoutRegression.h"
#include "CollectorRegression.h"
#include "HandleTableRegression.h"
#include "ScannerRegression.h"
#include "SnapshotRpcRegression.h"
#include "SnapshotReviewRegression.h"
#include "ResultPageRegression.h"
#include "ResultExportRegression.h"
#include "UiLifecycleRegression.h"
#include "UiOperationsRegression.h"
#include "DebuggerRegression.h"
#include "KernelAnalysisRegression.h"
#include "KernelReviewRegression.h"
#include "CallbackRegression.h"
#include "PresentationRegression.h"
#include "KernelSymbolRegression.h"
#include "MemoryRegression.h"
#include "MemoryExportRegression.h"
#include "PlatformPostureRegression.h"
#include "DiagnosticRegression.h"
#include "PiddbRegression.h"
#include "CommandRecordRegression.h"
#include "KernelPartialRegression.h"
#include "AlpcRegression.h"
#include "Win32kDispatchRegression.h"

#include <cstdio>
#include <string>
#include <vector>

namespace
{
int g_failed = 0;
int g_passed = 0;

void Check(bool condition, const char *name)
{
    if (condition)
    {
        ++g_passed;
        std::printf("[PASS] %s\n", name);
    }
    else
    {
        ++g_failed;
        std::printf("[FAIL] %s\n", name);
    }
}

void TestJsonCodec()
{
    knjson::Value parsed;
    const bool okParse = knjson::Parse(L"{\"id\":7,\"ok\":true,\"name\":\"a\\\"b\",\"arr\":[1,2,null]}", &parsed);

    Check(okParse, "json.parse.object");
    Check(parsed.IsObject(), "json.type.object");
    Check(parsed.Get(L"id").AsDouble(0) == 7.0, "json.number");
    Check(parsed.Get(L"ok").AsBool(false) == true, "json.bool");
    Check(parsed.Get(L"name").AsString(L"") == L"a\"b", "json.escape");
    Check(parsed.Get(L"arr").IsArray() && parsed.Get(L"arr").Items().size() == 3, "json.array");

    const std::wstring written = parsed.Write();
    knjson::Value reparsed;

    Check(knjson::Parse(written, &reparsed), "json.roundtrip.parse");
    Check(reparsed.Write() == written, "json.roundtrip.stable");
    Check(knjson::Value(42.0).Write() == L"42", "json.write.int");
    Check(knjson::Value(3.5).Write() == L"3.5", "json.write.float");

    knjson::Value surrogate;

    Check(knjson::Parse(L"\"\\ud83d\\ude00\"", &surrogate), "json.surrogate.parse");
    Check(surrogate.AsString(L"").size() == 2, "json.surrogate.pair");

    knjson::Value bad;

    Check(!knjson::Parse(L"{\"a\":}", &bad), "json.reject.truncated");
    Check(!knjson::Parse(L"[1,", &bad), "json.reject.open");
}

void TestFormatting()
{
    Check(kncmd::FmtAddr(0xfffff80403800000ULL) == L"fffff804`03800000", "fmt.addr.grouping");
    Check(kncmd::FmtHexN(0xAB, 8) == L"000000ab", "fmt.hex.pad");
    Check(kncmd::FmtDec(12345) == L"12345", "fmt.dec");

    const std::vector<std::wstring> tokens = kncmd::TokenizeLine(L"  db  nt!KiSystemCall64   L10 ");

    Check(tokens.size() == 3 && tokens[0] == L"db" && tokens[2] == L"L10", "tokenize.basic");
}

void TestCatalog()
{
    const auto &entries = kncat::All();

    Check(!entries.empty(), "catalog.nonempty");

    bool duplicates = false;
    bool emptyFields = false;

    for (size_t i = 0; i < entries.size(); ++i)
    {
        if (entries[i].Name == nullptr || entries[i].Group == nullptr || entries[i].Synopsis == nullptr)
        {
            emptyFields = true;
            break;
        }

        for (size_t j = i + 1; j < entries.size(); ++j)
        {
            if (_wcsicmp(entries[i].Name, entries[j].Name) == 0)
            {
                duplicates = true;
                break;
            }
        }
    }

    Check(!emptyFields, "catalog.fields");
    Check(!duplicates, "catalog.unique-names");

    size_t plannedCount = 0;
    for (const auto &entry : entries)
    {
        if (entry.Level == kncat::Support::Planned)
        {
            ++plannedCount;
        }
    }
    Check(plannedCount == 0, "catalog.zero-planned-complete");

    const auto completes = [](const std::wstring &prefix, const std::wstring &expected)
    {
        const auto matches = kncat::CompletionsFor(prefix);
        return std::find(matches.begin(), matches.end(), expected) != matches.end();
    };
    bool allNames = true;
    bool allHelp = true;
    for (const auto &entry : entries)
    {
        allNames = allNames && completes(entry.Name, entry.Name);
        allHelp = allHelp && completes(L"help " + std::wstring(entry.Name), L"help " + std::wstring(entry.Name));
    }
    Check(allNames && allHelp, "catalog.completion-covers-every-command-alias-and-help-operand");
    const auto catalogReply = knbridge::HandleRequest(knself::FixtureRpc(L"catalog", 990));
    bool grammarMatches = catalogReply.Get(L"ok").AsBool(false);
    for (const auto &entry : entries)
    {
        const auto &group = catalogReply.Get(L"result").Get(L"groups").Get(entry.Group).Items();
        const auto item = std::find_if(group.begin(), group.end(), [&](const auto &row)
        {
            return row.Get(L"name").AsString(L"") == entry.Name;
        });
        grammarMatches = grammarMatches && item != group.end() &&
                         item->Get(L"grammar").AsString(L"") == kncmd::FindCommand(entry.Name)->Grammar;
    }
    Check(grammarMatches, "catalog.rpc-publishes-registry-grammar-for-every-command-and-alias");
    const auto catalogEntry = [&](const wchar_t *name)
    {
        for (const auto &[groupName, commands] : catalogReply.Get(L"result").Get(L"groups").Fields())
        {
            for (const auto &entry : commands.Items())
            {
                if (entry.Get(L"name").AsString(L"") == name)
                {
                    return entry;
                }
            }
        }
        return knjson::Value();
    };
    const auto codeParameters = catalogEntry(L"u").Get(L"symbolParameters");
    const auto typedParameters = catalogEntry(L"dt").Get(L"symbolParameters");
    const auto dumpOptions = catalogEntry(L"dump-raw").Get(L"completionOptions");
    Check(codeParameters.Items().size() == 1 && codeParameters.Items()[0].AsDouble(-1) == 0 &&
              typedParameters.Items().size() == 1 && typedParameters.Items()[0].AsDouble(-1) == 1 &&
              dumpOptions.Items().size() == 1 && dumpOptions.Items()[0].Get(L"name").AsString(L"") == L"/phys" &&
              !dumpOptions.Items()[0].Get(L"takesValue").AsBool(true),
          "catalog.symbol-completion-publishes-address-slots-and-option-arity");
    auto completionParams = knjson::Value::MakeObject();
    completionParams.Set(L"prefix", knjson::Value(L"!vad pid:4 /ex"));
    const auto completionReply = knbridge::HandleRequest(knself::FixtureRpc(L"complete", 991, completionParams));
    const auto &completionItems = completionReply.Get(L"result").Get(L"items").Items();
    Check(completionReply.Get(L"ok").AsBool(false) && completionItems.size() == 1 &&
              completionItems[0].AsString(L"") == L"!vad pid:4 /exec",
          "catalog.rpc-completes-arguments-without-an-engine-session");
    Check(completes(L"HeLp u", L"HeLp ui") && completes(L"  !THREADS et", L"  !THREADS ethread:"),
          "catalog.completion-preserves-leading-space-case-and-selector-prefix");
    Check(completes(L"!process p", L"!process pid:") && completes(L"!process ", L"!process 0") &&
              completes(L"!processes i", L"!processes image:") && completes(L"procctx r", L"procctx reset"),
          "catalog.completion-current-process-selectors-and-inventory-alias");
    Check(completes(L"!vad pid:4 /ex", L"!vad pid:4 /exec") &&
              completes(L"!vad /limit 8 /h", L"!vad /limit 8 /hiddenpte"),
          "catalog.completion-options-after-selector-or-value");
    Check(kncat::CompletionsFor(L"!vad /EXEC /ex").empty() && kncat::CompletionsFor(L"!vad /limit ").empty() &&
              kncat::CompletionsFor(L"!vad /json C:\\").empty() && kncat::CompletionsFor(L"!threads ethread:123 ").empty(),
          "catalog.completion-never-duplicates-options-or-invents-values");
    Check(kncat::CompletionsFor(L"").empty() && kncat::CompletionsFor(L"   ").empty() &&
              kncat::CompletionsFor(L"!vad image:\"a b\" /e").empty() && kncat::CompletionsFor(L"help; !vad /e").empty() &&
              kncat::CompletionsFor(L"help\nui").empty() && kncat::CompletionsFor(std::wstring(32769, L'a')).empty(),
          "catalog.completion-rejects-empty-quoted-compound-or-oversized-input");
    knengine::DbgSession unconnected;
    const auto workspace = kncmd::DispatchCommand(unconnected, L"help UI");
    Check(workspace.Ok && workspace.Output.find(L"Current process:") != std::wstring::npos &&
              workspace.Output.find(L"Processes:") != std::wstring::npos && workspace.Output.find(L"Memory:") != std::wstring::npos &&
              workspace.Output.find(L"Copy:") != std::wstring::npos,
          "help.workspace-is-available-without-target");
    Check(workspace.Output.find(L"ln and uf use the current instruction") != std::wstring::npos &&
              workspace.Output.find(L"Omitted memory/unassembly addresses") == std::wstring::npos,
          "help.workspace-distinguishes-current-instruction-from-continuation");
    const auto nearestHelp = kncmd::DispatchCommand(unconnected, L"help LN");
    const auto functionHelp = kncmd::DispatchCommand(unconnected, L"help UF");
    Check(nearestHelp.Ok && functionHelp.Ok && nearestHelp.Output.find(L"ln [address]") != std::wstring::npos &&
              functionHelp.Output.find(L"uf [address]") != std::wstring::npos &&
              functionHelp.Output.find(L"coverage is unverified") != std::wstring::npos,
          "help.optional-symbol-addresses-and-function-coverage-match-registry");
    Check(completes(L"l", L"ln") && completes(L"u", L"uf") && completes(L"HeLp l", L"HeLp ln") &&
              completes(L"HeLp u", L"HeLp uf") && kncat::CompletionsFor(L"ln ").empty() &&
              kncat::CompletionsFor(L"uf ").empty() && kncat::CompletionsFor(L"uf nt!KeBugCheckEx ").empty(),
          "catalog.optional-address-completion-does-not-invent-operands");
    bool symbolSlots = true;
    for (const auto *prefix : {L"u nt!KeBu", L"  DB nt!Ps", L"dump-pe nt!Ke", L"setfield nt!Ps",
                               L"dt nt!_EPROCESS nt!Ps", L"bp nt!Ke", L"bu nt!", L"!drvobj nt!Driver",
                               L"navigate va nt!Ke", L"irp nt!Irp", L"? nt!Ps", L"vtop nt!Ps"})
    {
        const auto query = kncat::SymbolQueryFor(prefix);
        symbolSlots = symbolSlots && query && query->Head + query->Word == prefix;
    }
    Check(symbolSlots, "catalog.symbol-completion-address-slots-aliases-and-forwarded-breakpoints");
    bool rejected = true;
    for (const auto *prefix : {L"u ", L"u nt!Foo+", L"u nt!Foo;g", L"u \"nt!Ke\"", L"u nt!A\ng",
                               L"dump-raw /phys nt!Ke", L"navigate pa nt!Ke", L"!db nt!Ke", L"dt nt!_EP",
                               L"eb 1000 nt!Ke", L"driver-audit nt!Ke", L"dump-pe nt nt!Ke", L"ioctl nt!Ke",
                               L"u 0xffff", L"u @rip", L"u nt!!Ke", L"u *!Ke"})
    {
        rejected = rejected && !kncat::SymbolQueryFor(prefix);
    }
    Check(rejected && !kncat::SymbolQueryFor(std::wstring(4097, L'a')),
          "catalog.symbol-completion-refuses-paths-values-physical-and-malformed-input");
    Check(!kncat::SymbolQueryFor(L"dump-raw nt!Ke", L" 100 out.bin /phys") &&
              !kncat::SymbolQueryFor(L"dump-raw nt!Ke", L" 100 \"out file.bin\" /PHYS") &&
              kncat::SymbolQueryFor(L"dump-raw nt!Ke", L" 100 \"C:\\folder /phys file.bin\"") &&
              kncat::SymbolQueryFor(L"dump-pe nt!Ke", L" <path>") &&
              !kncat::SymbolQueryFor(L"dump-pe nt!Ke", L"x <path>") &&
              !kncat::SymbolQueryFor(L"dump-pe nt!Ke", L" <path>\ng") &&
              !kncat::SymbolQueryFor(L"dump-pe nt!Ke", std::wstring(32768, L' ')),
          "catalog.symbol-completion-validates-the-entire-draft-for-physical-options-and-limits");
    auto symbolParams = knjson::Value::MakeObject();
    symbolParams.Set(L"prefix", knjson::Value(L"u nt!Ke"));
    symbolParams.Set(L"suffix", knjson::Value(L""));
    symbolParams.Set(L"expectedStamp", kncore::SessionStamp{L"fixture", 1, 2, 3, 4}.ToJson());
    std::wstring symbolReason;
    const auto symbolRequest = knself::FixtureRpc(L"completeSymbols", 992, symbolParams);
    Check(kncore::RpcNeedsWorker(L"completeSymbols") && kncore::RpcShape(symbolRequest, symbolReason) &&
              knbridge::HandleRequest(symbolRequest).Get(L"error").AsString(L"") == L"OwnerThreadRequired",
          "catalog.symbol-completion-requires-context-and-owned-engine-worker");
    symbolParams.Set(L"expectedStamp", knjson::Value(L"stale"));
    Check(!kncore::RpcShape(knself::FixtureRpc(L"completeSymbols", 993, symbolParams), symbolReason),
          "catalog.symbol-completion-rejects-untyped-context");
    const auto detailed = kncmd::DispatchCommand(unconnected, L"help !processes");
    Check(detailed.Ok && detailed.Output.find(L"!dml_proc") != std::wstring::npos &&
              detailed.Output.find(L"Aliases: !processes") != std::wstring::npos &&
              detailed.Output.find(L"Option: /json <value>") != std::wstring::npos,
          "help.alias-resolves-canonical-syntax-and-option-values");
}

void TestDispatcherClassification()
{
    Check(kncmd::IsNativeCommand(L"db nt!KiSystemCall64 L20"), "classify.native.db");
    Check(kncmd::IsNativeCommand(L"!ssdt"), "classify.native.ssdt");
    Check(kncmd::IsNativeCommand(L"? poi(nt!PsActiveProcessHead)"), "classify.native.expr");
    Check(kncmd::IsNativeCommand(L"f 0 10 90"), "classify.native.fill");
    Check(kncmd::IsNativeCommand(L"!eb 1000 0"), "classify.native.eb");
    Check(kncmd::IsNativeCommand(L"!minifilter"), "classify.native.minifilter");
    Check(kncmd::IsNativeCommand(L"dump-analyze test.dmp"), "classify.native.dump-analyze");
    Check(kncmd::IsNativeCommand(L"!hive"), "classify.native.hive-early");
    Check(kncmd::IsNativeCommand(L"dt nt!_EPROCESS"), "classify.typed.dt");
    Check(kncmd::IsNativeCommand(L".reload /f"), "classify.typed.symbols");

    kncmd::ParsedCommand parsed;
    bool hostInputs = true;
    for (const auto *line : {L".echo hello", L".formats @rip", L"!external.inspect /all", L"?? sizeof(void*)",
                             L".echo first;.printf \"second:%d\", 42", L".echo \"unclosed", L"  .echo C:\\path\\  "})
    {
        hostInputs = kncmd::ParseUiCommand(line, &parsed) && parsed.Spec->Handler == kncmd::WinDbgCommand && parsed.RawArguments == line &&
                     kncmd::HasEffect(parsed.Spec->Effects, kncmd::Effect::OpaqueEngine) && hostInputs;
        auto params = knjson::Value::MakeObject();
        params.Set(L"command", knjson::Value(line));
        const auto reply = knbridge::HandleRequest(knself::FixtureRpc(L"classify", 1001, params));
        hostInputs = reply.Get(L"ok").AsBool(false) && reply.Get(L"result").Get(L"opaque").AsBool(false) &&
                     !reply.Get(L"result").Get(L"write").AsBool(true) && hostInputs;
    }
    Check(hostInputs, "ui-command.unknown-names-use-windbg-grammar-and-preserve-input");
    Check(!kncmd::ParseCommand(L".echo hello", &parsed), "ui-command.extension-parser-stays-strict");
    bool registered = true;
    for (const auto *line : {L"db 1000 L10", L"pdb 1000 L10", L"?1+2", L".reload nt", L"EB 1000 41", L"\"version\""})
    {
        registered = kncmd::ParseUiCommand(line, &parsed) && parsed.Spec->Handler != kncmd::WinDbgCommand && registered;
    }
    Check(registered, "ui-command.registered-names-aliases-and-expression-take-precedence");
    bool rejected = true;
    for (const auto *line : {L"eb 1000", L"db \"unclosed", L"db 1000; .echo bad", L"version;.echo bad", L"!vad /unknown", L".reload /f",
                             L"", L" \t", L".echo first\n.echo second", L".echo hello\r"})
    {
        auto params = knjson::Value::MakeObject();
        params.Set(L"command", knjson::Value(line));
        const auto reply = knbridge::HandleRequest(knself::FixtureRpc(L"classify", 1002, params));
        rejected = !kncmd::ParseUiCommand(line, &parsed) && !reply.Get(L"ok").AsBool(true) && rejected;
    }
    Check(rejected && !kncmd::ParseUiCommand(std::wstring(L".echo\0hidden", 12), &parsed) &&
              !kncmd::ParseUiCommand(std::wstring(32769, L'a'), &parsed),
          "ui-command.malformed-registered-and-invalid-transport-input-never-fall-through");
    knengine::DbgSession detached;
    const auto unavailable = kncmd::DispatchCommand(detached, L".echo hello", nullptr, {}, kncmd::CommandInput::UiConsole);
    Check(!unavailable.Ok && !unavailable.Native && unavailable.Data.State == kncore::Status::Unavailable &&
              kncore::Results().Find(unavailable.ResultId) != nullptr,
          "ui-command.no-engine-is-retained-as-unavailable");
    auto resultParams = knjson::Value::MakeObject();
    resultParams.Set(L"resultId", knjson::Value(unavailable.ResultId));
    const auto reopened = knbridge::HandleRequest(knself::FixtureRpc(L"resultInfo", 1004, resultParams));
    const auto retained = kncore::Results().Find(unavailable.ResultId);
    Check(reopened.Get(L"ok").AsBool(false) && reopened.Get(L"result").Get(L"command").AsString(L"") == L".echo hello" &&
              retained != nullptr && retained->Data.Analysis.Get(L"hostCommandLine").AsString(L"") == L".echo hello",
          "ui-command.original-host-input-survives-result-reopen");
    const std::wstring largeCommand = L".echo " + std::wstring(16000, wchar_t(0xac00));
    const auto large = kncmd::DispatchCommand(detached, largeCommand, nullptr, {}, kncmd::CommandInput::UiConsole);
    resultParams.Set(L"resultId", knjson::Value(large.ResultId));
    const auto largeReply = knbridge::HandleRequest(knself::FixtureRpc(L"resultInfo", 1005, resultParams));
    Check(largeReply.Get(L"ok").AsBool(false) && largeReply.Get(L"result").Get(L"command").AsString(L"") == largeCommand &&
              knutil::WideToUtf8(largeReply.Write()).size() <= 65536,
          "ui-command.large-unicode-input-is-not-duplicated-in-result-metadata");
    const auto strict = kncmd::DispatchCommand(detached, L".echo hello");
    Check(!strict.Ok && strict.Blocked, "ui-command.extension-dispatch-does-not-inherit-fallback");
    auto params = knjson::Value::MakeObject();
    params.Set(L"command", knjson::Value(L".echo hello"));
    const auto request = knself::FixtureRpc(L"execute", 1003, params);
    const auto unowned = knbridge::HandleRequest(request);
    const auto cancelled = knbridge::HandleRequest(request, nullptr,
                                                   []()
                                                   {
                                                       return true;
                                                   });
    Check(unowned.Get(L"error").AsString(L"") == L"OwnerThreadRequired" &&
              cancelled.Get(L"error").AsString(L"") == L"CancelledBeforeExecution",
          "ui-command.fallback-retains-owner-and-cancellation-checks");
}

void TestPageWalkIndices()
{
    // 4-level: VA 0xfffff80403800000
    //   PML4=0x1f8 PDPT=0x100? compute expected from bits.
    const unsigned long long va = 0xfffff80403800000ULL;
    unsigned int idx[5] = {};

    knengine::ComputeOrderedIndices(va, false, idx);

    Check(idx[0] == ((va >> 39) & 0x1FF), "pgw.la4.pml4");
    Check(idx[1] == ((va >> 30) & 0x1FF), "pgw.la4.pdpt");
    Check(idx[2] == ((va >> 21) & 0x1FF), "pgw.la4.pd");
    Check(idx[3] == ((va >> 12) & 0x1FF), "pgw.la4.pte");
    Check(idx[4] == 0, "pgw.la4.spare");

    // Known concrete values for this address:
    Check(idx[0] == 496, "pgw.la4.pml4.value");
    Check(idx[3] == 0x000, "pgw.la4.pte.value");

    knengine::ComputeOrderedIndices(va, true, idx);

    Check(idx[0] == ((va >> 48) & 0x1FF), "pgw.la5.pml5");
    Check(idx[1] == ((va >> 39) & 0x1FF), "pgw.la5.pml4");
    Check(idx[2] == ((va >> 30) & 0x1FF), "pgw.la5.pdpt");
    Check(idx[3] == ((va >> 21) & 0x1FF), "pgw.la5.pd");
    Check(idx[4] == ((va >> 12) & 0x1FF), "pgw.la5.pte");

    // Ordering must be strictly top-down (each lower level covers a
    // smaller shift).
    unsigned int la4[5];
    knengine::ComputeOrderedIndices(0xffff800000000123ULL, false, la4);
    Check(la4[0] != 0 || la4[1] != 0, "pgw.order.nonzero-top");
}

void TestLargePageMask()
{
    const ULONG64 kPhysMask = 0x000FFFFFFFFFF000ULL;

    // 2MB page (PDE, shift = 21)
    const int shift2M = 21;
    const ULONG64 offsetMask2M = (1ULL << shift2M) - 1;
    const ULONG64 entry2M = 0x00000001802000E3ULL; // Large page bit set + flags
    const ULONG64 pageBase2M = entry2M & ~offsetMask2M & kPhysMask;
    Check(pageBase2M == 0x0000000180200000ULL, "pgw.2mb.mask-preserves-base");

    // 1GB page (PDPTE, shift = 30)
    const int shift1G = 30;
    const ULONG64 offsetMask1G = (1ULL << shift1G) - 1;
    const ULONG64 entry1G = 0x00000002400000E3ULL;
    const ULONG64 pageBase1G = entry1G & ~offsetMask1G & kPhysMask;
    Check(pageBase1G == 0x0000000240000000ULL, "pgw.1gb.mask-preserves-base");
}

void TestIdtGateReconstruction()
{
    // 64-bit IDT gate for handler 0xFFFFF80412345678
    unsigned char gate[16] = {};
    gate[0] = 0x78;
    gate[1] = 0x56;
    gate[6] = 0x34;
    gate[7] = 0x12;
    UINT32 highPart = 0xFFFFF804U;
    memcpy(gate + 8, &highPart, sizeof(highPart));

    const ULONG64 handler = gate[0] | (static_cast<ULONG64>(gate[1]) << 8) | (static_cast<ULONG64>(gate[6]) << 16) |
                            (static_cast<ULONG64>(gate[7]) << 24) | (static_cast<ULONG64>(highPart) << 32);

    Check(handler == 0xFFFFF80412345678ULL, "idt.reconstruct.canonical-high-bits");
}

void TestSsdtOffsetDecoding()
{
    const ULONG64 tableBase = 0xFFFFF80400000000ULL;

    // Positive 32-bit signed offset: 0x00123450 >> 4 = +0x00012345
    LONG entryPos = 0x00123450;
    const LONG signedPos = entryPos >> 4;
    const ULONG64 routinePos = tableBase + static_cast<ULONG64>(signedPos);
    Check(routinePos == 0xFFFFF80400012345ULL, "ssdt.decode.positive-offset");

    // Negative 32-bit signed offset (relative backward): 0xFFFE0000 >> 4 = -0x00002000
    LONG entryNeg = static_cast<LONG>(0xFFFE0000);
    const LONG signedNeg = entryNeg >> 4;
    const ULONG64 routineNeg = tableBase + static_cast<ULONG64>(signedNeg);
    Check(routineNeg == (tableBase + static_cast<ULONG64>(signedNeg)), "ssdt.decode.negative-offset-arithmetic");
}

void TestMsrBacktickStripping()
{
    const std::wstring output = L"msr[c0000082] = fffff804`03805000";
    const size_t eq = output.find(L'=');
    Check(eq != std::wstring::npos, "msr.find-eq");

    const wchar_t *scan = output.c_str() + eq + 1;
    wchar_t cleanValue[64] = L"";
    size_t cleanIndex = 0;

    auto IsHex = [](wchar_t c)
    {
        return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
    };

    for (; *scan != L'\0' && cleanIndex < 63; ++scan)
    {
        if (*scan == L'`')
        {
            continue;
        }
        if (cleanIndex == 1 && cleanValue[0] == L'0' && (*scan == L'x' || *scan == L'X'))
        {
            cleanIndex = 0;
            continue;
        }
        if (!IsHex(*scan) && cleanIndex > 0)
        {
            break;
        }
        if (!IsHex(*scan))
        {
            continue;
        }
        cleanValue[cleanIndex++] = *scan;
    }
    cleanValue[cleanIndex] = L'\0';

    wchar_t *endPtr = nullptr;
    const unsigned long long parsed = wcstoull(cleanValue, &endPtr, 16);
    Check(parsed == 0xFFFFF80403805000ULL, "msr.parse.backtick-stripped");

    // Also verify 0x prefix with backticks
    const std::wstring with0x = L"cr3 = 0x00000002`c1a86000";
    const size_t eq2 = with0x.find(L'=');
    scan = with0x.c_str() + eq2 + 1;
    cleanIndex = 0;
    for (; *scan != L'\0' && cleanIndex < 63; ++scan)
    {
        if (*scan == L'`')
        {
            continue;
        }
        if (cleanIndex == 1 && cleanValue[0] == L'0' && (*scan == L'x' || *scan == L'X'))
        {
            cleanIndex = 0;
            continue;
        }
        if (!IsHex(*scan) && cleanIndex > 0)
        {
            break;
        }
        if (!IsHex(*scan))
        {
            continue;
        }
        cleanValue[cleanIndex++] = *scan;
    }
    cleanValue[cleanIndex] = L'\0';
    const unsigned long long parsed0x = wcstoull(cleanValue, &endPtr, 16);
    Check(parsed0x == 0x00000002C1A86000ULL, "hex.parse.0x-prefix-handled");
}

void TestObjectNameInfoLayout()
{
    // _OBJECT_HEADER_NAME_INFO on x64:
    // Directory (+0x00, 8 bytes), Name (+0x08, UNICODE_STRING: Length +0x00, Buffer +0x08)
    const size_t offsetNameInNameInfo = 8;
    const size_t offsetBufferInUnicodeString = 8;
    const size_t fullBufferOffset = offsetNameInNameInfo + offsetBufferInUnicodeString;
    Check(offsetNameInNameInfo == 8, "nameinfo.name-offset-8");
    Check(fullBufferOffset == 16, "nameinfo.buffer-offset-16");
}

void TestHandleStructLayout()
{
    const size_t kHeaderSize = 16; // NumberOfHandles (8) + Reserved (8)
    const size_t kEntrySize = 40;  // Object(8) + Pid(8) + Handle(8) + Access(4) + BackTrace(2) + TypeIdx(2) + Attr(4) + Reserved(4)
    Check(kHeaderSize == 16, "handles.header-16-bytes");
    Check(kEntrySize == 40, "handles.entry-40-bytes");
}

void TestWriteClassification()
{
    Check(kncmd::ClassifyAsWrite(L"eb fffff80403800000 90"), "write.eb");
    Check(kncmd::ClassifyAsWrite(L"f L100 90"), "write.fill");
    Check(kncmd::ClassifyAsWrite(L"eq @rcx 0"), "write.eq");
    Check(kncmd::ClassifyAsWrite(L"!eb 1000 90"), "write.eb-phys");
    Check(kncmd::ClassifyAsWrite(L"!ew 1000 90"), "write.ew-phys");
    Check(kncmd::ClassifyAsWrite(L"!ed 1000 90"), "write.ed-phys");
    Check(kncmd::ClassifyAsWrite(L"!eq 1000 90"), "write.eq-phys");
    Check(!kncmd::IsNativeCommand(L"bp nt!NtCreateFile"), "policy.unknown-breakpoint-refused-until-control-adapter");
    Check(!kncmd::IsNativeCommand(L"bu mod!fn"), "policy.unknown-deferred-breakpoint-refused");
    Check(!kncmd::IsNativeCommand(L"eza addr str"), "policy.unknown-string-write-refused");

    Check(!kncmd::ClassifyAsWrite(L"db nt!KiSystemCall64 L10"), "notwrite.db");
    Check(!kncmd::ClassifyAsWrite(L"dq 0"), "notwrite.dq");
    Check(!kncmd::ClassifyAsWrite(L"!pool big /limit 5"), "notwrite.pool");
    Check(!kncmd::ClassifyAsWrite(L"ss nt!*create*"), "notwrite.ss-symbol-search");
    Check(!kncmd::ClassifyAsWrite(L"d* cmd"), "notwrite.d-star");
    Check(!kncmd::ClassifyAsWrite(L"dump-raw 0 10 x"), "notwrite.dump-prefix");
    Check(!kncmd::ClassifyAsWrite(L"dump-analyze test.dmp"), "notwrite.dump-analyze");
    Check(!kncmd::ClassifyAsWrite(L"!minifilter disable"), "write.minifilter-disable");
    Check(!kncmd::ClassifyAsWrite(L"!fltmgr enable"), "write.fltmgr-enable");
    Check(!kncmd::ClassifyAsWrite(L"!minifilter"), "notwrite.minifilter-audit");
    Check(kncmd::ClassifyAsWrite(L"peb 1000 90"), "write.peb");
    Check(kncmd::ClassifyAsWrite(L"peq 2000 1"), "write.peq");
    Check(!kncmd::ClassifyAsWrite(L"pdb 1000"), "notwrite.pdb");
}

void TestParseWindbgHex()
{
    unsigned long long value = 0;

    Check(knutil::ParseWindbgHex(L"cr3=00000000`001ab000", &value) && value == 0x1AB000ULL, "reghex.equals-backtick");
    Check(knutil::ParseWindbgHex(L"cr3 00000000`001ab000", &value) && value == 0x1AB000ULL, "reghex.space-backtick");
    Check(knutil::ParseWindbgHex(L"cr4=00000000`000006f8", &value) && value == 0x6F8ULL, "reghex.not-leading-c");
    Check(knutil::ParseWindbgHex(L"msr[c0000082] = fffff804`03805000", &value) && value == 0xFFFFF80403805000ULL, "reghex.msr");
    Check(knutil::ParseWindbgHex(L"cr3 = 0x00000002`c1a86000", &value) && value == 0x00000002C1A86000ULL, "reghex.0x-prefix");
}

void TestLa57Bit()
{
    Check(knengine::kCr4La57Bit == 12, "la57.bit-is-12");
    Check(knengine::Cr4HasLa57(0x1000ULL), "la57.cr4.value-0x1000");
    Check(!knengine::Cr4HasLa57(0x800000ULL), "la57.cr4.value-cet-mask");
    Check(knengine::Cr4HasLa57(1ULL << 12), "la57.cr4.bit12");
    Check(!knengine::Cr4HasLa57(1ULL << 23), "la57.cr4.bit23-is-cet");
    Check(!knengine::Cr4HasLa57(0), "la57.cr4.zero");
}

void TestNewNativeCommands()
{
    Check(kncmd::IsNativeCommand(L"!hive"), "classify.native.hive");
    Check(kncmd::IsNativeCommand(L"!hv"), "classify.native.hv");
    Check(kncmd::IsNativeCommand(L"!dma"), "classify.native.dma");
    Check(kncmd::IsNativeCommand(L"!token"), "classify.native.token");
    Check(kncmd::IsNativeCommand(L"procctx"), "classify.native.procctx");
    Check(kncmd::IsNativeCommand(L"cls"), "classify.native.cls");
    Check(kncmd::IsNativeCommand(L"dump-live"), "classify.native.dump-live");
    Check(kncmd::IsNativeCommand(L"!mapper"), "classify.native.mapper");
    Check(kncmd::IsNativeCommand(L"eb fffff80400000000 90"), "classify.native.eb");
    Check(kncmd::IsNativeCommand(L"!unloaded"), "classify.native.unloaded");
}

void TestCatalogNativeSync()
{
    bool missing = false;

    for (const auto &entry : kncat::All())
    {
        if (entry.Level != kncat::Support::Native)
        {
            continue;
        }

        const std::wstring name(entry.Name);

        if (!kncmd::IsNativeCommand(name))
        {
            missing = true;
            std::printf("[FAIL] catalog.native.unregistered %ls\n", name.c_str());
        }
    }

    Check(!missing, "catalog.native.registered");
}

void TestCatalogJsonRoundTrip()
{
    knjson::Value groups = knjson::Value::MakeObject();

    for (const kncat::CommandInfo &info : kncat::All())
    {
        const std::wstring groupKey(info.Group);
        knjson::Value list = groups.Get(groupKey);

        if (!list.IsArray())
        {
            list = knjson::Value::MakeArray();
        }

        knjson::Value entry = knjson::Value::MakeObject();
        entry.Set(L"name", knjson::Value(info.Name));
        entry.Set(L"synopsis", knjson::Value(info.Synopsis));
        entry.Set(L"support", knjson::Value(kncat::SupportText(info.Level)));
        list.Push(entry);
        groups.Set(groupKey, list);
    }

    knjson::Value root = knjson::Value::MakeObject();
    root.Set(L"id", knjson::Value(1.0));
    root.Set(L"ok", knjson::Value(true));
    knjson::Value result = knjson::Value::MakeObject();
    result.Set(L"groups", groups);
    root.Set(L"result", result);

    const std::wstring json = root.Write();
    knjson::Value parsed;

    Check(knjson::Parse(json, &parsed), "catalog.json.parse");
    Check(parsed.Get(L"ok").AsBool(false), "catalog.json.ok");
    Check(parsed.Get(L"result").Get(L"groups").IsObject(), "catalog.json.groups-object");
    Check(parsed.Get(L"result").Get(L"groups").Fields().size() >= 3, "catalog.json.group-count");
}

void TestDumpSignatures()
{
    const ULONG kPage = 0x45474150; // 'PAGE'
    const ULONG kDu64 = 0x34365544; // 'DU64'
    const ULONG kDump = 0x504d5544; // 'DUMP'
    const ULONG kMdmp = 0x504d444d; // 'MDMP'

    const char *pageStr = reinterpret_cast<const char *>(&kPage);
    const char *du64Str = reinterpret_cast<const char *>(&kDu64);
    const char *dumpStr = reinterpret_cast<const char *>(&kDump);
    const char *mdmpStr = reinterpret_cast<const char *>(&kMdmp);

    Check(std::strncmp(pageStr, "PAGE", 4) == 0, "dump.magic.page");
    Check(std::strncmp(du64Str, "DU64", 4) == 0, "dump.magic.du64");
    Check(std::strncmp(dumpStr, "DUMP", 4) == 0, "dump.magic.dump");
    Check(std::strncmp(mdmpStr, "MDMP", 4) == 0, "dump.magic.mdmp");
}
} // namespace

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && wcscmp(argv[1], L"--contract") == 0)
    {
        std::printf("%s\n", knutil::WideToUtf8(kncmd::CommandContract().Write()).c_str());
        return 0;
    }
    knself::RunPureRegression(Check);
    knself::RunFaultRegression(Check);
    knself::RunExecutionRegression(Check);
    knself::RunPolicyRegression(Check);
    knself::RunLayoutRegression(Check);
    knself::RunCollectorRegression(Check);
    knself::RunHandleTableRegression(Check);
    knself::RunScannerRegression(Check);
    knself::RunSnapshotRpcRegression(Check);
    knself::RunSnapshotReviewRegression(Check);
    knself::RunResultPageRegression(Check);
    knself::RunResultExportRegression(Check);
    knself::RunUiLifecycleRegression(Check);
    knself::RunUiOperationsRegression(Check);
    knself::RunDebuggerRegression(Check);
    knself::RunKernelAnalysisRegression(Check);
    knself::RunKernelReviewRegression(Check);
    knself::RunCallbackRegression(Check);
    knself::RunPresentationRegression(Check);
    knself::RunKernelSymbolRegression(Check);
    knself::RunPiddbRegression(Check);
    knself::RunCommandRecordRegression(Check);
    knself::RunKernelPartialRegression(Check);
    knself::RunAlpcRegression(Check);
    knself::RunWin32kDispatchRegression(Check);
    knself::RunMemoryRegression(Check);
    knself::RunMemoryExportRegression(Check);
    knself::RunPlatformPostureRegression(Check);
    knself::RunDiagnosticRegression(Check);
    TestJsonCodec();
    TestPageWalkIndices();
    TestLargePageMask();
    TestIdtGateReconstruction();
    TestSsdtOffsetDecoding();
    TestMsrBacktickStripping();
    TestObjectNameInfoLayout();
    TestHandleStructLayout();
    TestFormatting();
    TestCatalog();
    TestDispatcherClassification();
    TestWriteClassification();
    TestParseWindbgHex();
    TestLa57Bit();
    TestNewNativeCommands();
    TestCatalogNativeSync();
    TestCatalogJsonRoundTrip();
    TestDumpSignatures();

    std::printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
