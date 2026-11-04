#pragma once

#include "../cmd/CommandSpec.h"
#include "../cmd/Dispatcher.h"
#include "../cmd/Jobs.h"
#include "../core/MutationGrammar.h"
#include <set>

namespace knself
{
class PlanTarget final : public kncore::MutationTarget
{
  public:
    std::vector<unsigned char> Memory = std::vector<unsigned char>(65536, 0x31);
    kncore::SessionStamp Stamp{L"fixture", 1, 1, 1, 1};
    size_t Reads = 0;
    size_t Writes = 0;
    size_t FailWriteAt = SIZE_MAX;
    size_t ChangeStampAtWrite = SIZE_MAX;
    bool PartialRead = false;
    bool Stopped = true;
    bool Cancellation = false;
    bool CorruptVerification = false;
    std::chrono::seconds Elapsed{0};
    std::chrono::seconds ReadDelay{0};
    std::chrono::seconds WriteDelay{0};

    std::chrono::steady_clock::time_point Now() const override
    {
        return std::chrono::steady_clock::time_point{} + Elapsed;
    }

    kncore::SessionStamp CurrentStamp() override
    {
        return Stamp;
    }
    kncore::Status CheckWritable(uint64_t, size_t) override
    {
        return Stopped ? kncore::Status::Success : kncore::Status::Unavailable;
    }
    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t count) override
    {
        ++Reads;
        Elapsed += ReadDelay;
        kncore::ReadResult result;
        result.Space = space;
        result.Address = address;
        result.Requested = count;
        if (address < 0x1000 || address - 0x1000 > Memory.size() || count > Memory.size() - (address - 0x1000))
        {
            result.State = kncore::Status::Unavailable;
            return result;
        }
        result.Bytes.assign(Memory.begin() + address - 0x1000, Memory.begin() + address - 0x1000 + count);
        result.Transferred = PartialRead ? count - 1 : count;
        result.Valid.assign(count, 1);
        if (PartialRead)
        {
            result.Valid.back() = 0;
        }
        if (CorruptVerification && Writes != 0)
        {
            result.Bytes[0] ^= 0xff;
        }
        result.State = PartialRead ? kncore::Status::Partial : kncore::Status::Success;
        return result;
    }
    kncore::TransferResult Write(uint64_t address, std::span<const unsigned char> bytes) override
    {
        ++Writes;
        Elapsed += WriteDelay;
        const size_t count = Writes == FailWriteAt ? 3 : bytes.size();
        std::copy_n(bytes.begin(), count, Memory.begin() + address - 0x1000);
        if (Writes == ChangeStampAtWrite)
        {
            ++Stamp.StopEpoch;
        }
        return kncore::TransferStatus(bytes.size(), count, Writes == FailWriteAt ? E_FAIL : S_OK);
    }
    bool Cancelled() const override
    {
        return Cancellation;
    }
};

template <typename Check> void RunPolicyRegression(Check check)
{
    kncmd::ParsedCommand parsed;
    bool defaultsAccepted = true;
    for (const auto *command : {L"!threads", L"!token", L"!vad", L"!process", L"db", L"dw", L"dd", L"dq", L"dc", L"dds",
                               L"dqs", L"da", L"du", L"!db", L"!dw", L"!dd", L"!dq", L"u", L"source", L"ln", L"uf"})
    {
        defaultsAccepted = kncmd::ParseCommand(command, &parsed) && parsed.Positionals.empty() && defaultsAccepted;
    }
    check(defaultsAccepted, "policy.current-context-defaults-accepted");
    check(kncmd::ParseCommand(L"ln nt+1", &parsed) && kncmd::ParseCommand(L"uf @$ip", &parsed) &&
              !kncmd::ParseCommand(L"ln nt extra", &parsed) && !kncmd::ParseCommand(L"uf nt extra", &parsed),
          "policy.symbol-defaults-preserve-explicit-address-and-arity");
    check(kncmd::ParseCommand(L"!vad /limit 1 /exec", &parsed) && parsed.Positionals.empty() &&
              kncmd::ParseCommand(L"!vad /limit 1 pid:4 /exec", &parsed) && parsed.Positionals == std::vector<std::wstring>{L"pid:4"},
          "policy.options-do-not-become-process-selectors");
    check(kncmd::ParseCommand(L"!threads ethread:ffff800000001000", &parsed) && kncmd::ParseCommand(L"!process 0", &parsed) &&
              !kncmd::ParseCommand(L"!threads pid:4 extra", &parsed) && !kncmd::ParseCommand(L"!drvobj", &parsed),
          "policy.explicit-selector-and-required-object-boundaries");
    check(kncmd::ParseCommand(L"pdb 1000 L10", &parsed) && parsed.Spec == kncmd::FindCommand(L"!db"), "policy.alias-canonical-identity");
    check(!kncmd::ParseCommand(L"!minifilter disable", &parsed) && !kncmd::ParseCommand(L"!fltmgr enable", &parsed),
          "policy.removed-minifilter-mutations-rejected");
    check(!kncmd::ParseCommand(L"db 1000; eb 2000 90", &parsed), "policy.compound-typed-input-rejected");
    check(!kncmd::ParseCommand(L"!vad 123 /unknown", &parsed) && !kncmd::ParseCommand(L"!vad 123 /limit", &parsed),
          "policy.option-contract-enforced");
    check(kncmd::ParseCommand(L"raw --ack-effects .echo a; .echo b", &parsed) &&
              kncmd::HasEffect(parsed.Spec->Effects, kncmd::Effect::OpaqueEngine),
          "policy.explicit-raw-effects");
    check(!kncmd::ParseCommand(L"gateway on", &parsed), "policy.no-command-prefix-match");
    check(kncmd::ParseCommand(L"dump-analyze \"C:\\test;file.dmp\"", &parsed), "policy.quoted-path-not-compound");
    check(kncmd::FindCommand(L"!eb")->Support == kncmd::SupportLevel::Unsupported, "policy.physical-writes-default-unsupported");
    std::set<std::wstring> names;
    bool unique = true;
    for (const auto &spec : kncmd::CommandSpecs())
    {
        unique = names.insert(spec.Name).second && spec.Handler != nullptr && unique;
        for (const auto *alias : spec.Aliases)
        {
            unique = names.insert(alias).second && kncmd::FindCommand(alias) == &spec && unique;
        }
    }
    check(unique, "policy.single-registry-alias-handler-contract");
    // Kernel dump vs live kernel availability recorded in the registry.
    bool modesValid = true;
    for (const auto &spec : kncmd::CommandSpecs())
    {
        const auto modes = kncmd::EffectiveTargetModes(spec);
        const bool targetDependent = spec.Requires != kncmd::Capability::None && spec.Requires != kncmd::Capability::Engine;
        modesValid = modesValid && (targetDependent ? modes != kncmd::TargetMode::Any : modes == kncmd::TargetMode::Any);
    }
    check(modesValid, "policy.target-mode-coverage-recorded");
    check(kncmd::EffectiveTargetModes(*kncmd::FindCommand(L"eb")) == kncmd::TargetMode::LiveKernel &&
              kncmd::EffectiveTargetModes(*kncmd::FindCommand(L"debug-approve")) == kncmd::TargetMode::LiveKernel &&
              kncmd::EffectiveTargetModes(*kncmd::FindCommand(L"!pool")) == kncmd::TargetMode::LiveKernel,
          "policy.mutation-execution-local-collectors-live-kernel-only");
    check(kncmd::EffectiveTargetModes(*kncmd::FindCommand(L"db")) == kncmd::TargetMode::DumpAndLive &&
              kncmd::EffectiveTargetModes(*kncmd::FindCommand(L"!callbacks")) == kncmd::TargetMode::DumpAndLive,
          "policy.read-only-inspection-dump-and-live");
    check(kncmd::EffectiveTargetModes(*kncmd::FindCommand(L"help")) == kncmd::TargetMode::Any,
          "policy.host-command-mode-independent");
    // Mutation and execution control can never run against a read-only dump.
    bool mutationsLiveOnly = true;
    for (const auto &spec : kncmd::CommandSpecs())
    {
        if (kncmd::HasEffect(spec.Effects, kncmd::Effect::TargetMutation) ||
            kncmd::HasEffect(spec.Effects, kncmd::Effect::ExecutionControl))
        {
            mutationsLiveOnly = mutationsLiveOnly && kncmd::EffectiveTargetModes(spec) == kncmd::TargetMode::LiveKernel;
        }
    }
    check(mutationsLiveOnly, "policy.mutation-execution-always-live-kernel");
    // Display names distinguish remote-capable live-only commands from
    // host-machine collectors that refuse remote live targets.
    check(kncmd::TargetModeDisplayName(*kncmd::FindCommand(L"help")) == L"Any" &&
              kncmd::TargetModeDisplayName(*kncmd::FindCommand(L"db")) == L"DumpAndLive" &&
              kncmd::TargetModeDisplayName(*kncmd::FindCommand(L"eb")) == L"LiveKernel",
          "policy.mode-display-names");
    check(kncmd::TargetModeDisplayName(*kncmd::FindCommand(L"!hiddenproc")) == L"LiveKernelLocal" &&
              kncmd::TargetModeDisplayName(*kncmd::FindCommand(L"!handles")) == L"LiveKernelLocal" &&
              kncmd::TargetModeDisplayName(*kncmd::FindCommand(L"!pool")) == L"LiveKernel",
          "policy.mode-display-local-kernel-collectors");
    knengine::DbgSession unconnected;
    const auto commandSchema = kncmd::DispatchCommand(unconnected, L"command-schema");
    const auto legacySchema = kncmd::DispatchCommand(unconnected, L"CoNtRaCt");
    check(commandSchema.Ok && legacySchema.Ok && commandSchema.Output == legacySchema.Output &&
              commandSchema.Data.Rows.Items().size() == kncmd::CommandSpecs().size() &&
              kncmd::FindCommand(L"command-schema") == kncmd::FindCommand(L"contract") &&
              kncmd::DetachedCommand(kncmd::FindCommand(L"command-schema")),
          "policy.command-schema-keeps-legacy-input-and-detached-dispatch");
    check(kncmd::CommandContract().Write().find(L"contract") == std::wstring::npos &&
              kncmd::DispatchCommand(unconnected, L"help ui").Output.find(L"evidence") == std::wstring::npos,
          "policy.command-list-and-workspace-help-use-current-labels");
    const auto unknown = kncmd::DispatchCommand(unconnected, L"unregistered-write 1000 90");
    check(!unknown.Ok && unknown.Data.State == kncore::Status::Unsupported, "policy.unknown-never-reaches-engine");
    const auto removed = kncmd::DispatchCommand(unconnected, L"!minifilter disable");
    check(!removed.Ok && removed.Data.State == kncore::Status::InvalidInput, "policy.removed-mutation-product-dispatch");
    // Every registry entry renders an explicit session-availability tag, and
    // host-machine collectors are distinguished from remote-capable live-only
    // commands.
    bool tagged = true;
    for (const auto &spec : kncmd::CommandSpecs())
    {
        const auto single = kncmd::DispatchCommand(unconnected, std::wstring(L"help ") + spec.Name);
        const bool has = single.Output.find(L"[kernel: dump+live]") != std::wstring::npos ||
                         single.Output.find(L"[kernel: live only") != std::wstring::npos ||
                         single.Output.find(L"[kernel: dump only]") != std::wstring::npos ||
                         single.Output.find(L"[session: any]") != std::wstring::npos;
        tagged = tagged && has;
    }
    check(tagged, "policy.help-tags-every-command-with-session-availability");
    const auto localOnly = kncmd::DispatchCommand(unconnected, L"help !hiddenproc");
    check(localOnly.Output.find(L"[kernel: live only, local KD]") != std::wstring::npos,
          "policy.help-distinguishes-local-kernel-collectors");
    const auto unknownHelp = kncmd::DispatchCommand(unconnected, L"help definitely-not-a-command");
    check(unknownHelp.Data.State == kncore::Status::Unsupported &&
              unknownHelp.Output.find(L"Unknown command: definitely-not-a-command") != std::wstring::npos,
          "policy.help-unknown-operand-refuses-explicitly");
    ULONG written = 99;
    unsigned char byte = 0;
    check(!unconnected.WriteVirtual(0x1000, &byte, 1, &written) && written == 0, "policy.engine-rejects-write-without-permit");

    const auto eval = [](const std::wstring &input, uint64_t *value)
    {
        return kncore::ParseUnsigned(input, 16, value);
    };
    kncore::MutationIntent intent;
    check(!kncore::ParseMemoryMutation(L"eb", {L"eb", L"1000", L"41", L"invalid"}, {false, false, false, false}, eval, &intent),
          "plan.invalid-last-value-has-no-intent");
    check(!kncore::ParseMemoryMutation(L"eb", {L"eb", L"1000", L"100"}, {false, false, false}, eval, &intent),
          "plan.width-overflow-rejected");
    check(!kncore::ParseMemoryMutation(L"eq", {L"eq", L"fffffffffffffffc", L"1"}, {false, false, false}, eval, &intent),
          "plan.address-overflow-rejected");
    check(kncore::ParseMemoryMutation(L"f", {L"f", L"1000", L"L7", L"01"}, {false, false, false, true}, eval, &intent) &&
              intent.Desired == std::vector<unsigned char>({'0', '1', '0', '1', '0', '1', '0'}),
          "plan.quoted-numeric-ascii-preserved");
    check(!kncore::ParseMemoryMutation(L"f", {L"f", L"1000", L"L10", L""}, {false, false, false, true}, eval, &intent),
          "plan.empty-fill-rejected");

    const auto now = std::chrono::steady_clock::now();
    intent = {L"f", L"normalized", 0x1000, std::vector<unsigned char>(8193, 0x42)};
    kncore::MutationPlans plans;
    kncore::MutationPlan plan;
    PlanTarget target;
    auto prepared = plans.Prepare(target, intent, L"one", L"secret", &plan, now);
    check(prepared.State == kncore::Status::Success && target.Writes == 0 && plan.Original.size() == 8193 &&
              plan.ToJson().Get(L"after").AsString(L"").size() == 16386,
          "plan.complete-preview-does-not-write");
    check(plans.Execute(target, L"one", L"wrong", now).State == kncore::Status::InvalidInput && target.Writes == 0,
          "plan.token-bound-to-server-plan");
    const auto applied = plans.Execute(target, L"one", L"secret", now);
    check(applied.State == kncore::Status::Success && target.Writes == 3 && applied.Collected.Read == 8193 &&
              applied.Collected.Decoded == 8193 && applied.Collected.Complete,
          "plan.all-chunks-applied-and-verified");
    check(plans.Execute(target, L"one", L"secret", now).State == kncore::Status::InvalidInput && target.Writes == 3,
          "plan.approval-single-use");

    for (unsigned scenario = 0; scenario < 8; ++scenario)
    {
        PlanTarget changed;
        plans.Prepare(changed, intent, L"stale", L"token", &plan, now);
        auto executeTime = now;
        switch (scenario)
        {
        case 0:
            ++changed.Stamp.TargetGeneration;
            break;
        case 1:
            ++changed.Stamp.StopEpoch;
            break;
        case 2:
            ++changed.Stamp.ContextGeneration;
            break;
        case 3:
            ++changed.Stamp.SymbolGeneration;
            break;
        case 4:
            changed.Stamp.SessionId = L"replacement";
            break;
        case 5:
            changed.Memory[0] ^= 1;
            break;
        case 6:
            executeTime += std::chrono::seconds(61);
            break;
        case 7:
            changed.PartialRead = true;
            break;
        }
        const auto stale = plans.Execute(changed, L"stale", L"token", executeTime);
        check(stale.State == kncore::Status::StaleContext && changed.Writes == 0, "plan.stale-or-unreadable-writes-zero");
    }
    PlanTarget running;
    for (unsigned scenario = 0; scenario < 4; ++scenario)
    {
        PlanTarget changed;
        plans.Prepare(changed, intent, L"identity", L"token", &plan, now);
        if (scenario == 0)
        {
            changed.Stamp.Context.ImplicitProcess = 0x12345000;
        }
        else if (scenario == 1)
        {
            changed.Stamp.Context.ImplicitThread = 0x22345000;
        }
        else if (scenario == 2)
        {
            changed.Stamp.Context.EffectiveArchitecture = 0x14c;
        }
        else
        {
            changed.Stamp.Context.ScopeIndex = 1;
        }
        check(plans.Execute(changed, L"identity", L"token", now).State == kncore::Status::StaleContext && changed.Writes == 0,
              "rereview.plan-context-identity-change-writes-zero");
    }
    plans.Prepare(running, intent, L"run", L"token", &plan, now);
    running.Stopped = false;
    check(plans.Execute(running, L"run", L"token", now).State == kncore::Status::Unavailable && running.Writes == 0,
          "plan.running-target-writes-zero");
    PlanTarget partial;
    plans.Prepare(partial, intent, L"partial", L"token", &plan, now);
    partial.FailWriteAt = 2;
    const auto failed = plans.Execute(partial, L"partial", L"token", now);
    check(failed.State == kncore::Status::Partial && partial.Writes == 2 && failed.Collected.Read == 4099 && !failed.Collected.Complete,
          "plan.partial-write-exact-applied-ranges-no-retry");
    PlanTarget badVerify;
    plans.Prepare(badVerify, intent, L"verify", L"token", &plan, now);
    badVerify.CorruptVerification = true;
    const auto unverified = plans.Execute(badVerify, L"verify", L"token", now);
    check(unverified.State == kncore::Status::Partial && badVerify.Writes == 1 && unverified.Collected.Decoded == 0,
          "plan.readback-mismatch-stops-next-write");
    PlanTarget cancelled;
    plans.Prepare(cancelled, intent, L"cancel", L"token", &plan, now);
    cancelled.Cancellation = true;
    check(plans.Execute(cancelled, L"cancel", L"token", now).State == kncore::Status::Cancelled && cancelled.Writes == 0,
          "plan.cancel-before-write");
    PlanTarget changedAfterFinalWrite;
    plans.Prepare(changedAfterFinalWrite, intent, L"final", L"token", &plan, now);
    changedAfterFinalWrite.ChangeStampAtWrite = 3;
    const auto staleFinal = plans.Execute(changedAfterFinalWrite, L"final", L"token", now);
    check(staleFinal.State == kncore::Status::StaleContext && staleFinal.Collected.Read == 8193 && !staleFinal.Collected.Complete,
          "plan.context-after-final-write-invalidates-verification");
    PlanTarget slowPrepare;
    slowPrepare.ReadDelay = std::chrono::seconds(60);
    check(plans.Prepare(slowPrepare, intent, L"slow-prepare", L"token", &plan, now).State == kncore::Status::StaleContext &&
              plans.Execute(slowPrepare, L"slow-prepare", L"token", now).State == kncore::Status::InvalidInput,
          "review.plan-expiring-during-preview-is-not-published");
    PlanTarget slowRead;
    plans.Prepare(slowRead, intent, L"slow-read", L"token", &plan, now);
    slowRead.ReadDelay = std::chrono::seconds(60);
    check(plans.Execute(slowRead, L"slow-read", L"token", now).State == kncore::Status::StaleContext && slowRead.Writes == 0,
          "review.plan-expiring-during-recheck-writes-zero");
    PlanTarget slowWrite;
    plans.Prepare(slowWrite, intent, L"slow-write", L"token", &plan, now);
    slowWrite.WriteDelay = std::chrono::seconds(60);
    const auto timedOut = plans.Execute(slowWrite, L"slow-write", L"token", now);
    check(timedOut.State == kncore::Status::StaleContext && slowWrite.Writes == 1 && timedOut.Collected.Read == 4096 &&
              !timedOut.Collected.Complete,
          "review.plan-expiring-after-chunk-stops-following-writes");
}
} // namespace knself
