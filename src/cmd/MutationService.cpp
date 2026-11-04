#include "MutationService.h"
#include "../util/Log.h"
#include "WriteGate.h"
#include "../core/MutationGrammar.h"
#include "../engine/ContextGuard.h"
#include "../engine/PageWalk.h"
#include "../engine/LayoutResolver.h"
#include <bcrypt.h>
#include <dbgeng.h>

namespace kncmd
{
class MutationAdapter final : public kncore::MutationTarget
{
  public:
    explicit MutationAdapter(knengine::DbgSession &session) : session_(session)
    {
    }
    kncore::SessionStamp CurrentStamp() override
    {
        return session_.RefreshStamp();
    }
    kncore::Status CheckWritable(uint64_t address, size_t bytes) override
    {
        if (knengine::Epochs().State() == kncore::SessionState::Faulted)
        {
            return kncore::Status::InternalFault;
        }
        knengine::SessionStatus status = {};
        session_.QueryStatus(&status);
        const auto identity = session_.RefreshStamp().Context;
        if (!status.Stopped || !status.TargetPresent || status.DumpFile || status.LocalKernel ||
            status.Architecture != IMAGE_FILE_MACHINE_AMD64 || session_.dataSpaces_ == nullptr || !identity.Complete() ||
            identity.EffectiveArchitecture != IMAGE_FILE_MACHINE_AMD64 || !knengine::SessionObserverReady())
        {
            knlog::Write(std::wstring(L"CheckWritable: refused — stopped=") + (status.Stopped ? L"1" : L"0") + L" present=" +
                         (status.TargetPresent ? L"1" : L"0") + L" dump=" + (status.DumpFile ? L"1" : L"0") + L" localKernel=" +
                         (status.LocalKernel ? L"1" : L"0") + L" arch=" + std::to_wstring(status.Architecture) + L" dataSpaces=" +
                         (session_.dataSpaces_ != nullptr ? L"1" : L"0") + L" identityComplete=" +
                         (identity.Complete() ? L"1" : L"0") + L" effArch=" + std::to_wstring(identity.EffectiveArchitecture.value_or(0)) +
                         L" observerReady=" + (knengine::SessionObserverReady() ? L"1" : L"0"));
            return kncore::Status::Unavailable;
        }
        if (!kncore::ValidRange(address, bytes))
        {
            return kncore::Status::InvalidInput;
        }
        uint64_t current = address;
        size_t remaining = bytes;
        while (remaining != 0)
        {
            MEMORY_BASIC_INFORMATION64 region = {};
            const HRESULT result = session_.dataSpaces_->QueryVirtual(current, &region);
            if (FAILED(result) || region.BaseAddress > current || region.RegionSize == 0 ||
                !kncore::ValidRange(region.BaseAddress, region.RegionSize) || current - region.BaseAddress >= region.RegionSize)
            {
                // QueryVirtual needs the debugger's VAD view, which live KD
                // targets do not always provide (the observed live-remote
                // refusal). Fall back to the verified page-table walk: the
                // page must be present and effectively writable through
                // every traversed entry.
                ULONG64 cr3 = 0;
                ULONG64 cr4 = 0;
                knengine::PageWalkResult walk;
                if (session_.ReadRegisterHex(L"cr3", &cr3) && session_.ReadRegisterHex(L"cr4", &cr4) &&
                    knengine::WalkVirtualToPhysical(session_, current, cr3, knengine::Cr4HasLa57(cr4), &walk) && walk.Ok &&
                    walk.Present && walk.EffectiveWritable)
                {
                    const size_t take = static_cast<size_t>(std::min<uint64_t>(remaining, 0x1000 - (current & 0xfff)));
                    remaining -= take;
                    current += take;
                    continue;
                }
                knlog::Write(L"CheckWritable: region query failed and page-table fallback did not verify writability");
                return kncore::Status::Unavailable;
            }
            if (region.State != MEM_COMMIT || (region.Type != MEM_PRIVATE && region.Type != MEM_IMAGE && region.Type != MEM_MAPPED) ||
                (region.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) != 0)
            {
                return kncore::Status::Unsupported;
            }
            const size_t take = static_cast<size_t>(std::min<uint64_t>(remaining, region.RegionSize - (current - region.BaseAddress)));
            remaining -= take;
            current += take;
        }
        return kncore::Status::Success;
    }
    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t bytes) override
    {
        return session_.Read(space, address, bytes);
    }
    kncore::TransferResult Write(uint64_t address, std::span<const unsigned char> bytes) override
    {
        struct Permit
        {
            bool &Flag;
            explicit Permit(bool &flag) : Flag(flag)
            {
                Flag = true;
                ++knengine::InternalContextDepth;
            }
            ~Permit()
            {
                Flag = false;
                --knengine::InternalContextDepth;
            }
        } permit(session_.approvedWrite_);
        return session_.TransferMemory(kncore::AddressSpace::Virtual, true, address, const_cast<unsigned char *>(bytes.data()),
                                       static_cast<ULONG>(bytes.size()));
    }
    bool Cancelled() const override
    {
        return session_.Cancelled();
    }
    kncore::Status ValidateIntent(const kncore::MutationIntent &intent) override
    {
        if (!intent.Field)
        {
            return kncore::Status::Success;
        }
        knengine::LayoutResolver layout(session_);
        const auto field = layout.Field(intent.ModuleName.c_str(), intent.TypeName.c_str(), intent.FieldName.c_str());
        const auto identity = layout.Identity(intent.ModuleName.c_str());
        return field && identity && identity->Key() == intent.LayoutProfile && field->SimpleWritable() &&
                       field->Offset == intent.Field->Offset && field->Size == intent.Field->Size && field->Kind == intent.Field->Kind
                   ? kncore::Status::Success
                   : kncore::Status::StaleContext;
    }

  private:
    knengine::DbgSession &session_;
};

kncore::MutationPlans &PlanStore()
{
    static kncore::MutationPlans plans;
    return plans;
}

namespace
{
std::wstring RandomToken()
{
    unsigned char bytes[24] = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        return {};
    }
    return kncore::BytesHex(bytes);
}
} // namespace

PreparedMutation PrepareMutation(knengine::DbgSession &session, const std::wstring &line)
{
    PreparedMutation prepared;
    ParsedCommand request;
    if (!ParseCommand(line, &request) || request.Spec == nullptr || !HasEffect(request.Spec->Effects, Effect::TargetMutation) ||
        request.Spec->Support == SupportLevel::Unsupported)
    {
        prepared.Result.State = kncore::Status::InvalidInput;
        prepared.Result.Error.Message = request.Error.empty() ? L"UnsupportedMutationForm" : request.Error;
        return prepared;
    }
    kncore::MutationIntent intent;
    const auto evaluate = [&](const std::wstring &expression, uint64_t *value)
    {
        if (expression.find_first_of(L";{}\r\n") != std::wstring::npos)
        {
            return false;
        }
        ULONG64 resolved = 0;
        const bool ok = EvalAddress(session, expression, &resolved);
        *value = resolved;
        return ok;
    };
    bool parsed = false;
    if (std::wstring(request.Spec->Name) == L"setfield")
    {
        const auto &typeName = request.Arguments[2];
        const auto separator = typeName.find(L'!');
        const auto module = separator == std::wstring::npos ? L"nt" : typeName.substr(0, separator);
        const auto type = separator == std::wstring::npos ? typeName : typeName.substr(separator + 1);
        knengine::LayoutResolver layout(session);
        const auto field = layout.Field(module.c_str(), type.c_str(), request.Arguments[3].c_str());
        const auto identity = layout.Identity(module.c_str());
        if (!field || !identity || !field->SimpleWritable())
        {
            prepared.Result.State = kncore::Status::Unsupported;
            prepared.Result.Error.Message = L"VerifiedScalarFieldRequired: bitfields, pointers and composite fields cannot be written";
            return prepared;
        }
        uint64_t base = 0;
        uint64_t value = 0;
        const auto &input = request.Arguments[4];
        const bool negative = !input.empty() && input[0] == L'-';
        const unsigned bits = field->Size * 8;
        const uint64_t signedLimit = uint64_t(1) << (bits - 1);
        parsed = evaluate(request.Arguments[1], &base) && kncore::ParseUnsigned(negative ? input.substr(1) : input, 16, &value) &&
                 kncore::ValidRange(base, static_cast<uint64_t>(field->Offset) + field->Size);
        if (field->Kind == kncore::FieldKind::Signed)
        {
            parsed = parsed && value <= (negative ? signedLimit : signedLimit - 1);
        }
        else
        {
            parsed = parsed && !negative && (bits == 64 || value < (uint64_t(1) << bits));
            if (field->Kind == kncore::FieldKind::Boolean)
            {
                parsed = parsed && value <= 1;
            }
        }
        if (parsed)
        {
            value = negative ? uint64_t(0) - value : value;
            intent.CommandId = L"setfield";
            intent.NormalizedArguments = request.RawArguments;
            intent.Address = base + field->Offset;
            intent.Desired.resize(field->Size);
            std::memcpy(intent.Desired.data(), &value, field->Size);
            intent.LayoutProfile = identity->Key();
            intent.Field = field;
            intent.ModuleName = module;
            intent.TypeName = type;
            intent.FieldName = request.Arguments[3];
        }
    }
    else
    {
        parsed = kncore::ParseMemoryMutation(request.Spec->Name, request.Arguments, request.Quoted, evaluate, &intent);
    }
    if (!parsed)
    {
        prepared.Result.State = kncore::Status::InvalidInput;
        prepared.Result.Error.Message = L"InvalidMutation: validate all values, widths, count and range before planning";
        return prepared;
    }
    MutationAdapter target(session);
    prepared.Result = PlanStore().Prepare(target, intent, RandomToken(), RandomToken(), &prepared.Plan);
    return prepared;
}

kncore::Result ExecuteApproved(knengine::DbgSession &session, const std::wstring &id, const std::wstring &token)
{
    MutationAdapter target(session);
    auto result = PlanStore().Execute(target, id, token);
    if (result.Collected.Read != 0)
    {
        knengine::Epochs().ContextChanged();
    }
    return result;
}

void MutationCommand(Ctx &context)
{
    if (context.Request == nullptr)
    {
        context.Out.Fail(kncore::Status::InvalidInput, L"Parsed mutation request required");
        return;
    }
    const std::wstring line = std::wstring(context.Request->Spec->Name) + L" " + context.Request->RawArguments;
    const auto prepared = PrepareMutation(context.Session, line);
    context.Out.Details = prepared.Result;
    if (prepared.Result.State == kncore::Status::Success)
    {
        context.Out.Details.Rows.Push(prepared.Plan.ToJson());
        context.Out.AddLine(L"[plan] complete preview; no target bytes written");
        context.Out.AddLine(prepared.Plan.ToJson().Write());
        context.Out.AddLine(L"[plan.approval] approve " + prepared.Plan.Id + L" " + prepared.Plan.ApprovalToken);
    }
    else
    {
        context.Out.Fail(prepared.Result.State, prepared.Result.Error.Message.empty()
                                                    ? L"Mutation planning unavailable for this target or memory range"
                                                    : prepared.Result.Error.Message);
    }
}
} // namespace kncmd
