#include "CollectorSupport.h"
#include "../core/CallbackLayout.h"
#include "../core/CallbackRows.h"

namespace kncmd
{
namespace
{
const wchar_t *ProfileName(knengine::LayoutResolver &layout)
{
    const auto identity = layout.Identity(L"nt");
    return identity ? kncore::CallbackProfileName(*identity) : kncore::CallbackProfileId;
}

std::wstring CallbackProfileStatus(Ctx &ctx, knengine::LayoutResolver &layout, kncore::CallbackFamily family)
{
    const auto identity = layout.Identity(L"nt");
    return identity ? kncore::VerifyCallbackProfile(ctx.Session, *identity, family,
                                                    [&](const wchar_t *symbol)
                                                    {
                                                        return SymbolAddress(ctx.Session, layout, L"nt", symbol);
                                                    })
                    : L"NoMatchedKernelIdentity";
}

void NotifyTable(Ctx &ctx, knengine::LayoutResolver &layout, kncore::WalkBudget &budget, const kncore::TargetArchitecture &architecture,
                 const kncore::OwnershipIndex &owners, kncore::CallbackFamily family)
{
    const auto *name = kncore::NotifyTableName(family);
    const auto address = SymbolAddress(ctx.Session, layout, L"nt", name);
    auto table = layout.Symbol(L"nt", name);
    const auto references = layout.Field(L"nt", L"_EX_FAST_REF", L"RefCnt");
    auto function = layout.Field(L"nt", L"_EX_CALLBACK_ROUTINE_BLOCK", L"Function");
    auto context = layout.Field(L"nt", L"_EX_CALLBACK_ROUTINE_BLOCK", L"Context");
    if (!address || !architecture.KernelPointer(*address))
    {
        UnknownScope(ctx, budget, name, L"Table symbol unavailable");
        return;
    }
    std::wstring profileStatus = L"MatchedPdbLayout";
    if (!table || !function || !context)
    {
        profileStatus = CallbackProfileStatus(ctx, layout, family);
        if (profileStatus == L"Verified" &&
            ((!table && !layout.PublicOnlySymbol(L"nt", name)) ||
             !layout.CanProfileField(L"nt", L"_EX_CALLBACK_ROUTINE_BLOCK", L"Function") ||
             !layout.CanProfileField(L"nt", L"_EX_CALLBACK_ROUTINE_BLOCK", L"Context") ||
             (table && (!kncore::NotifyTableValid(table, *address) || table->ArrayCount != 64u)) ||
             (function && (function->Offset != 8 || function->Size != 8 || function->BitOffset || function->BitWidth)) ||
             (references && references->BitWidth && (references->BitOffset != 0u || references->BitWidth != 4u)) ||
             (context && (context->Offset != 16 || context->Size != 8 || context->BitOffset || context->BitWidth))))
        {
            profileStatus = L"CallbackProfileMetadataConflict";
        }
        if (profileStatus == L"Verified")
        {
            if (!table)
            {
                table = kncore::CallbackProfileTable(ProfileName(layout));
            }
            if (!function)
            {
                function = kncore::CallbackProfileField(8, 8, ProfileName(layout));
            }
            if (!context)
            {
                context = kncore::CallbackProfileField(16, 8, ProfileName(layout));
            }
        }
    }
    if (!kncore::NotifyTableValid(table, *address) || profileStatus == L"CallbackProfileMetadataConflict")
    {
        UnknownScope(ctx, budget, name, L"Table extent unavailable: " + profileStatus + L"; raw first slot only");
        uint64_t raw = 0;
        const bool read = ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *address, &raw);
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"RawSymbolObservation"));
        row.Set(L"symbol", knjson::Value(name));
        row.Set(L"address", knjson::Value(kncore::Hex(*address)));
        row.Set(L"rawFirstSlot", read ? knjson::Value(kncore::Hex(raw)) : knjson::Value());
        if (!read)
        {
            ++budget.Report.Collected.Unreadable;
        }
        EmitRow(ctx, budget, row);
        return;
    }
    auto tableRow = knjson::Value::MakeObject();
    tableRow.Set(L"kind", knjson::Value(L"CallbackTable"));
    tableRow.Set(L"family", knjson::Value(name));
    tableRow.Set(L"address", knjson::Value(kncore::Hex(*address)));
    tableRow.Set(L"slots", knjson::Value(std::to_wstring(*table->ArrayCount)));
    tableRow.Set(L"layoutSource", knjson::Value(table->Source));
    tableRow.Set(L"verification", knjson::Value(profileStatus));
    EmitRow(ctx, budget, tableRow);
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    budget.Report.Collected.Expected += *table->ArrayCount;
    for (uint32_t i = 0; i < *table->ArrayCount && CheckCollection(ctx, budget); ++i)
    {
        ++budget.Report.Collected.Visited;
        const uint64_t slot = *address + static_cast<uint64_t>(i) * 8;
        const auto observed = kncore::ReadNotifyCallback(ctx.Session, architecture, slot, references, function, context);
        if (observed.Raw)
        {
            ++budget.Report.Collected.Read;
        }
        if (observed.Raw == 0)
        {
            ++budget.Report.Collected.Decoded;
            continue;
        }
        if (observed.Unreadable)
        {
            ++budget.Report.Collected.Unreadable;
        }
        if (std::wstring_view(observed.Reason) == L"Decoded")
        {
            ++budget.Report.Collected.Decoded;
        }
        auto row = kncore::RoutineObservation(budget.Report, architecture, owners, name, slot, observed.Routine);
        const auto type = family == kncore::CallbackFamily::Process ? L"Notify.Process"
                          : family == kncore::CallbackFamily::Thread ? L"Notify.Thread" : L"Notify.Image";
        row.Set(L"callbackType", knjson::Value(type));
        row.Set(L"flags", kncore::OptionalNumber(observed.Context, true));
        if (!observed.Context)
        {
            ++budget.Report.Collected.Unknown;
        }
        row.Set(L"flagsMeaning", knjson::Value(L"Notify registration context; fast-reference count bits are excluded"));
        row.Set(L"rawFastRef", kncore::OptionalNumber(observed.Raw, true));
        row.Set(L"block", kncore::OptionalNumber(observed.Block, true));
        row.Set(L"decode", knjson::Value(observed.Reason));
        row.Set(L"layoutSource", function ? knjson::Value(function->Source) : knjson::Value());
        budget.Report.Rows.Push(row);
    }
}

void ObjectCallbacks(Ctx &ctx, knengine::LayoutResolver &layout, kncore::WalkBudget &budget, const kncore::TargetArchitecture &architecture,
                     const kncore::OwnershipIndex &owners)
{
    const auto callbacks = layout.Field(L"nt", L"_OBJECT_TYPE", L"CallbackList");
    const auto nameField = layout.Field(L"nt", L"_OBJECT_TYPE", L"Name");
    auto links = layout.Field(L"nt", L"_OB_CALLBACK_ENTRY_ITEM", L"CallbackList");
    auto operations = layout.Field(L"nt", L"_OB_CALLBACK_ENTRY_ITEM", L"Operations");
    auto pre = layout.Field(L"nt", L"_OB_CALLBACK_ENTRY_ITEM", L"PreOperation");
    auto post = layout.Field(L"nt", L"_OB_CALLBACK_ENTRY_ITEM", L"PostOperation");
    const auto canProfile = [&](const wchar_t *type)
    {
        return layout.CanProfileField(L"nt", type, L"CallbackList") && layout.CanProfileField(L"nt", type, L"Operations") &&
               layout.CanProfileField(L"nt", type, L"PreOperation") && layout.CanProfileField(L"nt", type, L"PostOperation");
    };
    const wchar_t *entryType = L"_OB_CALLBACK_ENTRY_ITEM";
    if (!links && !operations && !pre && !post && canProfile(entryType))
    {
        entryType = L"_CALLBACK_ENTRY_ITEM";
        links = layout.Field(L"nt", L"_CALLBACK_ENTRY_ITEM", L"CallbackList");
        operations = layout.Field(L"nt", L"_CALLBACK_ENTRY_ITEM", L"Operations");
        pre = layout.Field(L"nt", L"_CALLBACK_ENTRY_ITEM", L"PreOperation");
        post = layout.Field(L"nt", L"_CALLBACK_ENTRY_ITEM", L"PostOperation");
    }
    std::optional<kncore::FieldInfo> entryObjectType;
    std::optional<kncore::FieldInfo> active;
    std::wstring profileStatus = L"MatchedPdbLayout";
    if (!links || !operations || !pre || !post)
    {
        profileStatus = CallbackProfileStatus(ctx, layout, kncore::CallbackFamily::Object);
        if (profileStatus == L"Verified" &&
            (!canProfile(entryType) || !kncore::ApplyObjectCallbackProfile(links, operations, pre, post, ProfileName(layout))))
        {
            profileStatus = L"CallbackProfileMetadataConflict";
        }
        if (profileStatus == L"Verified")
        {
            entryObjectType = kncore::CallbackProfileField(0x20, 8, ProfileName(layout));
            active = kncore::CallbackProfileField(0x14, 4, ProfileName(layout));
        }
    }
    const bool decoded =
        links && links->Size == 16 && operations && operations->Size == 4 && pre && pre->Size == 8 && post && post->Size == 8;
    if (!callbacks || callbacks->Size != 16 || !nameField)
    {
        UnknownScope(ctx, budget, L"Object callbacks", L"Object type list layout unavailable");
        return;
    }
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    for (const auto &named :
         {std::pair(L"PsProcessType", L"Process"), std::pair(L"PsThreadType", L"Thread"), std::pair(L"ExDesktopObjectType", L"Desktop")})
    {
        if (!CheckCollection(ctx, budget))
        {
            break;
        }
        const auto symbol = SymbolAddress(ctx.Session, layout, L"nt", named.first);
        uint64_t object = 0;
        std::wstring actualName;
        if (!symbol || !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *symbol, &object) || !architecture.KernelPointer(object) ||
            !kncore::ValidRange(object, std::max(static_cast<uint64_t>(nameField->Offset) + nameField->Size,
                                                 static_cast<uint64_t>(callbacks->Offset) + callbacks->Size)) ||
            !ReadUnicodeString(ctx.Session, layout, object + nameField->Offset, &actualName) || actualName != named.second)
        {
            UnknownScope(ctx, budget, named.first, L"Object type identity not corroborated");
            continue;
        }
        const auto before = budget.Report.Collected.Visited;
        const bool walked = kncore::WalkList(
            ctx.Session, object + callbacks->Offset, architecture, budget,
            [&](uint64_t node)
            {
                if (!decoded)
                {
                    auto row = kncore::ObjectCallbackRegistration(budget.Report, architecture, owners, named.second, node,
                                                                    std::nullopt, std::nullopt, std::nullopt);
                    row.Set(L"listEntry", knjson::Value(kncore::Hex(node)));
                    row.Set(L"reason", knjson::Value(L"Callback entry fields unavailable: " + profileStatus));
                    budget.Report.Rows.Push(row);
                    return kncore::VisitDecision::Continue;
                }
                if (node < links->Offset)
                {
                    return kncore::VisitDecision::Failed;
                }
                const auto entry = node - links->Offset;
                if (!architecture.KernelPointer(entry))
                {
                    return kncore::VisitDecision::Failed;
                }
                const auto ops = kncore::ReadField(ctx.Session, entry, operations);
                const auto registeredType = kncore::ReadField(ctx.Session, entry, entryObjectType);
                if (entryObjectType && registeredType != object)
                {
                    UnknownScope(ctx, budget, named.second, L"Callback entry object type does not match its list");
                    if (!registeredType)
                    {
                        ++budget.Report.Collected.Unreadable;
                    }
                    return kncore::VisitDecision::Continue;
                }
                const auto enabled = kncore::ReadField(ctx.Session, entry, active);
                const auto preRoutine = kncore::ReadField(ctx.Session, entry, pre);
                const auto postRoutine = kncore::ReadField(ctx.Session, entry, post);
                if (active && (!enabled || *enabled > 1))
                {
                    ++budget.Report.Collected.Unknown;
                    if (!enabled)
                    {
                        ++budget.Report.Collected.Unreadable;
                    }
                }
                if (!ops)
                {
                    ++budget.Report.Collected.Unreadable;
                }
                auto row = kncore::ObjectCallbackRegistration(budget.Report, architecture, owners, named.second, entry,
                                                               preRoutine, postRoutine, ops);
                row.Set(L"listEntry", knjson::Value(kncore::Hex(node)));
                row.Set(L"layoutSource", knjson::Value(pre->Source));
                row.Set(L"active", enabled && *enabled <= 1 ? knjson::Value(*enabled != 0) : knjson::Value());
                if (!preRoutine)
                {
                    ++budget.Report.Collected.Unreadable;
                }
                if (!postRoutine)
                {
                    ++budget.Report.Collected.Unreadable;
                }
                budget.Report.Rows.Push(row);
                return kncore::VisitDecision::Continue;
            });
        if (walked)
        {
            budget.Report.Collected.Expected += budget.Report.Collected.Visited - before;
        }
    }
}

void RegistryCallbacks(Ctx &ctx, knengine::LayoutResolver &layout, kncore::WalkBudget &budget,
                       const kncore::TargetArchitecture &architecture, const kncore::OwnershipIndex &owners)
{
    const auto profileStatus = CallbackProfileStatus(ctx, layout, kncore::CallbackFamily::Registry);
    const auto head = SymbolAddress(ctx.Session, layout, L"nt", L"CallbackListHead");
    const auto countAddress = SymbolAddress(ctx.Session, layout, L"nt", L"CmpCallBackCount");
    if (profileStatus != L"Verified" || !head || !countAddress)
    {
        UnknownScope(ctx, budget, L"Registry callbacks", L"Registry registration layout unavailable: " + profileStatus);
        return;
    }
    uint32_t declared = 0;
    const bool countRead = ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *countAddress, &declared);
    if (countRead)
    {
        budget.Report.Collected.Expected += declared;
    }
    else
    {
        ++budget.Report.Collected.Unreadable;
    }
    const auto before = budget.Report.Collected.Visited;
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    const bool walked = kncore::WalkList(
        ctx.Session, *head, architecture, budget,
        [&](uint64_t entry)
        {
            const auto observed = kncore::ReadProfiledRegistryCallback(ctx.Session, architecture, entry);
            auto row = kncore::RoutineObservation(budget.Report, architecture, owners, L"Registry", entry, observed.Routine);
            row.Set(L"callbackType", knjson::Value(L"Registry"));
            row.Set(L"flags", observed.Flags ? knjson::Value(kncore::Hex(*observed.Flags)) : knjson::Value());
            row.Set(L"flagsMeaning", knjson::Value(L"Registry registration flags; unregistering is a separate reference-state bit"));
            row.Set(L"layoutSource", knjson::Value(ProfileName(layout)));
            row.Set(L"context", kncore::OptionalNumber(observed.Context, true));
            row.Set(L"cookie", kncore::OptionalNumber(observed.Cookie, true));
            row.Set(L"unregistering", observed.References ? knjson::Value((*observed.References & 0x80000000u) != 0) : knjson::Value());
            std::wstring altitude;
            const bool altitudeRead = kncore::ValidRange(entry, 0x40) && ReadUnicodeString(ctx.Session, layout, entry + 0x30, &altitude);
            row.Set(L"altitude", altitudeRead ? knjson::Value(altitude) : knjson::Value());
            if (!altitudeRead)
            {
                ++budget.Report.Collected.Unreadable;
                ++budget.Report.Collected.Unknown;
            }
            if (observed.Unreadable)
            {
                ++budget.Report.Collected.Unreadable;
            }
            budget.Report.Rows.Push(row);
            return kncore::VisitDecision::Continue;
        });
    uint32_t after = 0;
    if (walked && (!countRead || !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *countAddress, &after) || declared != after ||
                   budget.Report.Collected.Visited - before != declared))
    {
        UnknownScope(ctx, budget, L"Registry callbacks", L"Registry callback count did not corroborate the completed list");
    }
}
} // namespace

void ScanCallbacks(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:NotifyObjectAndRegistryCallbacks"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    for (const auto family : {kncore::CallbackFamily::Process, kncore::CallbackFamily::Thread, kncore::CallbackFamily::Image})
    {
        if (!budget.Stopped && !ctx.Session.Cancelled())
        {
            NotifyTable(ctx, layout, budget, architecture, owners, family);
        }
    }
    if (CheckCollection(ctx, budget))
    {
        ObjectCallbacks(ctx, layout, budget, architecture, owners);
    }
    if (CheckCollection(ctx, budget))
    {
        RegistryCallbacks(ctx, layout, budget, architecture, owners);
    }
    FinishCollection(ctx, budget);
    kncore::SeparateCallbackDiagnostics(ctx.Out.Details);
    for (const auto &row : ctx.Out.Details.Rows.Items())
    {
        ctx.Out.AddLine(row.Write());
    }
    ctx.Out.Details.Limitations.Push(knjson::Value(L"Callback symbols load owning PDBs on demand after traversal. Missing or rejected "
                                                  L"names retain module+RVA provenance; native symbol loads must return before cancellation."));
}
} // namespace kncmd
