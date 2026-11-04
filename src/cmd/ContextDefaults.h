#pragma once

#include "CmdTypes.h"
#include "../core/DisplayCursor.h"

namespace kncmd
{
inline bool CurrentInstruction(Ctx &ctx, ULONG64 &address)
{
    if (!EvalAddress(ctx.Session, L"@$ip", &address))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Current instruction address unavailable");
        return false;
    }
    return true;
}

inline bool DisplayArguments(Ctx &ctx, kncore::DisplayKind kind, std::vector<std::wstring> &args)
{
    args = ctx.Args;
    uint64_t count = 0;
    // A length-only range also uses the remembered address.
    if (args.size() == 1 ||
        (args.size() == 2 && args[1].size() > 1 && towlower(args[1][0]) == L'l' && kncore::ParseUnsigned(args[1].substr(1), 16, &count)))
    {
        const auto remembered = kncore::DisplayCursors().Next(kind, ctx.Session.RefreshStamp(), ctx.Session.ContextDtb());
        ULONG64 address = remembered.value_or(0);
        if (!remembered && kind != kncore::DisplayKind::PhysicalMemory && !CurrentInstruction(ctx, address))
        {
            return false;
        }
        args.insert(args.begin() + 1, kncore::Hex(address));
    }
    return true;
}

inline void RememberDisplay(Ctx &ctx, kncore::DisplayKind kind, const kncore::SessionStamp &begin, uint64_t next)
{
    const auto end = ctx.Session.RefreshStamp();
    if (kncore::DisplayCursorStore::SameContext(begin, end) && ctx.Out.Details.State == kncore::Status::Success)
    {
        kncore::DisplayCursors().Remember(kind, end, ctx.Session.ContextDtb(), next);
    }
}
} // namespace kncmd
