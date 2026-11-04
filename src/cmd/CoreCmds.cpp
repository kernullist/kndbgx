// Native core commands: query (readability probe), vtop (annotated page
// walk) and the '?' expression evaluator.

#include "CmdTypes.h"

#include "../engine/PageWalk.h"
#include "../core/MemoryOperands.h"

namespace kncmd
{
namespace
{
std::wstring EntryLevelName(int index, bool la57)
{
    if (la57)
    {
        switch (index)
        {
        case 0:
            return L"pml5e";
        case 1:
            return L"pml4e";
        case 2:
            return L"pdpte";
        case 3:
            return L"pde";
        default:
            return L"pte";
        }
    }

    switch (index)
    {
    case 0:
        return L"pml4e";
    case 1:
        return L"pdpte";
    case 2:
        return L"pde";
    default:
        return L"pte";
    }
}
} // namespace

void ProbeQuery(Ctx &ctx)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;

    do
    {
        const auto operands = kncore::ParseMemoryOperands(ctx.Args,
                                                          [&](const std::wstring &text, uint64_t *value)
                                                          {
                                                              return EvalAddress(session, text, value);
                                                          });
        const auto length = operands.Extra.value_or(1);
        if (!operands.Error.empty() || length > 65536 || !kncore::ValidRange(operands.Address, length))
        {
            out.Fail(kncore::Status::InvalidInput,
                     L"[query] " + (operands.Error.empty() ? L"Length must be 1..65536 bytes without address overflow" : operands.Error));
            break;
        }
        const auto read = session.Read(kncore::AddressSpace::Virtual, operands.Address, static_cast<size_t>(length));
        out.Details.State = read.State;
        out.Details.Error = read.Error;
        auto &coverage = out.Details.Collected;
        coverage.Expected = length;
        coverage.Visited = length;
        coverage.Read = read.Transferred;
        coverage.Unreadable = length - read.Transferred;
        coverage.Complete = read.State == kncore::Status::Success;
        coverage.StopReason = coverage.Complete ? L"RequestedBytesRead" : L"MemoryReadIncomplete";
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"MemoryReadability"));
        row.Set(L"address", knjson::Value(kncore::Hex(operands.Address)));
        row.Set(L"requestedBytes", knjson::Value(std::to_wstring(length)));
        row.Set(L"readBytes", knjson::Value(std::to_wstring(read.Transferred)));
        row.Set(L"readable", knjson::Value(coverage.Complete));
        out.Details.Rows.Push(row);
        if (!coverage.Complete)
        {
            out.AddLine(L"[query] " + FmtAddr(operands.Address) + L" range not completely readable");
            break;
        }
        out.AddLine(L"[query] " + FmtAddr(operands.Address) + L" readable bytes=" + FmtDec(length));
    } while (false);
}

void TranslateVtop(Ctx &ctx)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;

    do
    {
        const auto operands = kncore::ParseMemoryOperands(ctx.Args,
                                                          [&](const std::wstring &text, uint64_t *value)
                                                          {
                                                              return EvalAddress(session, text, value);
                                                          });
        if (!operands.Error.empty())
        {
            out.Fail(kncore::Status::InvalidInput, L"[vtop] " + operands.Error);
            break;
        }
        const auto virtualAddress = operands.Address;
        ULONG64 cr3Value = 0;

        if (operands.Extra)
        {
            cr3Value = *operands.Extra;
        }
        else if (session.HasContextDtb())
        {
            cr3Value = session.ContextDtb();
        }
        else
        {
            if (!session.ReadRegisterHex(L"cr3", &cr3Value))
            {
                out.Fail(kncore::Status::Unavailable, L"[vtop] cannot read CR3");
                break;
            }
        }

        const bool la57 = knengine::DetectLa57(session);
        out.AddLine(L"[vtop] va=" + FmtAddr(virtualAddress));
        out.AddLine(std::wstring(L"[vtop] dtb=") + FmtAddr(cr3Value) + L" paging=" + (la57 ? L"PML5" : L"PML4"));

        knengine::PageWalkResult walk;
        out.Details.Limitations.Push(
            knjson::Value(L"Physical mask uses the x64 architectural maximum; target CPU physical width is not verified"));

        const bool translated = knengine::WalkVirtualToPhysical(session, virtualAddress, cr3Value, la57, &walk);
        out.Details.Rows.Push(knengine::PageWalkObservation(walk));
        if (!translated)
        {
            for (int i = 0; i < walk.LevelCount; ++i)
            {
                out.AddLine(L"[vtop] " + EntryLevelName(i, la57) + L"@0x" + FmtHexN(walk.EntrySlotPhysical[i], 8) + L" = 0x" +
                            FmtHexN(walk.EntryValue[i], 16));
            }

            out.Details.Collected.Visited = walk.LevelCount;
            out.Details.Collected.Read = walk.LevelCount;
            out.Details.Collected.StopReason = walk.Error;
            out.Fail(kncore::Status::Unavailable, L"[vtop] failed: " + walk.Error);
            break;
        }
        out.Details.Collected.Expected = walk.LevelCount;
        out.Details.Collected.Visited = walk.LevelCount;
        out.Details.Collected.Read = walk.LevelCount;
        out.Details.Collected.Decoded = walk.LevelCount;
        out.Details.Collected.Complete = true;
        out.Details.Collected.StopReason = L"TranslationObserved";

        for (int i = 0; i < walk.LevelCount; ++i)
        {
            std::wstring row = L"[vtop] " + EntryLevelName(i, la57) + L"@0x" + FmtHexN(walk.EntrySlotPhysical[i], 8) + L" = 0x" +
                               FmtHexN(walk.EntryValue[i], 16);

            if (walk.LargePage && i == walk.LargePageLevel)
            {
                row += L" <large-page>";
            }

            out.AddLine(row);
        }

        out.AddLine(std::wstring(L"[vtop] pa=") + FmtAddr(walk.PhysicalAddress) + L" pagesize=0x" + FmtHexN(walk.PageSize, 1) +
                    L" offset=0x" + FmtHexN(walk.OffsetInPage, 1));
        out.AddLine(std::wstring(L"[vtop] leaf writable=") + (walk.EffectiveWritable ? L"true" : L"false") + L" executable=" +
                    (walk.EffectiveExecutable ? L"true" : L"false"));
    } while (false);
}

void EvaluateExpression(Ctx &ctx)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;

    do
    {
        if (ctx.Args.size() != 2 || ctx.Args[1].find_first_of(L";{}\r\n") != std::wstring::npos)
        {
            out.Fail(kncore::Status::InvalidInput, L"[expr] usage: ? <expression>");
            break;
        }
        const std::wstring &expression = ctx.Args[1];

        ULONG64 value = 0;

        if (!session.Evaluate(expression, &value))
        {
            out.Fail(kncore::Status::InvalidInput, L"[expr] evaluation failed: " + expression);
            break;
        }

        const long long signed64 = static_cast<long long>(value);
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"ExpressionValue"));
        row.Set(L"expression", knjson::Value(expression));
        row.Set(L"value", knjson::Value(kncore::Hex(value)));
        row.Set(L"unsigned", knjson::Value(FmtDec(value)));
        row.Set(L"signed", knjson::Value(std::to_wstring(signed64)));
        out.Details.Rows.Push(row);
        out.Details.Collected.Visited = 1;
        out.Details.Collected.Decoded = 1;
        out.Details.Collected.Complete = true;
        out.Details.Collected.StopReason = L"ExpressionEvaluated";
        out.AddLine(L"[expr] " + expression + L" = 0x" + FmtHexN(value, 16) + L" (" + FmtDec(value) + L" / signed " +
                    std::to_wstring(signed64) + L")");
    } while (false);
}
} // namespace kncmd
