// Native memory display commands: d/db/dw/dd/dq/dp/dc/da/du and the
// dds/dps/dqs symbol-annotated family, plus the physical-memory variants
// !db/!dw/!dd/!dq.

#include "CmdTypes.h"
#include "ContextDefaults.h"
#include "../core/Input.h"
#include "../core/MemoryString.h"
#include "../core/MemoryView.h"

#include <cstring>
#include <cwctype>

namespace kncmd
{
namespace
{
const ULONG64 kMaxDisplayBytes = 0x10000;
const size_t kMaxStringBytes = 4096;

wchar_t AsciiChar(unsigned char ch)
{
    if (ch >= 0x20 && ch < 0x7F)
    {
        return static_cast<wchar_t>(ch);
    }

    return L'.';
}

std::wstring BytesToAscii(const unsigned char *bytes, size_t count, bool valid)
{
    std::wstring text;

    for (size_t i = 0; i < count; ++i)
    {
        if (valid)
        {
            text += AsciiChar(bytes[i]);
        }
        else
        {
            text += L'?';
        }
    }

    return text;
}

void AppendUnreadableHex(std::wstring *row, int unitBytes)
{
    static const wchar_t *const patterns[9] = {L"", L"??", L"????", L"", L"????????", L"", L"", L"", L"????????????????"};

    row->append(patterns[unitBytes]);
    row->push_back(L' ');
}

// Renders one row of unit-sized values with optional ASCII gutter.
bool UnitValid(const unsigned char *validMask, size_t byteOffset, int unit, size_t available)
{
    if (byteOffset + static_cast<size_t>(unit) > available)
    {
        return false;
    }

    if (validMask != nullptr)
    {
        for (int b = 0; b < unit; ++b)
        {
            if (validMask[byteOffset + b] == 0)
            {
                return false;
            }
        }
    }

    return true;
}

void RenderRow(int unit, ULONG64 rowAddress, const unsigned char *data, size_t available, const unsigned char *validMask, size_t rowUnits,
               bool asciiGutter, bool symbolAnnotate, bool dwordAsciiMode, knengine::DbgSession &session, std::wstring *out)
{
    *out = FmtAddr(rowAddress) + L"  ";
    for (size_t i = 0; i < rowUnits; ++i)
    {
        const size_t byteOffset = i * unit;
        const bool valid = UnitValid(validMask, byteOffset, unit, available);

        if (!valid)
        {
            AppendUnreadableHex(out, unit);
            continue;
        }

        ULONG64 value = 0;

        switch (unit)
        {
        case 1:
            value = data[byteOffset];
            break;
        case 2:
            value = data[byteOffset] | (static_cast<ULONG64>(data[byteOffset + 1]) << 8);
            break;
        case 4:
            value = data[byteOffset] | (static_cast<ULONG64>(data[byteOffset + 1]) << 8) |
                    (static_cast<ULONG64>(data[byteOffset + 2]) << 16) | (static_cast<ULONG64>(data[byteOffset + 3]) << 24);
            break;
        default:
            for (int b = 7; b >= 0; --b)
            {
                value = (value << 8) | data[byteOffset + b];
            }
            break;
        }

        const int digits = unit == 1 ? 2 : unit == 2 ? 4 : unit == 4 ? 8 : 16;
        wchar_t valueText[32] = L"";
        swprintf_s(valueText, L"%0*llx", digits, value);
        *out += valueText;
        out->push_back(L' ');

        if (unit == 4 && dwordAsciiMode)
        {
            *out += L"'" + BytesToAscii(data + byteOffset, 4, true) + L"' ";
        }

        if (symbolAnnotate && value != 0 && (unit == 4 || unit == 8))
        {
            const std::wstring sym = AnnotateSymbol(session, value);

            if (!sym.empty())
            {
                *out += L" " + sym;
            }
        }

        // Group separator after every 8 bytes.
        if ((i + 1) % 8 == 0 && i + 1 < rowUnits)
        {
            out->push_back(L'-');
        }
    }

    if (asciiGutter && unit == 1)
    {
        std::wstring gutter;

        for (size_t i = 0; i < rowUnits; ++i)
        {
            const bool readableByte = UnitValid(validMask, i, 1, available);
            gutter += readableByte ? AsciiChar(data[i]) : L'?';
        }

        *out += L"  " + gutter;
    }

    // Trim trailing spaces for clean logs.
    while (!out->empty() && out->back() == L' ')
    {
        out->pop_back();
    }
}
} // namespace

void DisplayMemory(Ctx &ctx, int unitBytes, bool asciiGutter, bool dwordAsciiMode, bool symbolAnnotate, bool physical)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;
    const std::wstring tag = physical ? L"[pmemory]" : L"[memory]";

    do
    {
        const auto kind = physical ? kncore::DisplayKind::PhysicalMemory : kncore::DisplayKind::VirtualMemory;
        std::vector<std::wstring> args;
        if (!DisplayArguments(ctx, kind, args))
        {
            break;
        }

        ULONG64 start = 0;
        ULONG64 length = 0;
        std::wstring errorText;

        const ULONG64 defaultLength = unitBytes >= 8 ? 0x40 : 0x80;

        if (!ParseDisplayRange(session, args, 1, defaultLength, kMaxDisplayBytes, &start, &length, &errorText,
                               static_cast<unsigned>(unitBytes)))
        {
            out.Fail(kncore::Status::InvalidInput, tag + L" " + errorText);
            break;
        }

        const size_t totalBytes = static_cast<size_t>(length);
        const auto begin = session.RefreshStamp();
        const auto capture = session.MemoryCaptureInfo();
        auto attempts = knjson::Value::MakeArray();

        std::vector<unsigned char> buffer(totalBytes + 16, 0);
        std::vector<unsigned char> valid(totalBytes + 16, 0);
        size_t readable = 0;
        auto &coverage = out.Details.Collected;
        coverage.Expected = totalBytes;

        for (size_t offset = 0; offset < totalBytes;)
        {
            const ULONG64 addr = start + offset;
            ULONG chunk = 0x1000 - static_cast<ULONG>(addr & 0xFFFULL);

            if (chunk == 0)
            {
                chunk = 0x1000;
            }

            if (offset + chunk > totalBytes)
            {
                chunk = static_cast<ULONG>(totalBytes - offset);
            }

            const auto read = session.Read(physical ? kncore::AddressSpace::Physical : kncore::AddressSpace::Virtual, addr, chunk);
            attempts.Push(kncore::MemoryReadAttempt(read));
            if (read.State != kncore::Status::Success && read.State != kncore::Status::Partial && read.State != kncore::Status::Unavailable)
            {
                out.Fail(read.State, tag + L" read stopped", read.Error);
                break;
            }
            coverage.Visited += chunk;
            std::copy_n(read.Bytes.begin(), chunk, buffer.begin() + offset);
            std::copy_n(read.Valid.begin(), chunk, valid.begin() + offset);
            readable += read.Transferred;
            if (read.State != kncore::Status::Success)
            {
                out.Details.Error = read.Error;
                out.Details.State = kncore::Status::Partial;
            }

            offset += chunk;
        }
        coverage.Read = readable;
        coverage.Decoded = readable;
        coverage.Unreadable = coverage.Visited - readable;
        coverage.Complete = readable == totalBytes && out.Details.State == kncore::Status::Success;
        coverage.StopReason = coverage.Complete ? L"RequestedBytesRead" : L"MemoryReadIncomplete";
        out.Details.Analysis = knjson::Value::MakeObject();
        out.Details.Analysis.Set(L"memoryRead", kncore::MemoryReadEvidence(start,
            physical ? kncore::AddressSpace::Physical : kncore::AddressSpace::Virtual, totalBytes, readable, attempts, capture));
        out.Details.Rows = symbolAnnotate && !physical
                               ? kncore::MemoryPointerRows(start, unitBytes, {buffer.data(), totalBytes}, {valid.data(), totalBytes})
                               : kncore::MemoryByteRows(start, physical ? kncore::AddressSpace::Physical : kncore::AddressSpace::Virtual,
                                                         {buffer.data(), totalBytes}, {valid.data(), totalBytes});

        if (readable == 0)
        {
            const auto state = out.Details.State == kncore::Status::Partial ? kncore::Status::Unavailable : out.Details.State;
            out.Fail(state, tag + L" unreadable range at " + FmtAddr(start), out.Details.Error);
            break;
        }

        out.AddLine((physical ? tag + L" phys=" + FmtAddr(start) : tag + L" start=" + FmtAddr(start)) + L" length=0x" + FmtHexN(length, 1) +
                    L" read=0x" + FmtHexN(static_cast<ULONG64>(readable), 1));

        const size_t rowBytes = 16;
        ULONG64 addressCursor = start;

        for (size_t consumed = 0; consumed < totalBytes; consumed += rowBytes)
        {
            const size_t thisRow = (totalBytes - consumed) < rowBytes ? (totalBytes - consumed) : rowBytes;

            std::wstring row;
            RenderRow(unitBytes, addressCursor, buffer.data() + consumed, thisRow, valid.data() + consumed,
                      (thisRow + unitBytes - 1) / unitBytes, asciiGutter, symbolAnnotate, dwordAsciiMode, session, &row);
            out.AddLine(row);
            addressCursor += thisRow;
        }
        if (length <= UINT64_MAX - start)
        {
            RememberDisplay(ctx, kind, begin, start + length);
        }
    } while (false);
}

void DisplayString(Ctx &ctx, bool utf16)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;
    const std::wstring tag = utf16 ? L"[wstr]" : L"[astr]";

    do
    {
        std::vector<std::wstring> args;
        if (!DisplayArguments(ctx, kncore::DisplayKind::VirtualMemory, args))
        {
            break;
        }

        ULONG64 start = 0;
        ULONG64 length = 0;
        std::wstring error;
        const bool bounded = args.size() == 3;
        if (bounded && (args[2].size() < 2 || towlower(args[2][0]) != L'l'))
        {
            out.Fail(kncore::Status::InvalidInput, tag + L" string count must use L<count>");
            break;
        }
        if (!ParseDisplayRange(session, args, 1, kMaxStringBytes, kMaxStringBytes, &start, &length, &error, utf16 ? 2 : 1))
        {
            out.Fail(kncore::Status::InvalidInput, tag + L" " + error);
            break;
        }

        const auto begin = session.RefreshStamp();
        const auto read = session.Read(kncore::AddressSpace::Virtual, start, static_cast<size_t>(length));
        if (read.State != kncore::Status::Success && read.State != kncore::Status::Partial && read.State != kncore::Status::Unavailable)
        {
            out.Fail(read.State, tag + L" read stopped", read.Error);
            break;
        }
        auto &coverage = out.Details.Collected;
        coverage.Expected = length;
        if (read.Transferred == 0)
        {
            coverage.Visited = length;
            coverage.Unreadable = length;
            coverage.StopReason = L"UnreadableString";
            out.Fail(kncore::Status::Unavailable, tag + L" unreadable at " + FmtAddr(start), read.Error);
            break;
        }
        const auto decoded = kncore::DecodeMemoryString(std::span(read.Bytes).first(read.Transferred), utf16);
        coverage.Expected = decoded.Terminated ? decoded.Consumed : length;
        coverage.Visited = coverage.Expected;
        coverage.Read = decoded.Consumed;
        coverage.Decoded = decoded.Consumed;
        coverage.Unreadable = coverage.Expected - decoded.Consumed;
        coverage.Unknown = decoded.InvalidUnits + (!bounded && !decoded.Terminated && read.Transferred == length ? 1 : 0);
        coverage.Complete = (decoded.Terminated || (bounded && read.Transferred == length)) && decoded.InvalidUnits == 0;
        coverage.StopReason = decoded.InvalidUnits != 0            ? L"InvalidUtf16"
                              : decoded.Terminated                 ? L"StringTerminator"
                              : read.Transferred < length          ? L"UnreadableStringTail"
                              : bounded                            ? L"RequestedCharactersRead"
                                                                   : L"StringLimit";
        out.Details.State = coverage.Complete ? kncore::Status::Success : kncore::Status::Partial;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"MemoryString"));
        row.Set(L"address", knjson::Value(kncore::Hex(start)));
        row.Set(L"encoding", knjson::Value(utf16 ? L"UTF-16LE" : L"ASCII with escaped bytes"));
        row.Set(L"text", knjson::Value(decoded.Text));
        row.Set(L"bytesRead", knjson::Value(std::to_wstring(read.Transferred)));
        row.Set(L"bytesExamined", knjson::Value(std::to_wstring(decoded.Consumed)));
        row.Set(L"terminated", knjson::Value(decoded.Terminated));
        row.Set(L"invalidUnits", knjson::Value(std::to_wstring(decoded.InvalidUnits)));
        out.Details.Rows.Push(row);
        out.AddLine(tag + L" " + (decoded.Text.empty() ? L"(empty)" : decoded.Text));
        if (decoded.Consumed <= UINT64_MAX - start)
        {
            RememberDisplay(ctx, kncore::DisplayKind::VirtualMemory, begin, start + decoded.Consumed);
        }
    } while (false);
}

void FillMemoryCmd(Ctx &ctx)
{
    ctx.Out.Fail(kncore::Status::Unavailable, L"PlanApprovalRequired");
}

void WriteVirtualMemory(Ctx &ctx, int)
{
    ctx.Out.Fail(kncore::Status::Unavailable, L"PlanApprovalRequired");
}

void WritePhysicalMemory(Ctx &ctx, int)
{
    ctx.Out.Fail(kncore::Status::Unsupported, L"PhysicalWriteDisabled");
}
} // namespace kncmd
