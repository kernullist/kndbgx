#include "CmdTypes.h"
#include "../util/FileReader.h"
#include "../util/MemoryExport.h"
#include "../core/MappedPe.h"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

#include "../engine/ModuleList.h"

namespace kncmd
{
void RecordDumpArtifact(Ctx &ctx, const std::wstring &path, uint64_t bytes, const wchar_t *format)
{
    auto &result = ctx.Out.Details;
    if (!result.Analysis.IsObject())
    {
        result.Analysis = knjson::Value::MakeObject();
    }
    result.Analysis.Set(L"artifactCommitted", knjson::Value(true));
    result.Analysis.Set(L"artifactPath", knjson::Value(path));
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"DumpArtifact"));
    row.Set(L"path", knjson::Value(path));
    row.Set(L"bytes", knjson::Value(std::to_wstring(bytes)));
    row.Set(L"format", knjson::Value(format));
    result.Rows.Push(row);
    result.Collected.Expected = bytes;
    result.Collected.Visited = bytes;
    result.Collected.Read = bytes;
    result.Collected.Complete = true;
    result.Collected.StopReason = L"ArtifactCommitted";
}

void AnalyzeDump(Ctx &ctx)
{
    do
    {
        if (ctx.Args.size() != 2)
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"[dump.error] usage: dump-analyze <quoted-path>");
            break;
        }
        knutil::FileReader file(ctx.Args[1]);
        if (!file.IsOpen())
        {
            ctx.Out.Fail(kncore::Status::IOError, L"[dump.error] open failed; Win32=" + FmtDec(file.Error()));
            break;
        }
        kncore::DumpMetadata metadata;
        const auto parsed = kncore::ParseDumpMetadata(file, &metadata);
        if (!parsed)
        {
            const auto state =
                file.Error() != ERROR_SUCCESS
                    ? kncore::Status::IOError
                    : (parsed.Status == kncore::BinaryStatus::Unsupported ? kncore::Status::Unsupported : kncore::Status::InvalidInput);
            ctx.Out.Fail(state, L"[dump.error] " + parsed.Error + L" Win32=" + FmtDec(file.Error()));
            break;
        }
        ctx.Out.AddLine(L"[dump.file] metadata-only; bytes=" + FmtDec(file.Size()));
        auto summary = knjson::Value::MakeObject();
        summary.Set(L"kind", knjson::Value(L"DumpMetadata"));
        summary.Set(L"path", knjson::Value(ctx.Args[1]));
        summary.Set(L"format", knjson::Value(metadata.Minidump ? L"Minidump" : L"KernelDump"));
        summary.Set(L"bytes", knjson::Value(FmtDec(file.Size())));
        summary.Set(L"architecture", knjson::Value(kncore::Hex(metadata.Architecture)));
        summary.Set(L"build", metadata.SystemAvailable ? knjson::Value(FmtDec(metadata.Build)) : knjson::Value());
        summary.Set(L"processors", metadata.SystemAvailable ? knjson::Value(FmtDec(metadata.Processors)) : knjson::Value());
        summary.Set(L"exceptionCode", metadata.ExceptionAvailable ? knjson::Value(kncore::Hex(metadata.ExceptionCode)) : knjson::Value());
        ctx.Out.Details.Rows.Push(summary);
        ctx.Out.AddLine(std::wstring(L"[dump.format] ") + (metadata.Minidump ? L"minidump" : L"kernel dump") + L" architecture=" +
                        FmtDec(metadata.Architecture));
        ctx.Out.AddLine(metadata.SystemAvailable ? L"[dump.os] build=" + FmtDec(metadata.Build) + L" cpus=" + FmtDec(metadata.Processors)
                                                 : L"[dump.os] unavailable");
        ctx.Out.AddLine(metadata.ExceptionAvailable
                            ? L"[dump.exception] code=" + FmtHex(metadata.ExceptionCode) + L" address=" + FmtAddr(metadata.ExceptionAddress)
                            : L"[dump.exception] unavailable");
        if (!metadata.Minidump)
        {
            ctx.Out.AddLine(L"[dump.cr3] " + FmtAddr(metadata.DirectoryTableBase));
            ctx.Out.AddLine(L"[dump.bugcheck] code=" + FmtHex(metadata.ExceptionCode));
        }
        for (const auto &module : metadata.Modules)
        {
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"DumpModule"));
            row.Set(L"name", knjson::Value(module.Name));
            row.Set(L"base", knjson::Value(kncore::Hex(module.Record.BaseOfImage)));
            row.Set(L"size", knjson::Value(FmtDec(module.Record.SizeOfImage)));
            row.Set(L"source", knjson::Value(L"DumpFileModuleList"));
            ctx.Out.Details.Rows.Push(row);
            ctx.Out.AddLine(L"[dump.mod] base=" + FmtAddr(module.Record.BaseOfImage) + L" size=" + FmtHex(module.Record.SizeOfImage) +
                            L" name=" + module.Name);
        }
        ctx.Out.AddLine(metadata.ModuleListAvailable ? L"[dump.modules] validated=" + FmtDec(metadata.Modules.size())
                                                     : L"[dump.modules] unavailable");
        auto &report = ctx.Out.Details;
        report.Source = L"HostDumpMetadata";
        report.Consistency = L"immutable-file";
        report.Collected.Visited = report.Rows.Items().size();
        report.Collected.Decoded = report.Collected.Visited;
        report.Collected.Complete = true;
        report.Collected.StopReason = L"DumpMetadataParsed";
        report.Limitations.Push(knjson::Value(L"File metadata only; module addresses belong to the captured dump. "
                                              L"Current target symbols are not applied to imported addresses."));
    } while (false);
}

void DumpLive(Ctx &ctx)
{
    ctx.Out.Fail(kncore::Status::Unsupported, L"[dump-live] privileged host dump creation is disabled in this build");
}

namespace
{
void ExportRange(Ctx &ctx, ULONG64 address, ULONG64 length, const std::wstring &path, bool physical, bool mappedImage)
{
    const auto exported = knutil::ExportMemoryRange(
        ctx.Session, physical ? kncore::AddressSpace::Physical : kncore::AddressSpace::Virtual, address, length, path,
        [&]()
        {
            return ctx.Session.Cancelled() || (ctx.RequestCancelled && ctx.RequestCancelled());
        },
        [&]()
        {
            return ctx.ExpectedStamp == nullptr || ctx.Session.RefreshStamp() == *ctx.ExpectedStamp;
        });
    auto &result = ctx.Out.Details;
    result.State = exported.State;
    result.Collected = exported.Collected;
    result.Analysis = knjson::Value::MakeObject();
    auto &analysis = result.Analysis;
    const wchar_t *format = mappedImage ? L"MappedPeImage" : physical ? L"PhysicalRange" : L"VirtualRange";
    const std::wstring command = mappedImage ? L"dump-pe" : L"dump-raw";
    analysis.Set(L"artifactCommitted", knjson::Value(false));
    analysis.Set(L"format", knjson::Value(format));
    analysis.Set(L"baseAddress", knjson::Value(kncore::Hex(address)));
    analysis.Set(L"requestedBytes", knjson::Value(std::to_wstring(length)));
    if (exported.State == kncore::Status::Success)
    {
        RecordDumpArtifact(ctx, exported.Path, exported.Written, format);
        ctx.Out.AddLine(L"[" + command + L"] committed=" + exported.Path + L" bytes=" + FmtDec(exported.Written));
    }
    else
    {
        const wchar_t *reason = exported.State == kncore::Status::Cancelled       ? L"cancelled"
                                : exported.State == kncore::Status::StaleContext  ? L"target context changed"
                                : exported.State == kncore::Status::InternalFault ? L"memory reader fault"
                                : exported.State == kncore::Status::EngineError   ? L"debugger engine error"
                                                                                  : L"memory read incomplete";
        std::wstring message = L"[" + command + L".error] " + (exported.Error.Message.empty() ? reason : exported.Error.Message) +
                               L"; output not committed; read=" + FmtDec(exported.Collected.Read) + L"/" + FmtDec(length);
        if (exported.ReadRequested != 0)
        {
            analysis.Set(L"readAddress", knjson::Value(kncore::Hex(exported.ReadAddress)));
            analysis.Set(L"readRequestedBytes", knjson::Value(std::to_wstring(exported.ReadRequested)));
            analysis.Set(L"readTransferredBytes", knjson::Value(std::to_wstring(exported.ReadTransferred)));
        }
        if (exported.FirstUnreadAddress)
        {
            const auto offset = *exported.FirstUnreadAddress - address;
            analysis.Set(L"firstUnreadAddress", knjson::Value(kncore::Hex(*exported.FirstUnreadAddress)));
            analysis.Set(L"firstUnreadOffset", knjson::Value(kncore::Hex(offset)));
            message += L" first-unread=" + FmtAddr(*exported.FirstUnreadAddress) + (mappedImage ? L" RVA=" : L" offset=") + FmtHex(offset);
        }
        ctx.Out.Fail(exported.State, message, exported.Error);
    }
}
} // namespace

void DumpRaw(Ctx &ctx)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;

    do
    {
        if (ctx.Args.size() < 4 || ctx.Args.size() > 5 || (ctx.Args.size() == 5 && _wcsicmp(ctx.Args[4].c_str(), L"/phys") != 0))
        {
            out.Fail(kncore::Status::InvalidInput, L"[dump-raw] usage: dump-raw <addr> <length> "
                                                   L"<path> [/phys]");
            break;
        }

        ULONG64 address = 0;
        ULONG64 length = 0;

        if (!EvalAddress(session, ctx.Args[1], &address) || !EvalAddress(session, ctx.Args[2], &length) || length == 0 ||
            length > 0x4000000ULL)
        {
            out.Fail(kncore::Status::InvalidInput, L"[dump-raw] invalid address or length "
                                                   L"(max 64MB)");
            break;
        }

        bool physical = false;

        for (size_t i = 4; i < ctx.Args.size(); ++i)
        {
            if (_wcsicmp(ctx.Args[i].c_str(), L"/phys") == 0)
            {
                physical = true;
            }
        }

        if (!kncore::ValidRange(address, length))
        {
            out.Fail(kncore::Status::InvalidInput, L"[dump-raw.error] address range overflow");
            break;
        }
        ExportRange(ctx, address, length, ctx.Args[3], physical, false);
    } while (false);
}

void DumpPe(Ctx &ctx)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;

    do
    {
        if (ctx.Args.size() != 3)
        {
            out.Fail(kncore::Status::InvalidInput, L"[dump-pe] usage: dump-pe <module|addr> <path>");
            break;
        }

        std::vector<knengine::KernelModuleInfo> modules;

        if (!knengine::EnumerateKernelModules(session, &modules))
        {
            out.Fail(kncore::Status::Unavailable, L"[dump-pe] module enumeration failed");
            break;
        }

        ULONG64 base = 0;
        ULONG size = 0;

        if (!EvalAddress(session, ctx.Args[1], &base))
        {
            for (const knengine::KernelModuleInfo &mod : modules)
            {
                if (_wcsicmp(mod.ModuleName.c_str(), ctx.Args[1].c_str()) == 0)
                {
                    if (size != 0)
                    {
                        base = 0;
                        size = 0;
                        break;
                    }
                    base = mod.Base;
                    size = mod.Size;
                }
            }
        }
        else
        {
            const knengine::KernelModuleInfo *owner = knengine::FindModuleForAddress(modules, base);

            if (owner != nullptr)
            {
                base = owner->Base;
                size = owner->Size;
            }
        }

        if (base == 0 || size == 0 || size > 64 * 1024 * 1024)
        {
            out.Fail(kncore::Status::Unavailable, L"[dump-pe] module not resolved or too large");
            break;
        }

        const auto headers = kncore::ReadMappedPeHeaders(session, base, size);
        if (headers.State != kncore::Status::Success)
        {
            out.Details.Collected.StopReason = L"PeHeadersUnavailable";
            out.Fail(headers.State, L"[dump-pe.error] " + headers.Message, headers.LastRead.Error);
            break;
        }
        out.Details.Limitations.Push(knjson::Value(L"Mapped image bytes; not a reconstructed disk PE"));
        out.AddLine(L"[dump-pe.format] mapped image; this is not a reconstructed disk PE");
        ExportRange(ctx, base, size, ctx.Args[2], false, true);
    } while (false);
}
} // namespace kncmd
