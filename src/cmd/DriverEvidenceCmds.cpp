#include "CommandSpec.h"
#include "../core/DriverEvidence.h"
#include "../util/SnapshotStore.h"
#include <wintrust.h>
#include <softpub.h>

namespace kncmd
{
namespace
{
knjson::Value EmbeddedSignature(knutil::FileReader &file, const std::wstring &path)
{
    WINTRUST_FILE_INFO info = {};
    info.cbStruct = sizeof(info);
    info.pcwszFilePath = path.c_str();
    info.hFile = file.NativeHandle();
    WINTRUST_DATA trust = {};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &trust);
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"EmbeddedSignature"));
    row.Set(L"status", knjson::Value(kncore::Hex(static_cast<uint32_t>(status))));
    row.Set(L"interpretation", knjson::Value(status == ERROR_SUCCESS         ? L"TrustedByHostPolicyWithoutRevocation"
                                             : status == TRUST_E_NOSIGNATURE ? L"NoEmbeddedSignature"
                                                                             : L"NotTrustedOrUnavailable"));
    row.Set(L"trustedByHostOfflinePolicy", knjson::Value(status == ERROR_SUCCESS));
    row.Set(L"revocationChecked", knjson::Value(false));
    row.Set(L"catalogChecked", knjson::Value(false));
    row.Set(L"scope", knjson::Value(L"Host Authenticode trust with cached resources; kernel signing and target policy are not evaluated"));
    return row;
}
} // namespace

void DriverEvidenceCommand(Ctx &ctx)
{
    const bool sarif = std::wstring_view(ctx.Request->Spec->Name) == L"sarif-import";
    const auto &path = ctx.Args[1];
    knutil::FileReader file(path, true);
    const uint64_t maximum = sarif ? 16 * 1024 * 1024 : 64 * 1024 * 1024;
    if (!file.IsOpen() || file.Size() == 0 || file.Size() > maximum)
    {
        ctx.Out.Fail(kncore::Status::IOError, L"Input file is unavailable, empty, a reparse point, or over the size limit",
                     {L"Win32", file.Error(), L"OpenEvidence", path});
        return;
    }
    std::vector<unsigned char> bytes(static_cast<size_t>(file.Size()));
    for (size_t offset = 0; offset < bytes.size();)
    {
        if (ctx.Session.Cancelled())
        {
            ctx.Out.Fail(kncore::Status::Cancelled, L"File read cancelled");
            return;
        }
        const size_t length = std::min<size_t>(1024 * 1024, bytes.size() - offset);
        if (!file.Read(offset, std::span(bytes).subspan(offset, length)))
        {
            ctx.Out.Fail(kncore::Status::IOError, L"File read failed", {L"Win32", file.Error(), L"ReadEvidence", path});
            return;
        }
        offset += length;
    }
    const auto hash = knutil::Sha256Bytes(bytes);
    if (hash.empty())
    {
        ctx.Out.Fail(kncore::Status::IOError, L"Could not calculate the file SHA-256");
        return;
    }
    auto cancelled = [&ctx]()
    {
        return ctx.Session.Cancelled();
    };
    if (sarif)
    {
        std::wstring text;
        knjson::Value document;
        if (!knutil::StrictUtf8(bytes, text))
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"SARIF must be valid UTF-8");
            return;
        }
        if (!text.empty() && text.front() == 0xfeff)
        {
            text.erase(0, 1);
        }
        knjson::ParseLimits limits;
        limits.MaxNodes = 200000;
        if (!knjson::Parse(text, &document, limits))
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"SARIF JSON invalid or over parser budgets");
            return;
        }
        ctx.Out.Details = kncore::ImportSarif(document, cancelled);
    }
    else
    {
        ctx.Out.Details = kncore::AuditDriverPe(bytes, cancelled);
        if (ctx.Out.Details.State == kncore::Status::Success || ctx.Out.Details.State == kncore::Status::Partial)
        {
            ctx.Out.Details.Rows.Push(EmbeddedSignature(file, path));
            ctx.Out.Details.Limitations.Push(knjson::Value(
                L"Catalog signatures and revocation are not checked; a missing embedded signature does not imply an unsigned driver"));
        }
    }
    auto provenance = knjson::Value::MakeObject();
    provenance.Set(L"kind", knjson::Value(L"FileEvidence"));
    provenance.Set(L"path", knjson::Value(path));
    provenance.Set(L"sha256", knjson::Value(hash));
    provenance.Set(L"bytes", knjson::Value(std::to_wstring(bytes.size())));
    provenance.Set(L"targetAssociation", knjson::Value(L"Unverified; supplied host file"));
    ctx.Out.Details.Rows.Push(provenance);
    for (size_t i = 0; i < ctx.Out.Details.Rows.Items().size() && i < 256; ++i)
    {
        ctx.Out.AddLine(ctx.Out.Details.Rows.Items()[i].Write());
    }
    for (size_t i = 0; i < ctx.Out.Details.Findings.Items().size() && i < 128; ++i)
    {
        ctx.Out.AddLine(L"[finding] " + ctx.Out.Details.Findings.Items()[i].Write());
    }
    ctx.Out.AddLine(L"[findings] count=" + std::to_wstring(ctx.Out.Details.Findings.Items().size()));
    if (!ctx.Out.Details.Error.Message.empty())
    {
        ctx.Out.AddLine(ctx.Out.Details.Error.Message);
    }
    ctx.Out.AddLine(L"[file] rows=" + std::to_wstring(ctx.Out.Details.Rows.Items().size()) + L" status=" +
                    kncore::StatusName(ctx.Out.Details.State));
}
} // namespace kncmd
