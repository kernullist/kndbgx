#include "CmdUtil.h"
#include "../engine/SymbolQuery.h"
#include "../core/Input.h"
#include "../core/ObjectRead.h"
#include "../core/ResultPresentation.h"
#include "ProcCollect.h"

#include <dbgeng.h>

#include <cwctype>
#include <map>

#include "../util/Text.h"
#include "../engine/ModuleList.h"

namespace kncmd
{
namespace
{
wchar_t Lower(wchar_t ch)
{
    return static_cast<wchar_t>(std::towlower(ch));
}

struct AddressSymbol
{
    std::wstring Text;
    std::wstring Source = L"Unavailable";
    std::optional<uint64_t> Displacement;
};

AddressSymbol ResolveAddressSymbol(knengine::DbgSession &session, ULONG64 address,
                                   const knengine::KernelModuleInfo *module, bool resolveName, bool loadDeferred = true,
                                   kncore::SymbolAddressCache *bindings = nullptr)
{
    AddressSymbol result;
    if (address == 0)
    {
        result.Source = L"NullAddress";
    }
    else if (module != nullptr && !module->ModuleName.empty())
    {
        result.Text = kncore::ModuleAddressLabel(module->ModuleName, address - module->Base);
        result.Source = L"ModuleRva";
        auto *symbols = session.Symbols();
        bool queryName = resolveName && symbols != nullptr;
        if (queryName)
        {
            // Module inventory bases do not justify loading every module's PDB.
            // NONE records an unavailable symbol set; do not retry it for every address.
            DEBUG_MODULE_PARAMETERS parameters = {};
            ULONG64 base = module->Base;
            queryName = symbols->GetModuleParameters(1, &base, 0, &parameters) == S_OK &&
                        parameters.SymbolType != DEBUG_SYMTYPE_NONE &&
                        (loadDeferred || parameters.SymbolType != DEBUG_SYMTYPE_DEFERRED);
        }
        if (queryName)
        {
            wchar_t name[4096] = {};
            ULONG64 displacement = 0;
            if (symbols->GetNameByOffsetWide(address, name, _countof(name), nullptr, &displacement) == S_OK &&
                kncore::SymbolNameCanBind(name))
            {
                const auto lookup = [&]() -> std::optional<uint64_t>
                {
                    ULONG64 symbolStart = 0;
                    if (!session.Cancelled() && symbols->GetOffsetByNameWide(name, &symbolStart) == S_OK)
                    {
                        return symbolStart;
                    }
                    return std::nullopt;
                };
                const auto symbolStart = bindings != nullptr ? bindings->Get(module->Base, name, lookup) : lookup();
                if (symbolStart && kncore::ExactSymbolBinding(address, displacement, *symbolStart, module->Base, module->Size))
                {
                    result.Text = name;
                    if (displacement != 0)
                    {
                        result.Text += L"+0x" + FmtHex(displacement);
                    }
                    result.Source = L"LoadedDebuggerSymbols";
                    result.Displacement = displacement;
                }
            }
        }
    }
    return result;
}
} // namespace

std::wstring FmtAddr(ULONG64 value)
{
    wchar_t buffer[24] = L"";
    swprintf_s(buffer, L"%08x`%08x", static_cast<unsigned>((value >> 32) & 0xFFFFFFFF), static_cast<unsigned>(value & 0xFFFFFFFF));
    return std::wstring(buffer);
}

std::wstring FmtHexN(ULONG64 value, int digits)
{
    wchar_t buffer[24] = L"";

    if (digits <= 0 || digits > 16)
    {
        digits = 8;
    }

    swprintf_s(buffer, L"%0*llx", digits, value);
    return std::wstring(buffer);
}

std::wstring FmtHex(ULONG64 value)
{
    wchar_t buffer[24] = L"";
    swprintf_s(buffer, L"%llx", value);
    return std::wstring(buffer);
}

std::wstring FmtDec(ULONG64 value)
{
    wchar_t buffer[24] = L"";
    _ui64tow_s(value, buffer, 24, 10);
    return std::wstring(buffer);
}

std::wstring AnnotateSymbol(knengine::DbgSession &session, ULONG64 address)
{
    knengine::SymbolQueryScope query;
    auto *symbols = session.Symbols();
    ULONG index = 0;
    ULONG64 base = 0;
    DEBUG_MODULE_PARAMETERS parameters = {};
    wchar_t name[1024] = {};
    if (symbols == nullptr || symbols->GetModuleByOffset(address, 0, &index, &base) != S_OK ||
        symbols->GetModuleParameters(1, &base, 0, &parameters) != S_OK || address < base || address - base >= parameters.Size ||
        symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, index, base, name, _countof(name), nullptr) != S_OK)
    {
        return {};
    }
    knengine::KernelModuleInfo module;
    module.ModuleName = name;
    module.Base = base;
    module.Size = parameters.Size;
    return ResolveAddressSymbol(session, address, &module, !session.Cancelled()).Text;
}

void AnnotateResultSymbols(knengine::DbgSession &session, kncore::Result &report)
{
    if (report.State == kncore::Status::InternalFault || report.State == kncore::Status::StaleContext ||
        report.State == kncore::Status::Cancelled || session.Cancelled() ||
        knengine::Epochs().State() == kncore::SessionState::Faulted)
    {
        return;
    }
    knengine::SymbolQueryScope query;
    std::vector<knengine::KernelModuleInfo> modules;
    std::map<uint64_t, AddressSymbol> cache;
    kncore::SymbolAddressCache bindings;
    bool inventoried = false;
    auto rows = knjson::Value::MakeArray();
    for (auto row : report.Rows.Items())
    {
        if (!row.IsObject() || row.Get(L"addressSpace").AsString(L"") == L"physical")
        {
            rows.Push(row);
            continue;
        }
        const auto has = [&](const wchar_t *name)
        {
            return std::any_of(row.Fields().begin(), row.Fields().end(),
                               [&](const auto &field)
                               {
                                   return field.first == name;
                               });
        };
        const auto annotate = [&](const wchar_t *field, const std::wstring &symbolField, bool optionalRoutine)
        {
            const auto sourceField = symbolField + L"Source";
            if (!has(field) || row.Get(sourceField).IsString())
            {
                return;
            }
            uint64_t address = 0;
            AddressSymbol symbol;
            const auto raw = row.Get(field).AsString(L"");
            const bool known = raw.starts_with(L"0x") && kncore::ParseUnsigned(raw, 16, &address);
            if (known && address != 0)
            {
                if (!inventoried)
                {
                    knengine::EnumerateKernelModules(session, &modules);
                    inventoried = true;
                }
                auto found = cache.find(address);
                if (found == cache.end())
                {
                    symbol = ResolveAddressSymbol(session, address, knengine::FindModuleForAddress(modules, address),
                                                   !session.Cancelled(), std::wstring_view(field) != L"base", &bindings);
                    cache.emplace(address, symbol);
                }
                else
                {
                    symbol = found->second;
                }
            }
            else if (known)
            {
                symbol.Source = optionalRoutine ? L"NotRegistered" : L"NullAddress";
            }
            row.Set(symbolField, symbol.Text.empty() ? knjson::Value() : knjson::Value(symbol.Text));
            row.Set(sourceField, knjson::Value(symbol.Source));
            row.Set(symbolField + L"Displacement", symbol.Displacement ? knjson::Value(kncore::Hex(*symbol.Displacement))
                                                                       : knjson::Value());
            if (symbolField == L"symbol")
            {
                row.Set(L"symbolAddress", known ? knjson::Value(kncore::Hex(address)) : knjson::Value());
                row.Set(L"symbolField", knjson::Value(field));
            }
        };
        const bool paired = has(L"preRoutine") || has(L"postRoutine");
        if (paired)
        {
            annotate(L"preRoutine", L"preSymbol", true);
            annotate(L"postRoutine", L"postSymbol", true);
        }
        else
        {
            for (const wchar_t *field : {L"routine", L"handler", L"pointer", L"address", L"va", L"start", L"ethread", L"eprocess",
                                          L"object", L"device", L"base", L"slot"})
            {
                if (has(field))
                {
                    annotate(field, L"symbol", (std::wstring_view(field) == L"routine" &&
                                                  row.Get(L"ownership").AsString(L"") == L"NullObserved") ||
                                                 std::wstring_view(field) == L"handler");
                    break;
                }
            }
        }
        for (const wchar_t *field : {L"CompletionRoutine", L"CancelRoutine", L"DispatchRoutine", L"win32Start"})
        {
            annotate(field, std::wstring(field) + L"Symbol", true);
        }
        if (row.Get(L"kind").AsString(L"") == L"Thread")
        {
            annotate(L"start", L"startSymbol", true);
        }
        const auto reg = row.Get(L"register").AsString(L"");
        if (reg == L"LSTAR" || reg == L"CSTAR" || reg == L"SYSENTER_EIP" || row.Get(L"name").AsString(L"") == L"rip" ||
            row.Get(L"kind").AsString(L"") == L"ExpressionValue")
        {
            annotate(L"value", L"symbol", false);
        }
        rows.Push(row);
    }
    report.Rows = rows;
}

bool EvalAddress(knengine::DbgSession &session, const std::wstring &token, ULONG64 *value)
{
    return session.Evaluate(token, value);
}

bool ParseDisplayRange(knengine::DbgSession &session, const std::vector<std::wstring> &args, size_t index, ULONG64 defaultLength,
                       ULONG64 maxLength, ULONG64 *start, ULONG64 *length, std::wstring *errorText, unsigned unitBytes)
{
    bool ok = false;

    do
    {
        if (start == nullptr || length == nullptr || index >= args.size())
        {
            if (errorText != nullptr)
            {
                *errorText = L"missing address";
            }
            break;
        }

        ULONG64 startValue = 0;

        if (!EvalAddress(session, args[index], &startValue))
        {
            if (errorText != nullptr)
            {
                *errorText = L"cannot evaluate address: " + args[index];
            }
            break;
        }

        ULONG64 lengthValue = defaultLength;

        if (index + 1 < args.size())
        {
            const std::wstring &second = args[index + 1];

            if (!second.empty() && (second[0] == L'L' || second[0] == L'l'))
            {
                uint64_t count = 0;
                if (unitBytes == 0 || !kncore::ParseUnsigned(std::wstring_view(second).substr(1), 16, &count) || count == 0 ||
                    count > maxLength / unitBytes)
                {
                    if (errorText != nullptr)
                    {
                        *errorText = L"invalid or excessive element count: " + second;
                    }
                    break;
                }
                lengthValue = count * unitBytes;
            }
            else
            {
                ULONG64 endValue = 0;

                if (!EvalAddress(session, second, &endValue))
                {
                    if (errorText != nullptr)
                    {
                        *errorText = L"cannot evaluate end: " + second;
                    }
                    break;
                }

                if (endValue < startValue)
                {
                    if (errorText != nullptr)
                    {
                        *errorText = L"end address below start";
                    }
                    break;
                }

                lengthValue = endValue - startValue + 1;
            }
        }

        if (lengthValue > maxLength || !kncore::ValidRange(startValue, lengthValue) || args.size() > index + 2)
        {
            if (errorText != nullptr)
            {
                *errorText = L"invalid, overflowing or excessive range";
            }
            break;
        }

        *start = startValue;
        *length = lengthValue;
        ok = true;
    } while (false);

    return ok;
}

std::vector<std::wstring> TokenizeLine(const std::wstring &line)
{
    return knutil::Tokenize(line);
}

bool ReadUnicodeString(knengine::DbgSession &session, knengine::LayoutResolver &layout, ULONG64 uniAddress, std::wstring *value)
{
    kncore::TargetArchitecture architecture;
    return KernelArchitecture(session, &architecture) &&
           kncore::ReadUnicodeValue(session, uniAddress, layout.Field(L"nt", L"_UNICODE_STRING", L"Length"),
                                    layout.Field(L"nt", L"_UNICODE_STRING", L"MaximumLength"),
                                    layout.Field(L"nt", L"_UNICODE_STRING", L"Buffer"), architecture, value);
}

bool SessionIsLocalLiveKernel(knengine::DbgSession &session)
{
    knengine::SessionStatus status = {};
    session.QueryStatus(&status);
    return status.Kind == knengine::SessionKind::KernelLocal;
}

std::wstring HostCollectorRefusal(const wchar_t *tag)
{
    std::wstring line = L"[";
    line += (tag != nullptr ? tag : L"kndbgx");
    line += L".refused] host-machine collector; valid only on local "
            L"live kernel debugging (this session is not the target)";
    return line;
}

bool ExtractJsonPath(const std::vector<std::wstring> &args, size_t startIndex, std::wstring *jsonPath, std::vector<std::wstring> *rest)
{
    bool found = false;

    if (jsonPath != nullptr)
    {
        jsonPath->clear();
    }

    if (rest != nullptr)
    {
        rest->clear();
    }

    for (size_t i = startIndex; i < args.size(); ++i)
    {
        if (_wcsicmp(args[i].c_str(), L"/json") == 0 && i + 1 < args.size())
        {
            if (jsonPath != nullptr)
            {
                *jsonPath = args[i + 1];
            }
            found = true;
            ++i;
            continue;
        }

        if (rest != nullptr)
        {
            rest->push_back(args[i]);
        }
    }

    return found;
}
} // namespace kncmd
