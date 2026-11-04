#include "SymbolHealth.h"
#include "SymbolQuery.h"
#include <dbgeng.h>
#include <dbghelp.h>
#include <wrl/client.h>

namespace knengine
{
namespace
{
const wchar_t *LoadState(ULONG type)
{
    switch (type)
    {
    case DEBUG_SYMTYPE_NONE:
        return L"None";
    case DEBUG_SYMTYPE_DEFERRED:
        return L"Deferred";
    case DEBUG_SYMTYPE_EXPORT:
        return L"ExportOnly";
    case DEBUG_SYMTYPE_PDB:
        return L"PDB";
    case DEBUG_SYMTYPE_COFF:
        return L"COFF";
    case DEBUG_SYMTYPE_CODEVIEW:
        return L"CodeView";
    case DEBUG_SYMTYPE_SYM:
        return L"SYM";
    case DEBUG_SYMTYPE_DIA:
        return L"DIA";
    }
    return L"Unknown";
}

kncore::SymbolModuleKey Key(const DEBUG_MODULE_PARAMETERS &module)
{
    return {module.Base, module.Size, module.TimeDateStamp, module.Checksum};
}

knjson::Value Error(const wchar_t *reason, HRESULT code = S_OK)
{
    auto result = knjson::Value::MakeObject();
    result.Set(L"ok", knjson::Value(false));
    result.Set(L"error", knjson::Value(reason));
    result.Set(L"nativeError", code != S_OK ? knjson::Value(kncore::Hex(static_cast<uint32_t>(code))) : knjson::Value());
    return result;
}

knjson::Value ModuleRow(IDebugSymbols3 *symbols, const DEBUG_MODULE_PARAMETERS &module)
{
    auto result = knjson::Value::MakeObject();
    result.Set(L"key", Key(module).ToJson());
    wchar_t name[64] = {};
    const HRESULT named = symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, module.Base,
                                                          name, _countof(name), nullptr);
    result.Set(L"name", named == S_OK ? knjson::Value(name) : knjson::Value());
    result.Set(L"loadState", knjson::Value(LoadState(module.SymbolType)));
    result.Set(L"nameError", named == S_OK ? knjson::Value() : knjson::Value(kncore::Hex(static_cast<uint32_t>(named))));
    return result;
}

bool CurrentModule(IDebugSymbols3 *symbols, const kncore::SymbolModuleKey &key, DEBUG_MODULE_PARAMETERS &module)
{
    ULONG64 base = key.Base;
    return symbols->GetModuleParameters(1, &base, 0, &module) == S_OK && module.Base != DEBUG_INVALID_OFFSET &&
           !(module.Flags & DEBUG_MODULE_UNLOADED) && Key(module) == key;
}
} // namespace

knjson::Value ReadSymbolModules(DbgSession &session, const kncore::SessionStamp &expected, uint64_t cursor)
{
    SymbolQueryScope observed;
    auto symbols = session.Symbols();
    if (!symbols || session.RefreshStamp() != expected || cursor > 65536)
    {
        return Error(L"StaleContextOrInvalidModuleCursor");
    }
    ULONG loaded = 0;
    ULONG unloaded = 0;
    const HRESULT counted = symbols->GetNumberModules(&loaded, &unloaded);
    if (counted != S_OK || loaded > 65536 || cursor > loaded)
    {
        return Error(L"ModuleInventoryUnavailableOrLimit", counted);
    }
    auto modules = knjson::Value::MakeArray();
    const uint64_t end = (std::min)(cursor + 64, static_cast<uint64_t>(loaded));
    uint64_t unknown = 0;
    for (uint64_t index = cursor; index < end; ++index)
    {
        if (session.Cancelled())
        {
            return Error(L"Cancelled");
        }
        DEBUG_MODULE_PARAMETERS module = {};
        if (symbols->GetModuleParameters(1, nullptr, static_cast<ULONG>(index), &module) != S_OK ||
            module.Base == 0 || module.Base == DEBUG_INVALID_OFFSET || module.Size == 0 ||
            module.Flags & DEBUG_MODULE_UNLOADED || !kncore::ValidRange(module.Base, module.Size))
        {
            ++unknown;
            continue;
        }
        modules.Push(ModuleRow(symbols, module));
        kncore::PublishOperationStage(kncore::OperationStage::SymbolQuery);
    }
    if (session.RefreshStamp() != expected || session.Cancelled())
    {
        return Error(L"StaleOrCancelledModuleInventory");
    }
    auto result = knjson::Value::MakeObject();
    result.Set(L"ok", knjson::Value(true));
    result.Set(L"target", expected.ToJson());
    result.Set(L"modules", modules);
    result.Set(L"total", knjson::Value(std::to_wstring(loaded)));
    result.Set(L"unknown", knjson::Value(std::to_wstring(unknown)));
    result.Set(L"nextCursor", knjson::Value(std::to_wstring(end)));
    result.Set(L"complete", knjson::Value(end == loaded));
    return result;
}

knjson::Value InspectSymbolHealth(DbgSession &session, const kncore::SessionStamp &expected,
                                 const kncore::SymbolModuleKey &key, const std::wstring &type, const std::wstring &field)
{
    SymbolQueryScope observed;
    auto symbols = session.Symbols();
    if (!symbols || session.RefreshStamp() != expected || (!type.empty() && !kncore::SymbolIdentifier(type, 128)) ||
        (!field.empty() && (type.empty() || !kncore::SymbolIdentifier(field, 128))))
    {
        return Error(L"StaleContextOrInvalidSymbolQuery");
    }
    DEBUG_MODULE_PARAMETERS module = {};
    if (!CurrentModule(symbols, key, module))
    {
        return Error(L"StaleModuleIdentity");
    }
    auto result = knjson::Value::MakeObject();
    auto typeResult = knjson::Value::MakeObject();
    typeResult.Set(L"name", knjson::Value(type));
    typeResult.Set(L"field", knjson::Value(field));
    typeResult.Set(L"state", knjson::Value(L"NotRequested"));
    typeResult.Set(L"nativeError", knjson::Value());
    typeResult.Set(L"size", knjson::Value());
    typeResult.Set(L"fieldOffset", knjson::Value());
    if (!type.empty())
    {
        ULONG typeId = 0;
        ULONG size = 0;
        ULONG offset = 0;
        HRESULT queried = symbols->GetTypeIdWide(key.Base, type.c_str(), &typeId);
        if (queried == S_OK)
        {
            queried = symbols->GetTypeSize(key.Base, typeId, &size);
        }
        typeResult.Set(L"state", knjson::Value(queried == S_OK ? L"Available" : L"TypeUnavailable"));
        if (queried == S_OK)
        {
            typeResult.Set(L"size", knjson::Value(std::to_wstring(size)));
            if (!field.empty())
            {
                queried = symbols->GetFieldOffsetWide(key.Base, typeId, field.c_str(), &offset);
                typeResult.Set(L"state", knjson::Value(queried == S_OK ? L"Available" : L"FieldUnavailable"));
                if (queried == S_OK)
                {
                    typeResult.Set(L"fieldOffset", knjson::Value(std::to_wstring(offset)));
                }
            }
        }
        typeResult.Set(L"nativeError", queried == S_OK ? knjson::Value() : knjson::Value(kncore::Hex(static_cast<uint32_t>(queried))));
    }
    if (session.Cancelled())
    {
        return Error(L"Cancelled");
    }
    Microsoft::WRL::ComPtr<IDebugAdvanced3> advanced;
    IMAGEHLP_MODULEW64 image = {};
    image.SizeOfStruct = sizeof(image);
    HRESULT inspected = session.Client()->QueryInterface(IID_PPV_ARGS(&advanced));
    if (inspected == S_OK)
    {
        inspected = advanced->GetSymbolInformationWide(DEBUG_SYMINFO_IMAGEHLP_MODULEW64, key.Base, 0,
                                                       &image, sizeof(image), nullptr, nullptr, 0, nullptr);
    }
    if (!CurrentModule(symbols, key, module) || session.RefreshStamp() != expected || session.Cancelled())
    {
        return Error(L"StaleOrCancelledSymbolHealth");
    }
    const bool metadata = inspected == S_OK && image.BaseOfImage == key.Base && image.ImageSize == key.Size &&
                          image.TimeDateStamp == key.Timestamp;
    const bool pdb = metadata && image.SymType == SymPdb;
    const bool pdbIdentity = pdb && !IsEqualGUID(image.PdbSig70, GUID_NULL) && image.PdbAge != 0;
    const bool unmatched = metadata && (image.PdbUnmatched || image.DbgUnmatched);
    result.Set(L"ok", knjson::Value(true));
    result.Set(L"target", expected.ToJson());
    result.Set(L"module", ModuleRow(symbols, module));
    result.Set(L"imageMatch", knjson::Value(kncore::SymbolImageMatch(metadata, pdb, pdbIdentity, unmatched)));
    result.Set(L"typeInformation", pdb ? knjson::Value(image.TypeInfo != FALSE) : knjson::Value());
    result.Set(L"requestedType", typeResult);
    result.Set(L"nativeError", inspected == S_OK ? knjson::Value() : knjson::Value(kncore::Hex(static_cast<uint32_t>(inspected))));
    result.Set(L"metadataReason", knjson::Value(metadata ? L"" : L"Matching module metadata unavailable"));
    auto identity = knjson::Value();
    if (pdbIdentity)
    {
        wchar_t guid[40] = {};
        StringFromGUID2(image.PdbSig70, guid, _countof(guid));
        identity = knjson::Value::MakeObject();
        identity.Set(L"guid", knjson::Value(guid));
        identity.Set(L"age", knjson::Value(std::to_wstring(image.PdbAge)));
    }
    result.Set(L"pdbIdentity", identity);
    const auto name = result.Get(L"module").Get(L"name").AsString(L"");
    result.Set(L"reloadDraft", kncore::SymbolIdentifier(name, 127, true) && name.front() != L'-' && name.front() != L'.'
        ? knjson::Value(L".reload /f " + name) : knjson::Value());
    if (!CurrentModule(symbols, key, module) || session.RefreshStamp() != expected || session.Cancelled())
    {
        return Error(L"StaleOrCancelledSymbolHealth");
    }
    return result;
}
} // namespace knengine
