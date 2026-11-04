#include "LayoutResolver.h"
#include "SymbolQuery.h"
#include "../core/CollectorRead.h"
#include <dbgeng.h>
#include <dbghelp.h>
#include <wrl/client.h>

namespace knengine
{
namespace
{
std::wstring ModuleKey(const wchar_t *name)
{
    std::wstring value(name != nullptr && *name != 0 ? name : L"nt");
    for (auto &letter : value)
    {
        letter = static_cast<wchar_t>(towlower(letter));
    }
    return value;
}
} // namespace

LayoutResolver::LayoutResolver(DbgSession &session) : session_(session), cacheStamp_(Epochs().Stamp())
{
}

void LayoutResolver::CheckStamp()
{
    const auto current = Epochs().Stamp();
    if (current != cacheStamp_)
    {
        Clear();
        cacheStamp_ = current;
    }
}

bool LayoutResolver::NtBase(ULONG64 *base)
{
    return ModuleBase(L"nt", base);
}

bool LayoutResolver::ModuleBase(const wchar_t *moduleName, ULONG64 *base)
{
    SymbolQueryScope query;
    CheckStamp();
    bool ok = false;
    do
    {
        if (base == nullptr || session_.Symbols() == nullptr)
        {
            break;
        }
        const auto key = ModuleKey(moduleName);
        const auto found = moduleBaseCache_.find(key);
        if (found != moduleBaseCache_.end())
        {
            *base = found->second;
            ok = true;
            break;
        }
        ULONG index = 0;
        ULONG64 resolved = 0;
        if (session_.Symbols()->GetModuleByModuleNameWide(key.c_str(), 0, &index, &resolved) != S_OK || resolved == 0)
        {
            break;
        }
        moduleBaseCache_[key] = resolved;
        *base = resolved;
        ok = true;
    } while (false);
    return ok;
}

std::optional<kncore::ModuleIdentity> LayoutResolver::Identity(const wchar_t *moduleName)
{
    return IdentityImpl(moduleName, true);
}

std::optional<kncore::ModuleIdentity> LayoutResolver::LoadedIdentity(const wchar_t *moduleName)
{
    return IdentityImpl(moduleName, false);
}

std::optional<kncore::ModuleIdentity> LayoutResolver::IdentityImpl(const wchar_t *moduleName, bool loadSymbols)
{
    SymbolQueryScope query;
    CheckStamp();
    const auto key = ModuleKey(moduleName);
    if (const auto found = identities_.find(key); found != identities_.end())
    {
        return found->second;
    }
    ULONG64 base = 0;
    Microsoft::WRL::ComPtr<IDebugAdvanced3> advanced;
    if (!ModuleBase(moduleName, &base) || session_.Client() == nullptr ||
        FAILED(session_.Client()->QueryInterface(IID_PPV_ARGS(&advanced))))
    {
        return {};
    }
    IMAGEHLP_MODULEW64 image = {};
    image.SizeOfStruct = sizeof(image);
    const auto inspect = [&]()
    {
        return advanced->GetSymbolInformationWide(DEBUG_SYMINFO_IMAGEHLP_MODULEW64, base, 0, &image, sizeof(image), nullptr, nullptr, 0,
                                                  nullptr);
    };
    HRESULT inspected = inspect();
    if (loadSymbols && (inspected != S_OK || image.SymType == SymDeferred))
    {
        wchar_t name[1024] = {};
        ULONG64 displacement = 0;
        session_.Symbols()->GetNameByOffsetWide(base, name, _countof(name), nullptr, &displacement);
        inspected = inspect();
    }
    if (inspected != S_OK || image.PdbUnmatched || image.DbgUnmatched || image.SymType != SymPdb ||
        IsEqualGUID(image.PdbSig70, GUID_NULL) || image.PdbAge == 0 || image.BaseOfImage != base || image.ImageSize == 0 ||
        !kncore::ValidRange(base, image.ImageSize))
    {
        diagnostic_ = key + L": matching PDB/image identity unavailable (deferred, missing, exports-only or mismatched symbols)";
        return {};
    }
    const ULONG machine = image.MachineType;
    if (machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_ARM64)
    {
        return {};
    }
    wchar_t guid[40] = {};
    StringFromGUID2(image.PdbSig70, guid, _countof(guid));
    kncore::ModuleIdentity identity{guid, image.PdbAge, machine, image.TimeDateStamp, image.ImageSize, base, true};
    if (!loadSymbols)
    {
        // Do not cache an identity without its DIA metadata: a later Field
        // query must still be able to initialize the metadata provider.
        return identity;
    }
    auto metadata = std::make_unique<PdbMetadata>();
    if (metadata->Open(image.LoadedPdbName, image.PdbSig70, image.PdbAge))
    {
        metadata_[key] = std::move(metadata);
    }
    else
    {
        diagnostic_ = metadata->Diagnostic();
        metadataFailures_[key] = diagnostic_;
    }
    identities_[key] = identity;
    return identity;
}

std::optional<kncore::FieldInfo> LayoutResolver::Field(const wchar_t *moduleName, const wchar_t *typeName, const wchar_t *fieldName)
{
    SymbolQueryScope query;
    std::optional<kncore::FieldInfo> result;
    std::wstring key;
    do
    {
        if (typeName == nullptr || fieldName == nullptr)
        {
            break;
        }
        const auto identity = Identity(moduleName);
        if (!identity)
        {
            break;
        }
        key = identity->Key() + L"|" + typeName + L"|" + fieldName;
        if (const auto found = fields_.find(key); found != fields_.end())
        {
            result = found->second;
            if (!result)
            {
                diagnostic_ = fieldFailures_.at(key);
            }
            break;
        }
        kncore::FieldInfo field;
        ULONG typeSize = 0;
        const bool sized = TypeSize(moduleName, typeName, &typeSize);
        const auto metadata = metadata_.find(ModuleKey(moduleName));
        if (!sized)
        {
            break;
        }
        if (metadata == metadata_.end() || !metadata->second->Field(typeName, fieldName, &field))
        {
            diagnostic_ = ModuleKey(moduleName) + L"!" + typeName + L"." + fieldName + L": " +
                          (metadata == metadata_.end() ? L"DIA metadata provider unavailable" : metadata->second->Diagnostic());
            break;
        }
        ULONG id = 0;
        ULONG fieldType = 0;
        ULONG offset = 0;
        ULONG fieldSize = 0;
        auto *symbols = session_.Symbols();
        std::optional<kncore::FieldInfo> engine;
        if (symbols->GetTypeIdWide(identity->Base, typeName, &id) == S_OK &&
            symbols->GetFieldTypeAndOffsetWide(identity->Base, id, fieldName, &fieldType, &offset) == S_OK &&
            symbols->GetTypeSize(identity->Base, fieldType, &fieldSize) == S_OK)
        {
            engine.emplace();
            engine->Offset = offset;
            engine->Size = fieldSize;
        }
        if (!kncore::CorroborateField(field, engine, typeSize))
        {
            diagnostic_ = ModuleKey(moduleName) + L"!" + typeName + L"." + fieldName + L": conflicting field bounds/metadata";
            break;
        }
        result = field;
    } while (false);
    if (!key.empty())
    {
        fields_[key] = result;
        if (!result)
        {
            fieldFailures_[key] = diagnostic_;
        }
    }
    return result;
}

bool LayoutResolver::CanProfileField(const wchar_t *module, const wchar_t *type, const wchar_t *field)
{
    if (Field(module, type, field))
    {
        return true;
    }
    const auto metadata = metadata_.find(ModuleKey(module));
    return metadata != metadata_.end() && metadata->second->FieldAbsent(type, field);
}

std::optional<kncore::FieldInfo> LayoutResolver::Symbol(const wchar_t *module, const wchar_t *symbolName)
{
    SymbolQueryScope query;
    if (symbolName == nullptr)
    {
        return {};
    }
    ULONG id = 0;
    ULONG64 base = 0;
    ULONG size = 0;
    const auto identity = Identity(module);
    const std::wstring qualified = ModuleKey(module) + L"!" + symbolName;
    if (const auto found = symbols_.find(qualified); found != symbols_.end())
    {
        return found->second;
    }
    const auto metadata = metadata_.find(ModuleKey(module));
    kncore::FieldInfo described;
    uint32_t rva = 0;
    if (!identity || metadata == metadata_.end() || !metadata->second->Symbol(symbolName, &described, &rva))
    {
        diagnostic_ = qualified + L": typed data symbol unavailable in matched PDB; address presence does not establish storage";
        auto profiled = metadata != metadata_.end() && metadata->second->PublicOnlySymbol(symbolName) ? ProfileSymbol(module, symbolName)
                                                                                                      : std::nullopt;
        if (identity)
        {
            symbols_[qualified] = profiled;
        }
        return profiled;
    }
    if (rva >= identity->ImageSize || described.Size > identity->ImageSize - rva)
    {
        diagnostic_ = qualified + L": typed symbol storage outside matched image";
        return {};
    }
    if (session_.Symbols()->GetSymbolTypeIdWide(qualified.c_str(), &id, &base) == S_OK &&
        (base != identity->Base || (session_.Symbols()->GetTypeSize(base, id, &size) == S_OK && described.Size != size)))
    {
        diagnostic_ = qualified + L": conflicting data symbol metadata";
        return {};
    }
    const auto address = Address(module, symbolName);
    if (!address || *address != identity->Base + rva)
    {
        diagnostic_ = qualified + L": data symbol address does not match PDB RVA";
        return {};
    }
    symbols_[qualified] = described;
    return described;
}

bool LayoutResolver::PublicOnlySymbol(const wchar_t *module, const wchar_t *symbolName)
{
    SymbolQueryScope query;
    const auto identity = Identity(module);
    const auto metadata = metadata_.find(ModuleKey(module));
    return identity && metadata != metadata_.end() && metadata->second->PublicOnlySymbol(symbolName);
}

bool LayoutResolver::VerifyProfile(kncore::KernelLayoutFamily family)
{
    const auto identity = Identity(L"nt");
    if (!identity)
    {
        return false;
    }
    const auto reason = kncore::VerifyKernelProfile(session_, *identity, family,
                                                    [&](const wchar_t *name)
                                                    {
                                                        return Address(L"nt", name);
                                                    });
    const bool verified = std::wstring_view(reason) == L"Verified";
    if (!verified)
    {
        diagnostic_ = reason;
    }
    return verified;
}

std::optional<kncore::FieldInfo> LayoutResolver::ProfileSymbol(const wchar_t *module, const wchar_t *symbolName)
{
    using kncore::KernelLayoutFamily;
    if (ModuleKey(module) != L"nt")
    {
        return {};
    }
    const std::wstring_view name(symbolName);
    std::optional<KernelLayoutFamily> family;
    auto field = kncore::KernelProfileField(0, 0);
    if (name == L"ObTypeIndexTable")
    {
        family = KernelLayoutFamily::ObjectTypes;
        field.ArrayCount = 256;
        field.ElementSize = 8;
    }
    else if (name == L"ObpInfoMaskToOffset")
    {
        family = KernelLayoutFamily::ObjectNames;
        // Only the four-entry prefix used by name-info decoding is established.
        field.ArrayCount = 4;
        field.ElementSize = 1;
    }
    else if (name == L"MmProtectToValue")
    {
        const auto protection = Field(L"nt", L"_MMVAD_FLAGS", L"Protection");
        if (!protection || protection->BitWidth != 5u)
        {
            return {};
        }
        family = KernelLayoutFamily::VadProtection;
        field.ArrayCount = 32;
        field.ElementSize = 4;
    }
    else if (name == L"PspHostSiloGlobals")
    {
        ULONG size = 0;
        const auto job = Field(L"nt", L"_EJOB", L"ServerSiloGlobals");
        if (!job || job->Offset != 0x5e0 || job->Size != 8 || job->Kind != kncore::FieldKind::Pointer ||
            !TypeSize(L"_ESERVERSILO_GLOBALS", &size))
        {
            return {};
        }
        family = KernelLayoutFamily::HostSilo;
        field.Kind = kncore::FieldKind::Composite;
        field.TypeName = L"_ESERVERSILO_GLOBALS";
        field.Size = size;
    }
    if (!family || !VerifyProfile(*family))
    {
        return {};
    }
    if (field.ArrayCount)
    {
        field.Kind = kncore::FieldKind::Array;
        field.Size = *field.ArrayCount * *field.ElementSize;
    }
    ULONG id = 0;
    ULONG size = 0;
    ULONG64 base = 0;
    const auto identity = Identity(module);
    const auto address = Address(module, symbolName);
    const std::wstring qualified = ModuleKey(module) + L"!" + symbolName;
    if (!identity || !address || !field.ValidFor(field.Size) || field.Size > identity->ImageSize ||
        *address - identity->Base > identity->ImageSize - field.Size ||
        (session_.Symbols()->GetSymbolTypeIdWide(qualified.c_str(), &id, &base) == S_OK &&
         (base != identity->Base || (session_.Symbols()->GetTypeSize(base, id, &size) == S_OK && size != 0 && size != field.Size))))
    {
        diagnostic_ = qualified + L": profiled storage contradicts symbol metadata or image bounds";
        return {};
    }
    return field;
}

std::optional<uint64_t> LayoutResolver::Address(const wchar_t *module, const wchar_t *symbolName)
{
    SymbolQueryScope query;
    CheckStamp();
    ULONG64 address = 0;
    if (symbolName == nullptr || session_.Symbols() == nullptr)
    {
        return {};
    }
    const auto qualified = ModuleKey(module) + L"!" + symbolName;
    if (const auto found = addresses_.find(qualified); found != addresses_.end())
    {
        return found->second;
    }
    const HRESULT resolved = session_.Symbols()->GetOffsetByNameWide(qualified.c_str(), &address);
    const auto identity = Identity(module);
    if (resolved != S_OK || !identity || address < identity->Base || address - identity->Base >= identity->ImageSize)
    {
        diagnostic_ = qualified + L": symbol unavailable or outside matched image";
        return {};
    }
    const auto metadata = metadata_.find(ModuleKey(module));
    uint32_t rva = 0;
    if (metadata != metadata_.end() && metadata->second->PublicRva(symbolName, &rva) && address - identity->Base != rva)
    {
        diagnostic_ = qualified + L": public symbol RVA mismatch";
        return {};
    }
    addresses_[qualified] = address;
    return address;
}

bool LayoutResolver::FieldOffset(const wchar_t *type, const wchar_t *field, ULONG *offset)
{
    return FieldOffset(L"nt", type, field, offset);
}
bool LayoutResolver::FieldOffset(const wchar_t *module, const wchar_t *type, const wchar_t *name, ULONG *offset)
{
    const auto field = Field(module, type, name);
    if (offset != nullptr && field)
    {
        *offset = field->Offset;
        return true;
    }
    return false;
}
bool LayoutResolver::FieldSize(const wchar_t *type, const wchar_t *name, ULONG *size)
{
    return FieldSize(L"nt", type, name, size);
}
bool LayoutResolver::FieldSize(const wchar_t *module, const wchar_t *type, const wchar_t *name, ULONG *size)
{
    const auto field = Field(module, type, name);
    if (size != nullptr && field)
    {
        *size = field->Size;
        return true;
    }
    return false;
}
bool LayoutResolver::TypeSize(const wchar_t *type, ULONG *size)
{
    return TypeSize(L"nt", type, size);
}
bool LayoutResolver::TypeSize(const wchar_t *module, const wchar_t *type, ULONG *size)
{
    SymbolQueryScope query;
    if (type == nullptr || size == nullptr)
    {
        return false;
    }
    const auto identity = Identity(module);
    const auto metadata = metadata_.find(ModuleKey(module));
    uint32_t described = 0;
    if (!identity || metadata == metadata_.end() || !metadata->second->TypeSize(type, &described))
    {
        if (identity)
        {
            const auto failure = metadataFailures_.find(ModuleKey(module));
            diagnostic_ = ModuleKey(module) + L"!" + type + L": " +
                          (metadata != metadata_.end() ? metadata->second->Diagnostic()
                           : failure != metadataFailures_.end() ? failure->second
                                                                : L"DIA metadata provider unavailable");
        }
        return false;
    }
    ULONG id = 0;
    ULONG engineSize = 0;
    if (session_.Symbols()->GetTypeIdWide(identity->Base, type, &id) == S_OK &&
        session_.Symbols()->GetTypeSize(identity->Base, id, &engineSize) == S_OK && engineSize != described)
    {
        diagnostic_ = ModuleKey(module) + L"!" + type + L": conflicting type size";
        return false;
    }
    *size = described;
    return true;
}

std::optional<kncore::LayoutDescriptor> LayoutResolver::Describe(const wchar_t *module, const wchar_t *type)
{
    SymbolQueryScope query;
    ULONG size = 0;
    if (!TypeSize(module, type, &size))
    {
        return {};
    }
    kncore::LayoutDescriptor result;
    const auto identity = Identity(module);
    const auto metadata = metadata_.find(ModuleKey(module));
    if (!identity || metadata == metadata_.end() || !metadata->second->Describe(type, &result) || result.Size != size)
    {
        return {};
    }
    result.Identity = *identity;
    result.Stamp = Epochs().Stamp();
    result.TypeName = type;
    result.Size = size;
    const auto fields = result.Fields;
    for (const auto &[name, unused] : fields)
    {
        const auto field = Field(module, type, name.c_str());
        if (field)
        {
            result.Fields[name] = *field;
        }
        else
        {
            result.Fields.erase(name);
            result.UnknownFields.push_back(name);
        }
    }
    result.Complete = result.UnknownFields.empty();
    return result;
}

bool LayoutResolver::NestedFieldOffset(const wchar_t *outerType, const wchar_t *outerName, const wchar_t *innerType,
                                       const wchar_t *innerName, ULONG *offset)
{
    const auto outer = Field(L"nt", outerType, outerName);
    const auto inner = Field(L"nt", innerType, innerName);
    const auto nested = kncore::NestedField(outer, inner);
    if (offset == nullptr || !nested)
    {
        return false;
    }
    *offset = nested->Offset;
    return true;
}

void LayoutResolver::Clear()
{
    diagnostic_.clear();
    moduleBaseCache_.clear();
    identities_.clear();
    metadata_.clear();
    metadataFailures_.clear();
    fields_.clear();
    fieldFailures_.clear();
    symbols_.clear();
    addresses_.clear();
}

std::wstring LayoutResolver::Diagnostic() const
{
    return diagnostic_;
}
} // namespace knengine
