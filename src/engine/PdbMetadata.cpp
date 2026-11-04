#include "PdbMetadata.h"
#include <dia2.h>
#include <cvconst.h>
#include <wrl/client.h>
#include <filesystem>
#include <mutex>
#include "../util/ArtifactWriter.h"

using Microsoft::WRL::ComPtr;

namespace knengine
{
namespace
{
struct ProviderCopy
{
    std::filesystem::path Source;
    std::filesystem::path Directory;
    std::filesystem::path File;
    ~ProviderCopy()
    {
        if (!File.empty())
        {
            DeleteFileW(File.c_str());
        }
        if (!Directory.empty())
        {
            RemoveDirectoryW(Directory.c_str());
        }
    }
};
} // namespace

struct PdbMetadata::Impl
{
    HRESULT Com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    HMODULE Module = nullptr;
    ComPtr<IDiaDataSource> Source;
    ComPtr<IDiaSession> Session;
    ComPtr<IDiaSymbol> Global;
    std::shared_ptr<ProviderCopy> PrivateProvider;
    std::wstring Diagnostic = L"NotOpened";
    ~Impl()
    {
        Global.Reset();
        Session.Reset();
        Source.Reset();
        if (Module != nullptr)
        {
            FreeLibrary(Module);
        }
        if (SUCCEEDED(Com))
        {
            CoUninitialize();
        }
    }
};

PdbMetadata::PdbMetadata() : impl_(std::make_unique<Impl>())
{
}
PdbMetadata::~PdbMetadata() = default;
std::wstring PdbMetadata::Diagnostic() const
{
    return impl_->Diagnostic;
}

namespace
{
struct ModuleLease
{
    ModuleLease() = default;
    ModuleLease(const ModuleLease &) = delete;
    ModuleLease &operator=(const ModuleLease &) = delete;
    HMODULE Value = nullptr;
    ~ModuleLease()
    {
        if (Value != nullptr)
        {
            FreeLibrary(Value);
        }
    }
};

std::filesystem::path ModuleDirectory(HMODULE module)
{
    wchar_t path[32768] = {};
    const auto length = GetModuleFileNameW(module, path, _countof(path));
    return length != 0 && length < _countof(path) ? std::filesystem::path(path).parent_path() : std::filesystem::path();
}

std::filesystem::path ProviderPath()
{
    HMODULE own = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&ProviderPath), &own))
    {
        return {};
    }
    const auto directory = ModuleDirectory(own);
    return directory.empty() ? std::filesystem::path() : directory / L"runtime" / L"dia" / L"msdia140.dll";
}

std::filesystem::path EngineProviderPath()
{
    ModuleLease engine;
    if (!GetModuleHandleExW(0, L"dbgeng.dll", &engine.Value))
    {
        return {};
    }
    const auto directory = ModuleDirectory(engine.Value);
    return directory.empty() ? std::filesystem::path() : directory / L"msdia140.dll";
}

std::shared_ptr<ProviderCopy> PrivateEngineProvider(std::wstring &diagnostic)
{
    static std::mutex mutex;
    static std::weak_ptr<ProviderCopy> cached;
    std::lock_guard lock(mutex);
    const auto source = EngineProviderPath();
    if (source.empty())
    {
        diagnostic += L" [loaded DbgEng directory unavailable]";
        return {};
    }
    if (auto shared = cached.lock(); shared && shared->Source == source)
    {
        return shared;
    }
    wchar_t temporary[32768] = {};
    const auto length = GetTempPathW(_countof(temporary), temporary);
    const auto suffix = knutil::UniqueSuffix();
    if (length == 0 || length >= _countof(temporary) || suffix.empty())
    {
        diagnostic += L" [private DIA temporary directory unavailable]";
        return {};
    }
    auto copy = std::make_shared<ProviderCopy>();
    const auto directory = std::filesystem::path(temporary) / (L"kndbgx-dia-" + std::to_wstring(GetCurrentProcessId()) + L"-" + suffix);
    if (!CreateDirectoryW(directory.c_str(), nullptr))
    {
        diagnostic += L" [private DIA directory: Win32=" + std::to_wstring(GetLastError()) + L"]";
        return {};
    }
    copy->Directory = directory;
    const auto file = directory / L"msdia140.dll";
    copy->File = file;
    if (!CopyFileW(source.c_str(), file.c_str(), TRUE))
    {
        diagnostic += L" [private DIA copy from " + source.wstring() + L": Win32=" + std::to_wstring(GetLastError()) + L"]";
        return {};
    }
    copy->Source = source;
    cached = copy;
    return copy;
}

bool CreateProvider(const std::filesystem::path &path, HMODULE *module, ComPtr<IDiaDataSource> &source, std::wstring &diagnostic)
{
    if (path.empty())
    {
        return false;
    }
    // Use the packaged provider or a private copy of the loaded engine's provider.
    ModuleLease provider;
    provider.Value = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    const auto loadError = provider.Value == nullptr ? GetLastError() : ERROR_SUCCESS;
    using Factory = HRESULT(WINAPI *)(REFCLSID, REFIID, void **);
    const auto create =
        provider.Value == nullptr ? nullptr : reinterpret_cast<Factory>(GetProcAddress(provider.Value, "DllGetClassObject"));
    ComPtr<IClassFactory> factory;
    HRESULT status = create == nullptr ? E_NOINTERFACE : create(__uuidof(DiaSource), IID_PPV_ARGS(&factory));
    if (SUCCEEDED(status) && factory)
    {
        status = factory->CreateInstance(nullptr, IID_PPV_ARGS(&source));
    }
    const bool ready = SUCCEEDED(status) && source;
    if (ready)
    {
        *module = provider.Value;
        provider.Value = nullptr;
    }
    else
    {
        source.Reset();
        diagnostic += L" [" + path.wstring() + L": loader=" + std::to_wstring(loadError) + L" factory=" +
                      kncore::Hex(static_cast<uint32_t>(status)) + L"]";
    }
    return ready;
}
} // namespace

bool PdbMetadata::Open(const std::wstring &path, const GUID &guid, uint32_t age)
{
    bool ok = false;
    do
    {
        if (impl_->Source || path.empty() || (FAILED(impl_->Com) && impl_->Com != RPC_E_CHANGED_MODE))
        {
            break;
        }
        std::wstring providerErrors;
        HRESULT registered = S_OK;
        if (!CreateProvider(ProviderPath(), &impl_->Module, impl_->Source, providerErrors))
        {
            registered = CoCreateInstance(__uuidof(DiaSource), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&impl_->Source));
            if (FAILED(registered))
            {
                impl_->Source.Reset();
            }
            if (!impl_->Source)
            {
                // The engine's loaded DIA may use DbgHelp's private allocator.
                // A separate module keeps our standard COM/BSTR contract intact.
                impl_->PrivateProvider = PrivateEngineProvider(providerErrors);
                if (impl_->PrivateProvider)
                {
                    CreateProvider(impl_->PrivateProvider->File, &impl_->Module, impl_->Source, providerErrors);
                }
            }
        }
        GUID expected = guid;
        if (!impl_->Source)
        {
            impl_->Diagnostic = L"DIA provider unavailable; keep runtime/dia/msdia140.dll beside kndbgx.dll. Attempts:" +
                                providerErrors + L" registered=" + kncore::Hex(static_cast<uint32_t>(registered));
            break;
        }
        const auto loaded = impl_->Source->loadAndValidateDataFromPdb(path.c_str(), &expected, 0, age);
        if (loaded != S_OK)
        {
            impl_->Diagnostic = L"loadAndValidateDataFromPdb=" + kncore::Hex(static_cast<uint32_t>(loaded)) + L" path=" + path;
            break;
        }
        if (impl_->Source->openSession(&impl_->Session) != S_OK || impl_->Session->get_globalScope(&impl_->Global) != S_OK)
        {
            impl_->Diagnostic = L"DIA session or global scope unavailable";
            break;
        }
        impl_->Diagnostic = L"Ready";
        ok = true;
    } while (false);
    return ok;
}

namespace
{
bool UniqueChild(IDiaSymbol *parent, enum SymTagEnum tag, const std::wstring &name, IDiaSymbol **child)
{
    ComPtr<IDiaEnumSymbols> matches;
    LONG count = 0;
    ULONG fetched = 0;
    return parent->findChildren(tag, name.c_str(), nsCaseSensitive, &matches) == S_OK && matches->get_Count(&count) == S_OK && count == 1 &&
           matches->Next(1, child, &fetched) == S_OK && fetched == 1;
}

bool Unwrap(ComPtr<IDiaSymbol> &type, DWORD *tag)
{
    for (unsigned depth = 0; depth < 16; ++depth)
    {
        if (!type || type->get_symTag(tag) != S_OK)
        {
            break;
        }
        if (*tag != SymTagTypedef)
        {
            return true;
        }
        ComPtr<IDiaSymbol> underlying;
        if (type->get_type(&underlying) != S_OK)
        {
            break;
        }
        type = underlying;
    }
    return false;
}

bool ArrayShape(ComPtr<IDiaSymbol> type, kncore::FieldInfo &field)
{
    for (unsigned depth = 0; depth < 8; ++depth)
    {
        DWORD tag = 0;
        if (!Unwrap(type, &tag))
        {
            return false;
        }
        if (tag != SymTagArrayType)
        {
            ULONGLONG size = 0;
            if (type->get_length(&size) != S_OK || size == 0 || size > UINT32_MAX)
            {
                return false;
            }
            field.LeafElementSize = static_cast<uint32_t>(size);
            if (tag == SymTagUDT)
            {
                field.LeafKind = kncore::FieldKind::Composite;
            }
            else if (tag == SymTagPointerType)
            {
                field.LeafKind = kncore::FieldKind::Pointer;
            }
            else if (tag == SymTagBaseType)
            {
                DWORD base = 0;
                if (type->get_baseType(&base) == S_OK)
                {
                    field.LeafKind = base == btUInt || base == btULong ? kncore::FieldKind::Unsigned
                                     : base == btInt || base == btLong ? kncore::FieldKind::Signed
                                     : base == btBool                  ? kncore::FieldKind::Boolean
                                                                       : kncore::FieldKind::Unknown;
                }
            }
            BSTR name = nullptr;
            if (type->get_name(&name) == S_OK && name != nullptr)
            {
                field.LeafTypeName.assign(name, SysStringLen(name));
            }
            SysFreeString(name);
            return true;
        }
        DWORD count = 0;
        ComPtr<IDiaSymbol> next;
        if (type->get_count(&count) != S_OK || count == 0 || type->get_type(&next) != S_OK)
        {
            return false;
        }
        field.ArrayDimensions.push_back(count);
        type = next;
    }
    return false;
}
} // namespace

bool PdbMetadata::FieldAbsent(const wchar_t *typeName, const wchar_t *fieldName)
{
    if (!impl_->Global || typeName == nullptr || fieldName == nullptr || *typeName == 0 || *fieldName == 0 ||
        std::wstring(fieldName).find(L'.') != std::wstring::npos)
    {
        return false;
    }
    ComPtr<IDiaEnumSymbols> types;
    ComPtr<IDiaEnumSymbols> aliases;
    LONG typeCount = 0;
    LONG aliasCount = 0;
    if (impl_->Global->findChildren(SymTagUDT, typeName, nsCaseSensitive, &types) != S_OK || !types ||
        types->get_Count(&typeCount) != S_OK || impl_->Global->findChildren(SymTagTypedef, typeName, nsCaseSensitive, &aliases) != S_OK ||
        !aliases || aliases->get_Count(&aliasCount) != S_OK || typeCount < 0 || aliasCount < 0)
    {
        return false;
    }
    if (typeCount == 0 && aliasCount == 0)
    {
        return true;
    }
    if (typeCount > 1 || aliasCount > 1 || typeCount + aliasCount != 1)
    {
        return false;
    }
    ComPtr<IDiaSymbol> type;
    ULONG fetched = 0;
    DWORD tag = 0;
    ULONGLONG size = 0;
    auto *matches = typeCount == 1 ? types.Get() : aliases.Get();
    if (matches->Next(1, &type, &fetched) != S_OK || fetched != 1 || !Unwrap(type, &tag) || tag != SymTagUDT ||
        type->get_length(&size) != S_OK || size == 0 || size > UINT32_MAX)
    {
        return false;
    }
    ComPtr<IDiaEnumSymbols> fields;
    LONG fieldCount = 0;
    return type->findChildren(SymTagData, fieldName, nsCaseSensitive, &fields) == S_OK && fields &&
           fields->get_Count(&fieldCount) == S_OK && fieldCount == 0;
}

bool PdbMetadata::TypeSize(const wchar_t *typeName, uint32_t *size)
{
    ComPtr<IDiaSymbol> type;
    DWORD tag = 0;
    ULONGLONG length = 0;
    const bool ok = impl_->Global && typeName != nullptr && size != nullptr &&
                    (UniqueChild(impl_->Global.Get(), SymTagUDT, typeName, &type) ||
                     UniqueChild(impl_->Global.Get(), SymTagTypedef, typeName, &type)) &&
                    Unwrap(type, &tag) && type->get_length(&length) == S_OK && length != 0 && length <= UINT32_MAX;
    if (ok)
    {
        *size = static_cast<uint32_t>(length);
    }
    else
    {
        impl_->Diagnostic = L"Unique type size unavailable";
    }
    return ok;
}

bool PdbMetadata::Field(const wchar_t *typeName, const wchar_t *fieldName, kncore::FieldInfo *result)
{
    bool ok = false;
    do
    {
        if (!impl_->Global || result == nullptr || typeName == nullptr || fieldName == nullptr)
        {
            break;
        }
        ComPtr<IDiaSymbol> type;
        if (!UniqueChild(impl_->Global.Get(), SymTagUDT, typeName, &type) &&
            !UniqueChild(impl_->Global.Get(), SymTagTypedef, typeName, &type))
        {
            impl_->Diagnostic = L"Unique type unavailable";
            break;
        }
        uint32_t rootSize = 0;
        if (!TypeSize(typeName, &rootSize))
        {
            break;
        }
        kncore::FieldInfo info;
        const std::wstring path(fieldName);
        size_t part = 0;
        for (unsigned depth = 0; depth < 16; ++depth)
        {
            DWORD tag = 0;
            ULONGLONG parentSize = 0;
            if (!Unwrap(type, &tag) || tag != SymTagUDT || type->get_length(&parentSize) != S_OK || parentSize > UINT32_MAX)
            {
                break;
            }
            const auto end = path.find(L'.', part);
            ComPtr<IDiaSymbol> member;
            if (!UniqueChild(type.Get(), SymTagData, path.substr(part, end - part), &member))
            {
                impl_->Diagnostic = L"Unique field unavailable";
                break;
            }
            LONG offset = 0;
            DWORD location = 0;
            ComPtr<IDiaSymbol> memberType;
            if (member->get_locationType(&location) != S_OK || (location != LocIsThisRel && location != LocIsBitField) ||
                member->get_offset(&offset) != S_OK || offset < 0 || static_cast<uint32_t>(offset) > UINT32_MAX - info.Offset ||
                member->get_type(&memberType) != S_OK)
            {
                impl_->Diagnostic = L"Member location, offset or type unavailable";
                break;
            }
            ULONGLONG memberSize = 0;
            DWORD memberTag = 0;
            if (!Unwrap(memberType, &memberTag) || memberType->get_length(&memberSize) != S_OK || memberSize == 0 ||
                memberSize > parentSize || static_cast<uint64_t>(offset) > parentSize - memberSize ||
                (end != std::wstring::npos && location == LocIsBitField))
            {
                impl_->Diagnostic = L"Member outside its containing type or nested through a bitfield";
                break;
            }
            info.Offset += offset;
            type = memberType;
            if (end != std::wstring::npos)
            {
                part = end + 1;
                continue;
            }
            ULONGLONG length = 0;
            if (!Unwrap(type, &tag) || type->get_length(&length) != S_OK || length == 0 || length > UINT32_MAX)
            {
                impl_->Diagnostic = L"Field storage type or length unavailable";
                break;
            }
            info.Size = static_cast<uint32_t>(length);
            if (location == LocIsBitField)
            {
                DWORD position = 0;
                ULONGLONG bits = 0;
                if (member->get_bitPosition(&position) != S_OK || member->get_length(&bits) != S_OK || bits > UINT32_MAX)
                {
                    break;
                }
                info.BitOffset = position;
                info.BitWidth = static_cast<uint32_t>(bits);
            }
            if (tag == SymTagArrayType)
            {
                DWORD count = 0;
                ComPtr<IDiaSymbol> element;
                ULONGLONG size = 0;
                if (type->get_count(&count) != S_OK || type->get_type(&element) != S_OK || element->get_length(&size) != S_OK ||
                    size > UINT32_MAX)
                {
                    break;
                }
                info.Kind = kncore::FieldKind::Array;
                info.ArrayCount = count;
                info.ElementSize = static_cast<uint32_t>(size);
                if (!ArrayShape(type, info))
                {
                    break;
                }
            }
            else if (tag == SymTagPointerType)
            {
                info.Kind = kncore::FieldKind::Pointer;
                ComPtr<IDiaSymbol> pointee;
                DWORD pointeeTag = 0;
                info.FunctionPointer = type->get_type(&pointee) == S_OK && Unwrap(pointee, &pointeeTag) && pointeeTag == SymTagFunctionType;
            }
            else if (tag == SymTagUDT)
            {
                info.Kind = kncore::FieldKind::Composite;
            }
            else if (tag == SymTagBaseType)
            {
                DWORD baseType = 0;
                if (type->get_baseType(&baseType) == S_OK)
                {
                    info.Kind = baseType == btInt || baseType == btLong     ? kncore::FieldKind::Signed
                                : baseType == btUInt || baseType == btULong ? kncore::FieldKind::Unsigned
                                : baseType == btBool                        ? kncore::FieldKind::Boolean
                                                                            : kncore::FieldKind::Unknown;
                }
            }
            BSTR fieldTypeName = nullptr;
            if (type->get_name(&fieldTypeName) == S_OK && fieldTypeName != nullptr)
            {
                info.TypeName.assign(fieldTypeName, SysStringLen(fieldTypeName));
            }
            SysFreeString(fieldTypeName);
            info.Source = L"DIAValidatedPdb";
            if (!info.ValidFor(rootSize))
            {
                impl_->Diagnostic = L"Field bounds or bit/array metadata invalid";
                break;
            }
            *result = info;
            ok = true;
            break;
        }
    } while (false);
    return ok;
}

bool PdbMetadata::Describe(const wchar_t *typeName, kncore::LayoutDescriptor *result)
{
    ComPtr<IDiaSymbol> type;
    DWORD tag = 0;
    ULONGLONG length = 0;
    ComPtr<IDiaEnumSymbols> children;
    LONG count = 0;
    if (!impl_->Global || typeName == nullptr || result == nullptr ||
        (!UniqueChild(impl_->Global.Get(), SymTagUDT, typeName, &type) &&
         !UniqueChild(impl_->Global.Get(), SymTagTypedef, typeName, &type)) ||
        !Unwrap(type, &tag) || type->get_length(&length) != S_OK || length == 0 || length > UINT32_MAX ||
        type->findChildren(SymTagData, nullptr, nsNone, &children) != S_OK || children->get_Count(&count) != S_OK || count < 0 ||
        count > 4096)
    {
        return false;
    }
    *result = {};
    result->TypeName = typeName;
    result->Size = static_cast<uint32_t>(length);
    for (LONG i = 0; i < count; ++i)
    {
        ComPtr<IDiaSymbol> child;
        ULONG fetched = 0;
        BSTR name = nullptr;
        if (children->Next(1, &child, &fetched) != S_OK || fetched != 1 || child->get_name(&name) != S_OK || name == nullptr)
        {
            SysFreeString(name);
            return false;
        }
        const std::wstring key(name, SysStringLen(name));
        SysFreeString(name);
        kncore::FieldInfo field;
        if (Field(typeName, key.c_str(), &field) && field.ValidFor(result->Size))
        {
            result->Fields[key] = field;
        }
        else
        {
            result->UnknownFields.push_back(key);
        }
    }
    result->Complete = result->UnknownFields.empty();
    return true;
}

bool PdbMetadata::PublicRva(const wchar_t *name, uint32_t *rva)
{
    ComPtr<IDiaSymbol> symbol;
    DWORD relative = 0;
    if (!impl_->Global || rva == nullptr || name == nullptr || !UniqueChild(impl_->Global.Get(), SymTagPublicSymbol, name, &symbol) ||
        symbol->get_relativeVirtualAddress(&relative) != S_OK)
    {
        return false;
    }
    *rva = relative;
    return true;
}

bool PdbMetadata::PublicOnlySymbol(const wchar_t *name)
{
    ComPtr<IDiaEnumSymbols> children;
    LONG count = 0;
    uint32_t rva = 0;
    return impl_->Global && name != nullptr && PublicRva(name, &rva) &&
           impl_->Global->findChildren(SymTagData, name, nsCaseSensitive, &children) == S_OK && children->get_Count(&count) == S_OK &&
           count == 0;
}

bool PdbMetadata::Symbol(const wchar_t *name, kncore::FieldInfo *result, uint32_t *rva)
{
    ComPtr<IDiaSymbol> symbol;
    ComPtr<IDiaSymbol> type;
    DWORD tag = 0;
    ULONGLONG length = 0;
    if (!impl_->Global || name == nullptr || result == nullptr || !UniqueChild(impl_->Global.Get(), SymTagData, name, &symbol) ||
        symbol->get_type(&type) != S_OK || !Unwrap(type, &tag) || type->get_length(&length) != S_OK || length == 0 || length > UINT32_MAX)
    {
        return false;
    }
    kncore::FieldInfo info;
    info.Size = static_cast<uint32_t>(length);
    info.Source = L"DIAValidatedPdb";
    if (rva != nullptr)
    {
        DWORD relative = 0;
        if (symbol->get_relativeVirtualAddress(&relative) != S_OK)
        {
            return false;
        }
        *rva = relative;
    }
    BSTR typeName = nullptr;
    if (type->get_name(&typeName) == S_OK && typeName != nullptr)
    {
        info.TypeName.assign(typeName, SysStringLen(typeName));
    }
    SysFreeString(typeName);
    if (tag == SymTagArrayType)
    {
        DWORD count = 0;
        ComPtr<IDiaSymbol> element;
        ULONGLONG elementSize = 0;
        if (type->get_count(&count) != S_OK || type->get_type(&element) != S_OK || element->get_length(&elementSize) != S_OK ||
            elementSize == 0 || elementSize > UINT32_MAX)
        {
            return false;
        }
        info.Kind = kncore::FieldKind::Array;
        info.ArrayCount = count;
        info.ElementSize = static_cast<uint32_t>(elementSize);
        if (!ArrayShape(type, info))
        {
            return false;
        }
    }
    else if (tag == SymTagUDT)
    {
        info.Kind = kncore::FieldKind::Composite;
    }
    else if (tag == SymTagPointerType)
    {
        info.Kind = kncore::FieldKind::Pointer;
    }
    else if (tag == SymTagBaseType)
    {
        DWORD base = 0;
        if (type->get_baseType(&base) == S_OK)
        {
            info.Kind = base == btUInt || base == btULong ? kncore::FieldKind::Unsigned
                        : base == btInt || base == btLong ? kncore::FieldKind::Signed
                                                          : kncore::FieldKind::Unknown;
        }
    }
    if (!info.ValidFor(info.Size))
    {
        return false;
    }
    *result = info;
    return true;
}
} // namespace knengine
