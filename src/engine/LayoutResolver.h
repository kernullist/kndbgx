#pragma once

// PDB-driven type layout resolution through the hosting debugger engine,
// with a per-session cache. This is the KNDbgX equivalent of kn-live-dbg's
// LayoutResolver: scanners ask for nt!TYPE.field offsets and degrade to
// "incomplete coverage" when a field is absent from the loaded PDB.

#include <map>
#include <string>

#include "EngineCore.h"
#include "PdbMetadata.h"
#include "../core/KernelSymbolProfile.h"

namespace knengine
{
class LayoutResolver
{
  public:
    explicit LayoutResolver(DbgSession &session);

    // Base address of the nt module (cached).
    bool NtBase(ULONG64 *base);

    bool ModuleBase(const wchar_t *moduleName, ULONG64 *base);

    bool FieldOffset(const wchar_t *typeName, const wchar_t *fieldName, ULONG *offset);

    bool FieldOffset(const wchar_t *moduleName, const wchar_t *typeName, const wchar_t *fieldName, ULONG *offset);

    bool TypeSize(const wchar_t *typeName, ULONG *size);

    bool TypeSize(const wchar_t *moduleName, const wchar_t *typeName, ULONG *size);

    bool FieldSize(const wchar_t *typeName, const wchar_t *fieldName, ULONG *size);

    bool FieldSize(const wchar_t *moduleName, const wchar_t *typeName, const wchar_t *fieldName, ULONG *size);

    // Convenience for embedded structures: resolves
    // outerType.outerField first, then innerField inside that type.
    bool NestedFieldOffset(const wchar_t *outerTypeName, const wchar_t *outerFieldName, const wchar_t *innerTypeName,
                           const wchar_t *innerFieldName, ULONG *absoluteOffsetInOuter);

    void Clear();

    std::optional<kncore::FieldInfo> Field(const wchar_t *moduleName, const wchar_t *typeName, const wchar_t *fieldName);
    bool CanProfileField(const wchar_t *moduleName, const wchar_t *typeName, const wchar_t *fieldName);
    std::optional<kncore::FieldInfo> Symbol(const wchar_t *moduleName, const wchar_t *symbolName);
    bool PublicOnlySymbol(const wchar_t *moduleName, const wchar_t *symbolName);
    std::optional<uint64_t> Address(const wchar_t *moduleName, const wchar_t *symbolName);
    std::optional<kncore::ModuleIdentity> Identity(const wchar_t *moduleName);
    // Snapshot metadata must not trigger deferred symbol downloads or DIA loads.
    std::optional<kncore::ModuleIdentity> LoadedIdentity(const wchar_t *moduleName);
    std::optional<kncore::LayoutDescriptor> Describe(const wchar_t *moduleName, const wchar_t *typeName);
    std::wstring Diagnostic() const;
    bool VerifyProfile(kncore::KernelLayoutFamily family);

  private:
    std::optional<kncore::ModuleIdentity> IdentityImpl(const wchar_t *moduleName, bool loadSymbols);
    std::optional<kncore::FieldInfo> ProfileSymbol(const wchar_t *module, const wchar_t *symbolName);

    DbgSession &session_;

    std::map<std::wstring, ULONG64> moduleBaseCache_;
    kncore::SessionStamp cacheStamp_;
    std::map<std::wstring, kncore::ModuleIdentity> identities_;
    std::map<std::wstring, std::unique_ptr<PdbMetadata>> metadata_;
    std::map<std::wstring, std::wstring> metadataFailures_;
    std::map<std::wstring, std::optional<kncore::FieldInfo>> fields_;
    std::map<std::wstring, std::wstring> fieldFailures_;
    std::map<std::wstring, std::optional<kncore::FieldInfo>> symbols_;
    std::map<std::wstring, uint64_t> addresses_;
    std::wstring diagnostic_;
    void CheckStamp();
};
} // namespace knengine
