#pragma once

#include "../core/Layout.h"
#include <memory>
#include <guiddef.h>

namespace knengine
{
class PdbMetadata
{
  public:
    PdbMetadata();
    ~PdbMetadata();
    PdbMetadata(const PdbMetadata &) = delete;
    PdbMetadata &operator=(const PdbMetadata &) = delete;
    bool Open(const std::wstring &path, const GUID &guid, uint32_t age);
    bool TypeSize(const wchar_t *typeName, uint32_t *size);
    bool Field(const wchar_t *typeName, const wchar_t *fieldName, kncore::FieldInfo *result);
    bool FieldAbsent(const wchar_t *typeName, const wchar_t *fieldName);
    bool Describe(const wchar_t *typeName, kncore::LayoutDescriptor *result);
    bool Symbol(const wchar_t *name, kncore::FieldInfo *result, uint32_t *rva = nullptr);
    bool PublicRva(const wchar_t *name, uint32_t *rva);
    bool PublicOnlySymbol(const wchar_t *name);
    std::wstring Diagnostic() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace knengine
