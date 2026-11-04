#pragma once

#include "Result.h"
#include <optional>
#include <map>

namespace kncore
{
struct ModuleIdentity
{
    std::wstring PdbGuid;
    uint32_t PdbAge = 0;
    uint32_t Machine = 0;
    uint32_t Timestamp = 0;
    uint32_t ImageSize = 0;
    uint64_t Base = 0;
    bool Matched = false;

    std::wstring Key() const
    {
        return PdbGuid + L":" + std::to_wstring(PdbAge) + L":" + std::to_wstring(Machine) + L":" + std::to_wstring(Timestamp) + L":" +
               std::to_wstring(ImageSize) + L":" + Hex(Base);
    }
    bool operator==(const ModuleIdentity &) const = default;
};

enum class FieldKind
{
    Unknown,
    Unsigned,
    Signed,
    Boolean,
    Pointer,
    Array,
    Composite
};

struct FieldInfo
{
    uint32_t Offset = 0;
    uint32_t Size = 0;
    FieldKind Kind = FieldKind::Unknown;
    bool FunctionPointer = false;
    std::optional<uint32_t> ArrayCount;
    std::optional<uint32_t> ElementSize;
    std::vector<uint32_t> ArrayDimensions;
    std::optional<uint32_t> LeafElementSize;
    FieldKind LeafKind = FieldKind::Unknown;
    std::wstring LeafTypeName;
    std::optional<uint32_t> BitOffset;
    std::optional<uint32_t> BitWidth;
    std::wstring TypeName;
    std::wstring Source = L"DbgEngMatchedPdb";

    bool ValidFor(uint32_t containerSize) const
    {
        bool valid = Size != 0 && Offset <= containerSize && Size <= containerSize - Offset;
        if (Kind == FieldKind::Array)
        {
            valid = valid && ArrayCount && ElementSize && *ArrayCount != 0 && *ElementSize != 0 &&
                    static_cast<uint64_t>(*ArrayCount) * *ElementSize == Size;
            if (!ArrayDimensions.empty())
            {
                valid = valid && ArrayCount && ArrayDimensions.front() == *ArrayCount;
                uint64_t elements = 1;
                for (const auto count : ArrayDimensions)
                {
                    if (count == 0 || elements > UINT32_MAX / count)
                    {
                        return false;
                    }
                    elements *= count;
                }
                valid = valid && LeafElementSize && *LeafElementSize != 0 && elements * *LeafElementSize == Size;
            }
        }
        if (BitOffset || BitWidth)
        {
            valid = valid && BitOffset && BitWidth && *BitWidth != 0 &&
                    static_cast<uint64_t>(*BitOffset) + *BitWidth <= static_cast<uint64_t>(Size) * 8;
        }
        return valid;
    }

    bool SimpleWritable() const
    {
        return !BitOffset && !BitWidth && (Size == 1 || Size == 2 || Size == 4 || Size == 8) &&
               (Kind == FieldKind::Unsigned || Kind == FieldKind::Signed || Kind == FieldKind::Boolean);
    }
};

struct LayoutDescriptor
{
    ModuleIdentity Identity;
    SessionStamp Stamp;
    std::wstring TypeName;
    uint32_t Size = 0;
    std::map<std::wstring, FieldInfo> Fields;
    std::vector<std::wstring> UnknownFields;
    bool Complete = false;
};

inline bool CorroborateField(const std::optional<FieldInfo> &metadata, const std::optional<FieldInfo> &engine, uint32_t containerSize)
{
    return metadata && metadata->ValidFor(containerSize) &&
           (!engine || (metadata->Offset == engine->Offset && metadata->Size == engine->Size));
}
} // namespace kncore
