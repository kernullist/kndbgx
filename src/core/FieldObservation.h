#pragma once

#include "CollectorRead.h"
#include <bit>

namespace kncore
{
inline knjson::Value ScalarFieldObservation(const FieldInfo &field, const ReadResult &read)
{
    if ((field.Size != 1 && field.Size != 2 && field.Size != 4 && field.Size != 8) || !ExactBytes(read, field.Size) ||
        (field.Kind != FieldKind::Unsigned && field.Kind != FieldKind::Signed && field.Kind != FieldKind::Boolean &&
         field.Kind != FieldKind::Pointer))
    {
        return {};
    }
    uint64_t raw = 0;
    std::memcpy(&raw, read.Bytes.data(), field.Size);
    unsigned bits = field.Size * 8;
    if (field.BitOffset || field.BitWidth)
    {
        if (!field.BitOffset || !field.BitWidth || *field.BitWidth == 0 || *field.BitWidth > bits ||
            *field.BitOffset > bits - *field.BitWidth)
        {
            return {};
        }
        bits = *field.BitWidth;
        raw >>= *field.BitOffset;
        raw &= bits == 64 ? UINT64_MAX : (uint64_t(1) << bits) - 1;
    }
    if (field.Kind == FieldKind::Signed)
    {
        if (bits < 64 && (raw & (uint64_t(1) << (bits - 1))) != 0)
        {
            raw |= UINT64_MAX << bits;
        }
        return knjson::Value(std::to_wstring(std::bit_cast<int64_t>(raw)));
    }
    return field.Kind == FieldKind::Boolean ? knjson::Value(raw != 0) : knjson::Value(Hex(raw));
}
} // namespace kncore
