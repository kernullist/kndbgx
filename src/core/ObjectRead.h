#pragma once

#include "Process.h"

namespace kncore
{
// Insider public PDBs ship ObTypeIndexTable as untyped storage: no array
// shape, so the declared slot count is unknown. The table itself provides
// the bound — it is dense at the front and runs into a long null tail, so
// stop at the first sustained run of empty slots (or an unreadable one).
// Callers still self-verify every accepted slot, so an over-estimate can
// only add verified entries, never a wrong type index.
inline unsigned StructurallyBoundedTypeSlotCount(TargetReader &reader, uint64_t table)
{
    unsigned count = 0;
    unsigned empties = 0;
    for (unsigned slot = 0; slot < 256; ++slot)
    {
        uint64_t entry = 0;
        if (!reader.ReadExact(AddressSpace::Virtual, table + static_cast<uint64_t>(slot) * 8, &entry))
        {
            break;
        }
        if (entry == 0)
        {
            if (++empties >= 32)
            {
                break;
            }
        }
        else
        {
            empties = 0;
            count = slot + 1;
        }
    }
    return count;
}

template <typename Match, typename Cancel>
// A public symbol is only a candidate; the table and matcher corroborate it.
std::optional<unsigned> FindReferencedPointerSlot(TargetReader &reader, uint64_t reference, uint64_t table, unsigned count,
    const std::optional<FieldInfo> &index, const TargetArchitecture &architecture, Match match, Cancel cancel)
{
    const auto kernelRange = [&](uint64_t address, uint64_t size)
    {
        return ValidRange(address, size) && architecture.KernelPointer(address) && architecture.KernelPointer(address + size - 1);
    };
    if (architecture.PointerBytes != 8 || count == 0 || count > 256 || !index || index->Size != 1 ||
        index->Kind != FieldKind::Unsigned || index->BitOffset || index->BitWidth || !index->ValidFor(4096) ||
        reference % 8 != 0 || table % 8 != 0 || !kernelRange(reference, 8) || !kernelRange(table, uint64_t(count) * 8) || cancel())
    {
        return {};
    }
    uint64_t object = 0;
    if (!reader.ReadExact(AddressSpace::Virtual, reference, &object) || cancel() || object % 8 != 0 ||
        !kernelRange(object, uint64_t(index->Offset) + 1))
    {
        return {};
    }
    const auto slot = ReadField(reader, object, index);
    if (cancel() || !slot || *slot == 0 || *slot >= count)
    {
        return {};
    }
    uint64_t observed = 0;
    if (!reader.ReadExact(AddressSpace::Virtual, table + *slot * 8, &observed) || cancel() || observed != object ||
        !match(static_cast<unsigned>(*slot), object) || cancel())
    {
        return {};
    }
    return static_cast<unsigned>(*slot);
}

template <typename Match, typename Cancel>
std::optional<unsigned> FindSparsePointerSlot(TargetReader &reader, uint64_t table, unsigned count, const TargetArchitecture &architecture,
                                              Match match, Cancel cancel)
{
    if (count == 0 || count > 256 || architecture.PointerBytes != 8 || !ValidRange(table, uint64_t(count) * 8))
    {
        return {};
    }
    for (unsigned slot = 0; slot < count && !cancel(); ++slot)
    {
        uint64_t object = 0;
        if (reader.ReadExact(AddressSpace::Virtual, table + uint64_t(slot) * 8, &object) && object != 0 &&
            architecture.KernelPointer(object) && match(slot, object))
        {
            return slot;
        }
    }
    return {};
}

inline std::optional<std::wstring> NormalizeDriverName(const std::wstring &input)
{
    std::wstring name = input;
    if (FoldName(name).starts_with(L"\\driver\\"))
    {
        name.erase(0, 8);
    }
    if (name.empty() || name.find_first_of(L"\\/:") != std::wstring::npos)
    {
        return {};
    }
    return L"\\Driver\\" + name;
}

inline bool ReadUnicodeValue(TargetReader &reader, uint64_t object, const std::optional<FieldInfo> &lengthField,
                             const std::optional<FieldInfo> &maximumField, const std::optional<FieldInfo> &bufferField,
                             const TargetArchitecture &architecture, std::wstring *text)
{
    if (text == nullptr || !architecture.KernelPointer(object) || !lengthField || !maximumField || !bufferField || lengthField->Size != 2 ||
        maximumField->Size != 2 || bufferField->Size != architecture.PointerBytes)
    {
        return false;
    }
    const auto length = ReadField(reader, object, lengthField);
    const auto maximum = ReadField(reader, object, maximumField);
    const auto buffer = ReadField(reader, object, bufferField);
    if (!length || !maximum || !buffer || *length > *maximum || *length > 2048 || *length % 2 != 0)
    {
        return false;
    }
    if (*length == 0)
    {
        text->clear();
        return true;
    }
    // This reader resolves names stored in kernel objects, independent of process context.
    if (!architecture.KernelPointer(*buffer) || !ValidRange(*buffer, *length) || !architecture.KernelPointer(*buffer + *length - 1))
    {
        return false;
    }
    const auto read = reader.Read(AddressSpace::Virtual, *buffer, static_cast<size_t>(*length));
    if (!ExactBytes(read, static_cast<size_t>(*length)))
    {
        return false;
    }
    std::wstring result(static_cast<size_t>(*length / 2), L'\0');
    std::memcpy(result.data(), read.Bytes.data(), static_cast<size_t>(*length));
    for (size_t i = 0; i < result.size(); ++i)
    {
        const wchar_t unit = result[i];
        if (unit == 0 || (unit >= 0xdc00 && unit <= 0xdfff))
        {
            return false;
        }
        if (unit >= 0xd800 && unit <= 0xdbff)
        {
            if (++i >= result.size() || result[i] < 0xdc00 || result[i] > 0xdfff)
            {
                return false;
            }
        }
    }
    *text = std::move(result);
    return true;
}
} // namespace kncore
