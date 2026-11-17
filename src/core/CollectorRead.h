#pragma once

#include "Layout.h"
#include "Walker.h"
#include <algorithm>

namespace kncore
{
// A terminal target failure ends the collection, including fallback reads.
class CollectionReadGuard final : public TargetReader
{
  public:
    CollectionReadGuard(TargetReader &source, WalkBudget &budget) : source_(source), budget_(budget)
    {
    }

    ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
    {
        if (budget_.Stopped)
        {
            ReadResult result;
            result.Space = space;
            result.Address = address;
            result.Requested = length;
            result.State = budget_.Report.State;
            return result;
        }
        auto result = source_.Read(space, address, length);
        if (result.State == Status::Cancelled || result.State == Status::StaleContext || result.State == Status::InternalFault)
        {
            budget_.Stop(result.State, L"CollectionReadStopped");
        }
        return result;
    }

  private:
    TargetReader &source_;
    WalkBudget &budget_;
};

inline std::optional<FieldInfo> NestedField(const std::optional<FieldInfo> &outer, const std::optional<FieldInfo> &inner)
{
    if (!outer || !inner || outer->Kind != FieldKind::Composite || outer->BitOffset || outer->BitWidth || !outer->ValidFor(UINT32_MAX) ||
        !inner->ValidFor(outer->Size) || inner->Offset > UINT32_MAX - outer->Offset)
    {
        return {};
    }
    auto field = *inner;
    field.Offset += outer->Offset;
    return field;
}

inline bool ExactBytes(const ReadResult &read, size_t length)
{
    return read.State == Status::Success && read.Transferred == length && read.Bytes.size() == length && read.Valid.size() == length &&
           std::all_of(read.Valid.begin(), read.Valid.end(),
                       [](unsigned char byte)
                       {
                           return byte != 0;
                       });
}

inline std::optional<uint64_t> ReadField(TargetReader &reader, uint64_t object, const std::optional<FieldInfo> &field)
{
    std::optional<uint64_t> value;
    if (field && (field->Size == 1 || field->Size == 2 || field->Size == 4 || field->Size == 8) &&
        ValidRange(object, static_cast<uint64_t>(field->Offset) + field->Size))
    {
        const auto read = reader.Read(AddressSpace::Virtual, object + field->Offset, field->Size);
        if (ExactBytes(read, field->Size))
        {
            uint64_t raw = 0;
            std::memcpy(&raw, read.Bytes.data(), field->Size);
            if (field->BitOffset && field->BitWidth && *field->BitWidth != 0 && *field->BitWidth <= field->Size * 8 &&
                *field->BitOffset <= field->Size * 8 - *field->BitWidth)
            {
                raw >>= *field->BitOffset;
                raw &= *field->BitWidth == 64 ? UINT64_MAX : (uint64_t(1) << *field->BitWidth) - 1;
            }
            else if (field->BitOffset || field->BitWidth)
            {
                return value;
            }
            value = raw;
        }
    }
    return value;
}

inline knjson::Value OptionalNumber(std::optional<uint64_t> value, bool hex = false)
{
    return value ? knjson::Value(hex ? Hex(*value) : std::to_wstring(*value)) : knjson::Value();
}

inline std::optional<uint64_t> ReadIndirectKernelPointer(TargetReader &reader, const TargetArchitecture &architecture, uint64_t object,
                                                         const std::optional<FieldInfo> &through, const std::optional<FieldInfo> &field)
{
    if (!architecture.KernelPointer(object) || !through || !field || through->Kind != FieldKind::Pointer ||
        field->Kind != FieldKind::Pointer || through->Size != architecture.PointerBytes || field->Size != architecture.PointerBytes ||
        through->BitOffset || through->BitWidth || field->BitOffset || field->BitWidth)
    {
        return {};
    }
    const auto block = ReadField(reader, object, through);
    if (block == 0)
    {
        return 0;
    }
    if (!block || !architecture.KernelPointer(*block))
    {
        return {};
    }
    const auto pointer = ReadField(reader, *block, field);
    return pointer && (*pointer == 0 || architecture.KernelPointer(*pointer)) ? pointer : std::nullopt;
}

template <typename Visitor>
bool WalkList(TargetReader &reader, uint64_t head, const TargetArchitecture &architecture, WalkBudget &budget, Visitor visitor,
              const std::function<void(uint64_t)> &prepare = {})
{
    uint64_t first = 0;
    uint64_t last = 0;
    if (!architecture.KernelPointer(head) || !ValidRange(head, 2 * architecture.PointerBytes) ||
        !ReadPointer(reader, head, architecture.PointerBytes, &first) ||
        !ReadPointer(reader, head + architecture.PointerBytes, architecture.PointerBytes, &last))
    {
        if (budget.Stopped)
        {
            return false;
        }
        ++budget.Report.Collected.Unreadable;
        return budget.Stop(Status::Unavailable, L"UnreadableListHead");
    }
    uint64_t previous = head;
    const bool walked = WalkChain(reader, first, head, 0, architecture, budget,
                                  [&](uint64_t node)
                                  {
                                      uint64_t backlink = 0;
                                      if (!architecture.KernelPointer(node) || !ValidRange(node, 2 * architecture.PointerBytes) ||
                                          !ReadPointer(reader, node + architecture.PointerBytes, architecture.PointerBytes, &backlink))
                                      {
                                          if (budget.Stopped)
                                          {
                                              return VisitDecision::Failed;
                                          }
                                          ++budget.Report.Collected.Unreadable;
                                          budget.Stop(Status::Partial, L"UnreadableBacklink");
                                          return VisitDecision::Failed;
                                      }
                                      if (budget.Stopped)
                                      {
                                          return VisitDecision::Failed;
                                      }
                                      if (backlink != previous)
                                      {
                                          budget.Stop(Status::Partial, L"InconsistentBacklink");
                                          return VisitDecision::Failed;
                                      }
                                      previous = node;
                                      return visitor(node);
                                  }, prepare);
    if (walked && !budget.Stopped && previous != last)
    {
        return budget.Stop(Status::Partial, L"InconsistentHeadBacklink");
    }
    return walked;
}
} // namespace kncore
