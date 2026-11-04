#pragma once

#include "Result.h"
#include <algorithm>
#include <optional>

namespace kncore
{
struct ImageRange
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    std::wstring Name;
    std::wstring Identity;
};

enum class OwnershipState
{
    Owned,
    OutsideCollectedImages,
    Unknown
};
struct AddressOwnership
{
    OwnershipState State = OwnershipState::Unknown;
    std::optional<ImageRange> Image;
    uint64_t Rva = 0;
    std::wstring Reason;
};

class OwnershipIndex
{
  public:
    OwnershipIndex(std::vector<ImageRange> images, bool complete, const SessionStamp &stamp) : complete_(complete), stamp_(stamp)
    {
        std::sort(images.begin(), images.end(),
                  [](const auto &left, const auto &right)
                  {
                      return left.Base < right.Base;
                  });
        uint64_t end = 0;
        for (auto &image : images)
        {
            if (image.Size == 0 || !ValidRange(image.Base, image.Size))
            {
                complete_ = false;
                continue;
            }
            end = std::max(end, image.Base + (image.Size - 1));
            entries_.push_back({std::move(image), end});
        }
    }

    AddressOwnership Find(uint64_t address, const SessionStamp &stamp) const
    {
        AddressOwnership result;
        if (stamp != stamp_)
        {
            result.Reason = L"StaleModuleInventory";
            return result;
        }
        auto it = std::upper_bound(entries_.begin(), entries_.end(), address,
                                   [](uint64_t value, const Entry &entry)
                                   {
                                       return value < entry.Image.Base;
                                   });
        while (it != entries_.begin())
        {
            --it;
            if (it->PrefixEnd < address)
            {
                break;
            }
            if (address >= it->Image.Base && address - it->Image.Base < it->Image.Size)
            {
                if (result.Image)
                {
                    result = {};
                    result.Reason = L"OverlappingModuleRanges";
                    return result;
                }
                result.Image = it->Image;
                result.Rva = address - it->Image.Base;
            }
        }
        result.State = result.Image ? OwnershipState::Owned : complete_ ? OwnershipState::OutsideCollectedImages : OwnershipState::Unknown;
        result.Reason = result.Image ? L"ObservedImageRange"
                        : complete_  ? L"NoCollectedImageContainsAddress"
                                     : L"IncompleteModuleInventory";
        return result;
    }

  private:
    struct Entry
    {
        ImageRange Image;
        uint64_t PrefixEnd;
    };
    std::vector<Entry> entries_;
    bool complete_;
    SessionStamp stamp_;
};
} // namespace kncore
