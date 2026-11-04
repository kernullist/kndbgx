#pragma once

#include "Result.h"
#include <mutex>
#include <deque>
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <set>
#include "Input.h"

namespace kncore
{
struct StoredResult
{
    std::wstring Id;
    Result Data;
    std::wstring Text;
    size_t RetainedBytes = 0;
};

class ResultStore
{
  public:
    static constexpr size_t MaximumUiPins = 128;

    std::shared_ptr<const StoredResult> Publish(const std::wstring &id, const Result &data, const std::wstring &text)
    {
        constexpr size_t maximumUnits = 64 * 1024 * 1024 / sizeof(wchar_t);
        if (id.empty() || id.size() > 256 || !ValidUtf16(id, false) || text.size() > maximumUnits || !ValidUtf16(text))
        {
            return {};
        }
        size_t dataUnits = 0;
        try
        {
            dataUnits = data.ToJson().Write().size();
        }
        catch (const std::logic_error &)
        {
            return {};
        }
        if (dataUnits > maximumUnits - text.size())
        {
            return {};
        }
        const auto bytes = (dataUnits + text.size()) * sizeof(wchar_t);
        auto value = std::make_shared<const StoredResult>(StoredResult{id, data, text, bytes});
        std::lock_guard<std::mutex> lock(mutex_);
        if (std::any_of(values_.begin(), values_.end(),
                        [&](const auto &entry)
                        {
                            return entry->Id == id;
                        }))
        {
            return {};
        }
        size_t pinnedBytes = 0;
        size_t unpinned = 0;
        for (const auto &entry : values_)
        {
            if (uiPins_.contains(entry->Id))
            {
                pinnedBytes += entry->RetainedBytes;
            }
            else
            {
                ++unpinned;
            }
        }
        if (pinnedBytes > 64 * 1024 * 1024 - bytes)
        {
            return {};
        }
        while (unpinned >= 16 || bytes_ + bytes > 64 * 1024 * 1024)
        {
            const auto oldest = std::find_if(values_.begin(), values_.end(),
                [&](const auto &entry)
                {
                    return !uiPins_.contains(entry->Id);
                });
            bytes_ -= (*oldest)->RetainedBytes;
            values_.erase(oldest);
            --unpinned;
        }
        values_.push_back(value);
        bytes_ += bytes;
        return value;
    }
    bool SetUiPins(const std::vector<std::wstring> &ids, std::vector<std::wstring> *missing = nullptr)
    {
        if (ids.size() > MaximumUiPins || std::any_of(ids.begin(), ids.end(),
            [](const auto &id)
            {
                return id.empty() || id.size() > 256 || !ValidUtf16(id, false);
            }))
        {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        std::set<std::wstring> pins;
        if (missing != nullptr)
        {
            missing->clear();
        }
        for (const auto &id : ids)
        {
            if (std::any_of(values_.begin(), values_.end(),
                [&](const auto &entry)
                {
                    return entry->Id == id;
                }))
            {
                pins.insert(id);
            }
            else if (missing != nullptr)
            {
                missing->push_back(id);
            }
        }
        uiPins_ = std::move(pins);
        size_t unpinned = static_cast<size_t>(std::count_if(values_.begin(), values_.end(),
            [&](const auto &entry)
            {
                return !uiPins_.contains(entry->Id);
            }));
        while (unpinned > 16)
        {
            const auto oldest = std::find_if(values_.begin(), values_.end(),
                [&](const auto &entry)
                {
                    return !uiPins_.contains(entry->Id);
                });
            bytes_ -= (*oldest)->RetainedBytes;
            values_.erase(oldest);
            --unpinned;
        }
        return true;
    }
    std::shared_ptr<const StoredResult> Find(const std::wstring &id) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &value : values_)
        {
            if (value->Id == id)
            {
                return value;
            }
        }
        return {};
    }
    std::vector<std::shared_ptr<const StoredResult>> List() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return {values_.begin(), values_.end()};
    }

  private:
    mutable std::mutex mutex_;
    std::deque<std::shared_ptr<const StoredResult>> values_;
    std::set<std::wstring> uiPins_;
    size_t bytes_ = 0;
};

inline ResultStore &Results()
{
    static ResultStore store;
    return store;
}
} // namespace kncore
