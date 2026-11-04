#pragma once

#include "Result.h"
#include <deque>
#include <mutex>
#include <optional>

namespace kncore
{
struct NavigationPoint
{
    SessionStamp Stamp;
    std::wstring Space;
    uint64_t Address = 0;
    std::optional<uint64_t> Dtb;
    knjson::Value Observation = knjson::Value::MakeObject();
    std::wstring Note;
    knjson::Value ToJson(const SessionStamp &current) const
    {
        auto row = Observation;
        row.Set(L"target", Stamp.ToJson());
        row.Set(L"historical", knjson::Value(Stamp != current));
        row.Set(L"addressSpace", knjson::Value(Space));
        row.Set(L"address", knjson::Value(Hex(Address)));
        row.Set(L"dtb", Dtb ? knjson::Value(Hex(*Dtb)) : knjson::Value());
        row.Set(L"note", knjson::Value(Note));
        return row;
    }
};

class NavigationStore
{
  public:
    bool Push(NavigationPoint point)
    {
        if ((point.Space != L"virtual" && point.Space != L"physical") || point.Stamp.SessionId.empty())
        {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        if (!history_.empty())
        {
            history_.erase(history_.begin() + position_ + 1, history_.end());
        }
        history_.push_back(std::move(point));
        if (history_.size() > 256)
        {
            history_.pop_front();
        }
        position_ = history_.size() - 1;
        return true;
    }
    std::optional<NavigationPoint> Move(int direction)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (history_.empty() || (direction < 0 && position_ == 0) || (direction > 0 && position_ + 1 == history_.size()))
        {
            return std::nullopt;
        }
        position_ = static_cast<size_t>(static_cast<int64_t>(position_) + direction);
        return history_[position_];
    }
    std::optional<NavigationPoint> Current() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return history_.empty() ? std::nullopt : std::optional<NavigationPoint>(history_[position_]);
    }
    bool Bookmark(const std::wstring &note)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (history_.empty() || note.size() > 1024 || bookmarks_.size() >= 256)
        {
            return false;
        }
        auto point = history_[position_];
        point.Note = note;
        bookmarks_.push_back(std::move(point));
        return true;
    }
    knjson::Value List(const SessionStamp &current, bool bookmarks) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto rows = knjson::Value::MakeArray();
        for (const auto &point : bookmarks ? bookmarks_ : history_)
        {
            rows.Push(point.ToJson(current));
        }
        return rows;
    }

  private:
    mutable std::mutex mutex_;
    std::deque<NavigationPoint> history_;
    std::deque<NavigationPoint> bookmarks_;
    size_t position_ = 0;
};

inline NavigationStore &Navigation()
{
    static NavigationStore store;
    return store;
}
} // namespace kncore
