#pragma once

#include "Json.h"
#include <charconv>
#include <cmath>
#include <string_view>
#include <unordered_set>

namespace knjson::detail
{
class Parser
{
  public:
    Parser(const std::wstring &text, const ParseLimits &limits) : text_(text), limits_(limits)
    {
    }

    bool Parse(Value *out)
    {
        const bool parsed = text_.size() <= limits_.MaxInputUnits && ReadValue(out, 0);
        SkipSpace();
        return parsed && pos_ == text_.size();
    }

  private:
    void SkipSpace()
    {
        while (pos_ < text_.size() && (text_[pos_] == L' ' || text_[pos_] == L'\r' || text_[pos_] == L'\n' || text_[pos_] == L'\t'))
        {
            ++pos_;
        }
    }

    bool Take(wchar_t ch)
    {
        const bool matches = pos_ < text_.size() && text_[pos_] == ch;
        if (matches)
        {
            ++pos_;
        }
        return matches;
    }

    bool HexUnit(wchar_t *out)
    {
        unsigned code = 0;
        if (text_.size() - pos_ < 4)
        {
            return false;
        }
        for (size_t i = 0; i < 4; ++i)
        {
            const wchar_t ch = text_[pos_++];
            const int digit = ch >= L'0' && ch <= L'9'   ? ch - L'0'
                              : ch >= L'a' && ch <= L'f' ? ch - L'a' + 10
                              : ch >= L'A' && ch <= L'F' ? ch - L'A' + 10
                                                         : -1;
            if (digit < 0)
            {
                return false;
            }
            code = code * 16 + static_cast<unsigned>(digit);
        }
        *out = static_cast<wchar_t>(code);
        return true;
    }

    bool String(std::wstring *out)
    {
        if (!Take(L'"'))
        {
            return false;
        }
        bool highSurrogate = false;
        while (pos_ < text_.size())
        {
            wchar_t ch = text_[pos_++];
            if (ch == L'"')
            {
                return !highSurrogate;
            }
            if (ch < 0x20)
            {
                return false;
            }
            if (ch == L'\\')
            {
                if (pos_ == text_.size())
                {
                    return false;
                }
                switch (text_[pos_++])
                {
                case L'"':
                    ch = L'"';
                    break;
                case L'\\':
                    ch = L'\\';
                    break;
                case L'/':
                    ch = L'/';
                    break;
                case L'b':
                    ch = L'\b';
                    break;
                case L'f':
                    ch = L'\f';
                    break;
                case L'n':
                    ch = L'\n';
                    break;
                case L'r':
                    ch = L'\r';
                    break;
                case L't':
                    ch = L'\t';
                    break;
                case L'u':
                    if (!HexUnit(&ch))
                    {
                        return false;
                    }
                    break;
                default:
                    return false;
                }
            }
            if (highSurrogate)
            {
                if (ch < 0xDC00 || ch > 0xDFFF)
                {
                    return false;
                }
                highSurrogate = false;
            }
            else if (ch >= 0xDC00 && ch <= 0xDFFF)
            {
                return false;
            }
            else
            {
                highSurrogate = ch >= 0xD800 && ch <= 0xDBFF;
            }
            if (out->size() == limits_.MaxStringUnits)
            {
                return false;
            }
            out->push_back(ch);
        }
        return false;
    }

    bool Digit() const
    {
        return pos_ < text_.size() && text_[pos_] >= L'0' && text_[pos_] <= L'9';
    }

    bool Number(Value *out)
    {
        const size_t start = pos_;
        Take(L'-');
        if (!Take(L'0'))
        {
            if (!Digit())
            {
                return false;
            }
            while (Digit())
            {
                ++pos_;
            }
        }
        if (Take(L'.'))
        {
            if (!Digit())
            {
                return false;
            }
            while (Digit())
            {
                ++pos_;
            }
        }
        if (Take(L'e') || Take(L'E'))
        {
            if (!Take(L'+'))
            {
                Take(L'-');
            }
            if (!Digit())
            {
                return false;
            }
            while (Digit())
            {
                ++pos_;
            }
        }
        if (pos_ - start > 128)
        {
            return false;
        }
        std::string ascii;
        for (size_t i = start; i < pos_; ++i)
        {
            ascii.push_back(static_cast<char>(text_[i]));
        }
        double value = 0;
        const auto parsed = std::from_chars(ascii.data(), ascii.data() + ascii.size(), value);
        const bool ok = parsed.ec == std::errc() && parsed.ptr == ascii.data() + ascii.size() && std::isfinite(value);
        if (ok)
        {
            *out = Value(value);
        }
        return ok;
    }

    bool ReadValue(Value *out, size_t depth)
    {
        SkipSpace();
        if (pos_ == text_.size() || ++nodes_ > limits_.MaxNodes)
        {
            return false;
        }
        const wchar_t ch = text_[pos_];
        if (ch == L'{' || ch == L'[')
        {
            if (depth >= limits_.MaxDepth)
            {
                return false;
            }
            const bool object = ch == L'{';
            const wchar_t end = object ? L'}' : L']';
            *out = object ? Value::MakeObject() : Value::MakeArray();
            ++pos_;
            SkipSpace();
            if (Take(end))
            {
                return true;
            }
            std::unordered_set<std::wstring> keys;
            do
            {
                SkipSpace();
                std::wstring key;
                if (object)
                {
                    if (!String(&key) || !keys.insert(key).second)
                    {
                        return false;
                    }
                    SkipSpace();
                    if (!Take(L':'))
                    {
                        return false;
                    }
                }
                Value child;
                if (!ReadValue(&child, depth + 1))
                {
                    return false;
                }
                if (object)
                {
                    out->object_->emplace_back(std::move(key), std::move(child));
                }
                else
                {
                    out->Push(child);
                }
                SkipSpace();
                if (Take(end))
                {
                    return true;
                }
            } while (Take(L','));
            return false;
        }
        if (ch == L'"')
        {
            std::wstring value;
            const bool ok = String(&value);
            if (ok)
            {
                *out = Value(value);
            }
            return ok;
        }
        for (const auto literal : {std::wstring_view(L"true"), std::wstring_view(L"false"), std::wstring_view(L"null")})
        {
            if (text_.substr(pos_, literal.size()) == literal)
            {
                pos_ += literal.size();
                *out = literal == L"null" ? Value() : Value(literal == L"true");
                return true;
            }
        }
        return Number(out);
    }

    std::wstring_view text_;
    ParseLimits limits_;
    size_t pos_ = 0;
    size_t nodes_ = 0;
};
} // namespace knjson::detail
