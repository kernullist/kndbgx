#include "Json.h"
#include "JsonParser.h"
#include <charconv>
#include <cmath>
#include <limits>
#include <stdexcept>

#include <cstdio>
#include <cstdlib>

namespace knjson
{
namespace
{
const Value kNullValue;
constexpr size_t kMaxOutputUnits = 16 * 1024 * 1024;

void WriteEscaped(const std::wstring &text, std::wstring *out)
{
    if (out->size() > kMaxOutputUnits || kMaxOutputUnits - out->size() < 2)
    {
        throw std::length_error("JSON serialization budget exceeded");
    }
    const size_t remaining = kMaxOutputUnits - out->size();
    size_t encoded = 2;
    bool high = false;
    for (const wchar_t ch : text)
    {
        if ((high && (ch < 0xDC00 || ch > 0xDFFF)) || (!high && ch >= 0xDC00 && ch <= 0xDFFF))
        {
            throw std::domain_error("JSON string contains an unpaired surrogate");
        }
        high = !high && ch >= 0xD800 && ch <= 0xDBFF;
        const size_t units = ch == L'"' || ch == L'\\' || ch == L'\b' || ch == L'\f' || ch == L'\n' || ch == L'\r' || ch == L'\t' ? 2
                             : ch < 0x20                                                                                          ? 6
                                                                                                                                  : 1;
        if (units > remaining - encoded)
        {
            throw std::length_error("JSON serialization budget exceeded");
        }
        encoded += units;
    }
    if (high)
    {
        throw std::domain_error("JSON string contains an unpaired surrogate");
    }
    out->push_back(L'"');

    for (wchar_t ch : text)
    {
        switch (ch)
        {
        case L'"':
            out->append(L"\\\"");
            break;

        case L'\\':
            out->append(L"\\\\");
            break;

        case L'\b':
            out->append(L"\\b");
            break;

        case L'\f':
            out->append(L"\\f");
            break;

        case L'\n':
            out->append(L"\\n");
            break;

        case L'\r':
            out->append(L"\\r");
            break;

        case L'\t':
            out->append(L"\\t");
            break;

        default:
            if (ch < 0x20)
            {
                wchar_t buffer[8];
                swprintf_s(buffer, L"\\u%04x", static_cast<unsigned>(ch));
                out->append(buffer);
            }
            else
            {
                out->push_back(ch);
            }
            break;
        }
    }

    out->push_back(L'"');
}

} // namespace

Value::Value() : type_(Type::Null), bool_(false), number_(0.0)
{
}

Value::Value(bool boolean) : type_(Type::Bool), bool_(boolean), number_(0.0)
{
}

Value::Value(double number) : type_(Type::Number), bool_(false), number_(number)
{
}

Value::Value(const wchar_t *text) : type_(Type::String), bool_(false), number_(0.0), string_(text != nullptr ? text : L"")
{
}

Value::Value(const std::wstring &text) : type_(Type::String), bool_(false), number_(0.0), string_(text)
{
}

Value Value::MakeArray()
{
    Value value;
    value.type_ = Type::Array;
    value.array_.reset(new ArrayItems());
    return value;
}

Value Value::MakeObject()
{
    Value value;
    value.type_ = Type::Object;
    value.object_.reset(new ObjectFields());
    return value;
}

Type Value::GetType() const
{
    return type_;
}

bool Value::IsNull() const
{
    return type_ == Type::Null;
}

bool Value::IsObject() const
{
    return type_ == Type::Object;
}

bool Value::IsArray() const
{
    return type_ == Type::Array;
}

bool Value::IsString() const
{
    return type_ == Type::String;
}

bool Value::IsNumber() const
{
    return type_ == Type::Number;
}

bool Value::IsBool() const
{
    return type_ == Type::Bool;
}

bool Value::AsBool(bool fallback) const
{
    return type_ == Type::Bool ? bool_ : fallback;
}

double Value::AsDouble(double fallback) const
{
    return type_ == Type::Number ? number_ : fallback;
}

std::wstring Value::AsString(const std::wstring &fallback) const
{
    return type_ == Type::String ? string_ : fallback;
}

void Value::Set(const std::wstring &key, const Value &child)
{
    if (type_ != Type::Object)
    {
        return;
    }

    const Value snapshot = child;
    if (object_.use_count() != 1)
    {
        object_ = std::make_shared<ObjectFields>(*object_);
    }
    for (auto &field : *object_)
    {
        if (field.first == key)
        {
            field.second = snapshot;
            return;
        }
    }

    object_->push_back(std::make_pair(key, snapshot));
}

const Value &Value::Get(const std::wstring &key) const
{
    if (type_ == Type::Object)
    {
        for (const auto &field : *object_)
        {
            if (field.first == key)
            {
                return field.second;
            }
        }
    }

    return kNullValue;
}

void Value::Push(const Value &item)
{
    if (type_ == Type::Array)
    {
        const Value snapshot = item;
        if (array_.use_count() != 1)
        {
            array_ = std::make_shared<ArrayItems>(*array_);
        }
        array_->push_back(snapshot);
    }
}

const ObjectFields &Value::Fields() const
{
    static const ObjectFields empty;
    return type_ == Type::Object ? *object_ : empty;
}

const ArrayItems &Value::Items() const
{
    static const ArrayItems empty;
    return type_ == Type::Array ? *array_ : empty;
}

std::wstring Value::Write() const
{
    std::wstring out;
    WriteTo(&out);
    return out;
}

bool WriteStringStream(std::wstring_view text, const std::function<bool(std::wstring_view)> &emit)
{
    if (!emit)
    {
        return false;
    }
    std::wstring buffer;
    buffer.reserve(4104);
    buffer.push_back(L'"');
    bool high = false;
    for (wchar_t unit : text)
    {
        if ((high && (unit < 0xdc00 || unit > 0xdfff)) || (!high && unit >= 0xdc00 && unit <= 0xdfff))
        {
            return false;
        }
        high = !high && unit >= 0xd800 && unit <= 0xdbff;
        switch (unit)
        {
        case L'"':
            buffer.append(L"\\\"");
            break;
        case L'\\':
            buffer.append(L"\\\\");
            break;
        case L'\b':
            buffer.append(L"\\b");
            break;
        case L'\f':
            buffer.append(L"\\f");
            break;
        case L'\n':
            buffer.append(L"\\n");
            break;
        case L'\r':
            buffer.append(L"\\r");
            break;
        case L'\t':
            buffer.append(L"\\t");
            break;
        default:
            if (unit < 0x20)
            {
                wchar_t escaped[8] = {};
                swprintf_s(escaped, L"\\u%04x", static_cast<unsigned>(unit));
                buffer.append(escaped);
            }
            else
            {
                buffer.push_back(unit);
            }
            break;
        }
        if (buffer.size() >= 4096 && !high)
        {
            if (!emit(buffer))
            {
                return false;
            }
            buffer.clear();
        }
    }
    if (high)
    {
        return false;
    }
    buffer.push_back(L'"');
    return emit(buffer);
}

bool Value::WriteStream(const std::function<bool(std::wstring_view)> &emit, size_t depth) const
{
    if (!emit || depth > 128)
    {
        return false;
    }
    if (IsString())
    {
        return WriteStringStream(string_, emit);
    }
    if (!IsArray() && !IsObject())
    {
        return emit(Write());
    }
    if (!emit(IsArray() ? L"[" : L"{"))
    {
        return false;
    }
    bool first = true;
    const auto separator = [&]()
    {
        const bool ok = first || emit(L",");
        first = false;
        return ok;
    };
    if (IsArray())
    {
        for (const auto &item : Items())
        {
            if (!separator() || !item.WriteStream(emit, depth + 1))
            {
                return false;
            }
        }
    }
    else
    {
        for (const auto &[key, item] : Fields())
        {
            if (!separator() || !WriteStringStream(key, emit) || !emit(L":") || !item.WriteStream(emit, depth + 1))
            {
                return false;
            }
        }
    }
    return emit(IsArray() ? L"]" : L"}");
}

void Value::WriteTo(std::wstring *out, size_t depth) const
{
    if (depth > 128 || out->size() > kMaxOutputUnits)
    {
        throw std::length_error("JSON serialization budget exceeded");
    }
    switch (type_)
    {
    case Type::Null:
        out->append(L"null");
        break;

    case Type::Bool:
        out->append(bool_ ? L"true" : L"false");
        break;

    case Type::Number:
    {
        if (!std::isfinite(number_))
        {
            throw std::domain_error("JSON number is not finite");
        }
        char buffer[64] = {};
        const auto converted =
            std::to_chars(buffer, buffer + sizeof(buffer), number_, std::chars_format::general, std::numeric_limits<double>::max_digits10);
        if (converted.ec != std::errc())
        {
            throw std::domain_error("JSON number cannot be serialized");
        }
        out->append(buffer, converted.ptr);
        break;
    }

    case Type::String:
        WriteEscaped(string_, out);
        break;

    case Type::Array:
    {
        out->push_back(L'[');

        bool first = true;

        for (const Value &item : *array_)
        {
            if (!first)
            {
                out->push_back(L',');
            }

            first = false;
            item.WriteTo(out, depth + 1);
        }

        out->push_back(L']');
        break;
    }

    case Type::Object:
    {
        out->push_back(L'{');

        bool first = true;

        for (const auto &field : *object_)
        {
            if (!first)
            {
                out->push_back(L',');
            }

            first = false;
            WriteEscaped(field.first, out);
            out->push_back(L':');
            field.second.WriteTo(out, depth + 1);
        }

        out->push_back(L'}');
        break;
    }
    }
    if (out->size() > kMaxOutputUnits)
    {
        throw std::length_error("JSON serialization budget exceeded");
    }
}

std::wstring Escape(const std::wstring &text)
{
    std::wstring out;
    WriteEscaped(text, &out);
    return out;
}

bool Parse(const std::wstring &text, Value *out, const ParseLimits &limits)
{
    bool ok = false;

    do
    {
        if (out == nullptr || text.empty())
        {
            break;
        }

        detail::Parser parser(text, limits);
        Value parsed;

        if (!parser.Parse(&parsed))
        {
            break;
        }

        *out = parsed;
        ok = true;
    } while (false);

    return ok;
}
} // namespace knjson
