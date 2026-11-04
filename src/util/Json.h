#pragma once

// Minimal JSON parser and writer for the WebView2 bridge protocol.
//
// The protocol only needs objects, arrays, strings, numbers (integral
// range), booleans and null. The parser is a straightforward recursive
// descent implementation; the writer is a tiny builder.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <functional>
#include <string_view>

namespace knjson
{
namespace detail
{
class Parser;
}
class Value;

typedef std::vector<std::pair<std::wstring, Value>> ObjectFields;
typedef std::vector<Value> ArrayItems;

enum class Type
{
    Null,
    Bool,
    Number,
    String,
    Array,
    Object
};

class Value
{
  public:
    Value();
    explicit Value(bool boolean);
    explicit Value(double number);
    explicit Value(const wchar_t *text);
    explicit Value(const std::wstring &text);

    static Value MakeArray();
    static Value MakeObject();

    Type GetType() const;

    bool IsNull() const;
    bool IsObject() const;
    bool IsArray() const;
    bool IsString() const;
    bool IsNumber() const;
    bool IsBool() const;

    bool AsBool(bool fallback) const;
    double AsDouble(double fallback) const;
    std::wstring AsString(const std::wstring &fallback) const;

    // Object helpers. Get returns a null Value when the key is missing.
    void Set(const std::wstring &key, const Value &child);
    const Value &Get(const std::wstring &key) const;

    // Array helper.
    void Push(const Value &item);

    const ObjectFields &Fields() const;
    const ArrayItems &Items() const;

    std::wstring Write() const;
    // Streams bounded UTF-16 fragments without constructing a whole document.
    bool WriteStream(const std::function<bool(std::wstring_view)> &emit, size_t depth = 0) const;

  private:
    friend class detail::Parser;
    void WriteTo(std::wstring *out, size_t depth = 0) const;

    Type type_;
    bool bool_;
    double number_;
    std::wstring string_;
    std::shared_ptr<ArrayItems> array_;
    std::shared_ptr<ObjectFields> object_;
};

struct ParseLimits
{
    size_t MaxInputUnits = 8 * 1024 * 1024;
    size_t MaxStringUnits = 1024 * 1024;
    size_t MaxNodes = 100000;
    size_t MaxDepth = 32;
};

// Strict UTF-16; duplicate keys and unpaired surrogates are rejected.
bool Parse(const std::wstring &text, Value *out, const ParseLimits &limits = {});

std::wstring Escape(const std::wstring &text);
bool WriteStringStream(std::wstring_view text, const std::function<bool(std::wstring_view)> &emit);
} // namespace knjson
