#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace knutil
{
std::wstring Utf8ToWide(const char *text);
std::string WideToUtf8(const std::wstring &text);
std::wstring Trim(const std::wstring &text);
size_t Utf16PrefixUnits(std::wstring_view text, size_t maximum);

// Native command quoting follows Windows backslash-before-quote rules.
// Empty quoted arguments are preserved; malformed input produces no tokens.
bool Tokenize(const std::wstring &text, std::vector<std::wstring> *tokens, std::wstring *error = nullptr,
              std::vector<bool> *quotedArguments = nullptr);
std::vector<std::wstring> Tokenize(const std::wstring &text);

// Parses a hex integer out of dbgeng output such as
// "cr3=00000000`001ab000" or "cr3 00000000`001ab000".
bool ParseWindbgHex(const std::wstring &text, unsigned long long *value);
} // namespace knutil
