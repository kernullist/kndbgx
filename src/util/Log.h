#pragma once

#include <string>

namespace knlog
{
void Write(const wchar_t *line);
void Write(const std::wstring &line);
std::wstring LogDirectory();
std::wstring SessionsDirectory();
} // namespace knlog
