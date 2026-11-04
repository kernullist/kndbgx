#pragma once

#include <string>
#include <string_view>

namespace knsnapshot
{
inline bool ServiceImagePath(std::wstring_view input, std::wstring_view windowsDirectory, std::wstring &path)
{
    path.clear();
    if (input.empty() || input.find_first_of(L"\r\n") != std::wstring_view::npos || input.find(L'\0') != std::wstring_view::npos)
    {
        return false;
    }
    if (input.front() == L'"')
    {
        if (input.size() < 3 || input.back() != L'"')
        {
            return false;
        }
        input = input.substr(1, input.size() - 2);
    }
    if (input.find(L'"') != std::wstring_view::npos)
    {
        return false;
    }
    if (input.starts_with(L"\\??\\") || input.starts_with(L"\\\\?\\"))
    {
        input.remove_prefix(4);
    }
    if (input.starts_with(L"\\SystemRoot\\"))
    {
        path = std::wstring(windowsDirectory) + L"\\" + std::wstring(input.substr(12));
    }
    else
    {
        path = input;
    }
    // Only local absolute drive paths are accepted; no service arguments or UNC.
    return path.size() > 7 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
           path[1] == L':' && path[2] == L'\\' && path.find(L':', 2) == std::wstring::npos &&
           _wcsicmp(path.c_str() + path.size() - 4, L".sys") == 0;
}
}
