#include "Log.h"

#include <windows.h>

#include <mutex>
#include <string>

namespace knlog
{
namespace
{
std::mutex g_logLock;
const unsigned long kMaxLogBytes = 2 * 1024 * 1024;

std::wstring ExpandKndbgxPath(const wchar_t *suffix)
{
    wchar_t raw[MAX_PATH * 2] = L"%LOCALAPPDATA%\\kndbgx";
    wchar_t expanded[MAX_PATH * 2] = L"";
    wcscat_s(raw, suffix);
    ExpandEnvironmentStringsW(raw, expanded, MAX_PATH * 2);
    return std::wstring(expanded);
}

void EnsureDirectory(const std::wstring &path)
{
    CreateDirectoryW(path.c_str(), nullptr);
}
} // namespace

std::wstring LogDirectory()
{
    const std::wstring path = ExpandKndbgxPath(L"\\logs");
    EnsureDirectory(ExpandKndbgxPath(L""));
    EnsureDirectory(path);
    return path;
}

std::wstring SessionsDirectory()
{
    const std::wstring path = ExpandKndbgxPath(L"\\sessions");
    EnsureDirectory(ExpandKndbgxPath(L""));
    EnsureDirectory(path);
    return path;
}

namespace
{
bool DiagnosticsEnabled()
{
    // Environment reads are not free and diagnostics can be probed from hot
    // engine-event paths; resolve the flag once per process.
    static const bool enabled = []
    {
        wchar_t value[4] = {};
        return GetEnvironmentVariableW(L"KNDBGX_DIAGNOSTICS", value, 4) == 1 && value[0] == L'1';
    }();
    return enabled;
}
} // namespace

void Write(const wchar_t *line)
{
    if (line == nullptr)
    {
        return;
    }

    Write(std::wstring(line));
}

void Write(const std::wstring &line)
{
    if (!DiagnosticsEnabled())
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_logLock);

    do
    {
        const std::wstring dir = LogDirectory();
        const std::wstring path = dir + L"\\kndbgx.log";

        HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            break;
        }

        LARGE_INTEGER size = {};
        if (GetFileSizeEx(file, &size) && size.QuadPart > static_cast<LONGLONG>(kMaxLogBytes))
        {
            CloseHandle(file);
            const std::wstring bak = path + L".old";
            DeleteFileW(bak.c_str());
            MoveFileW(path.c_str(), bak.c_str());
            file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (file == INVALID_HANDLE_VALUE)
            {
                break;
            }
        }

        SYSTEMTIME utc = {};
        GetSystemTime(&utc);
        wchar_t stamp[64] = L"";
        swprintf_s(stamp, L"%04u-%02u-%02uT%02u:%02u:%02uZ ", utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond);

        std::wstring record = stamp;
        record += line;
        if (record.empty() || record.back() != L'\n')
        {
            record += L"\n";
        }

        const int bytes = WideCharToMultiByte(CP_UTF8, 0, record.c_str(), static_cast<int>(record.size()), nullptr, 0, nullptr, nullptr);

        if (bytes > 0)
        {
            std::string utf8(static_cast<size_t>(bytes), '\0');
            WideCharToMultiByte(CP_UTF8, 0, record.c_str(), static_cast<int>(record.size()), utf8.data(), bytes, nullptr, nullptr);
            DWORD written = 0;
            WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
        }

        CloseHandle(file);
    } while (false);
}
} // namespace knlog
