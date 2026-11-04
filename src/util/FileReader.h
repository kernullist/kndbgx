#pragma once

#include "../core/BinaryFormats.h"

namespace knutil
{
class FileReader final : public kncore::ByteReader
{
  public:
    explicit FileReader(const std::wstring &path, bool rejectReparse = false)
    {
        handle_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | (rejectReparse ? FILE_FLAG_OPEN_REPARSE_POINT : 0), nullptr);
        if (handle_ == INVALID_HANDLE_VALUE)
        {
            error_ = GetLastError();
        }
        else
        {
            FILE_ATTRIBUTE_TAG_INFO attributes = {};
            if (rejectReparse && (!GetFileInformationByHandleEx(handle_, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                                  (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0))
            {
                error_ = ERROR_INVALID_DATA;
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
                return;
            }
            LARGE_INTEGER size = {};
            const BOOL sized = GetFileSizeEx(handle_, &size);
            if (sized && size.QuadPart >= 0)
            {
                size_ = static_cast<uint64_t>(size.QuadPart);
            }
            else
            {
                error_ = sized ? ERROR_INVALID_DATA : GetLastError();
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }
    }

    ~FileReader() override
    {
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle_);
        }
    }
    FileReader(const FileReader &) = delete;
    FileReader &operator=(const FileReader &) = delete;

    bool IsOpen() const
    {
        return handle_ != INVALID_HANDLE_VALUE;
    }
    DWORD Error() const
    {
        return error_;
    }
    HANDLE NativeHandle() const
    {
        return handle_;
    }
    uint64_t Size() const override
    {
        return size_;
    }
    bool Read(uint64_t offset, std::span<unsigned char> destination) override
    {
        bool ok = false;
        do
        {
            if (!IsOpen() || !kncore::Contains(size_, offset, destination.size()) || destination.size() > MAXDWORD)
            {
                error_ = ERROR_INVALID_PARAMETER;
                break;
            }
            LARGE_INTEGER position = {};
            position.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(handle_, position, nullptr, FILE_BEGIN))
            {
                error_ = GetLastError();
                break;
            }
            DWORD transferred = 0;
            if (!ReadFile(handle_, destination.data(), static_cast<DWORD>(destination.size()), &transferred, nullptr))
            {
                error_ = GetLastError();
                break;
            }
            if (transferred != destination.size())
            {
                error_ = ERROR_HANDLE_EOF;
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

  private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    uint64_t size_ = 0;
    DWORD error_ = ERROR_SUCCESS;
};
} // namespace knutil
