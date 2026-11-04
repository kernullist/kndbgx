#pragma once

#include <windows.h>
#include <objbase.h>
#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <functional>
#include "Text.h"

namespace knutil
{
class ArtifactOperations
{
  public:
    virtual ~ArtifactOperations() = default;
    virtual HANDLE Create(const std::wstring &path, DWORD *error) = 0;
    virtual bool Write(HANDLE handle, std::span<const unsigned char> bytes, DWORD *transferred, DWORD *error) = 0;
    virtual bool Flush(HANDLE handle, DWORD *error) = 0;
    virtual bool Close(HANDLE handle, DWORD *error) = 0;
    virtual bool Commit(const std::wstring &temporary, const std::wstring &finalPath, bool overwrite, DWORD *error) = 0;
    virtual void Remove(const std::wstring &path) = 0;
};

class WindowsArtifactOperations final : public ArtifactOperations
{
  public:
    HANDLE Create(const std::wstring &path, DWORD *error) override
    {
        const HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        *error = handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        return handle;
    }
    bool Write(HANDLE handle, std::span<const unsigned char> bytes, DWORD *transferred, DWORD *error) override
    {
        const bool ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), transferred, nullptr) != FALSE;
        *error = ok ? ERROR_SUCCESS : GetLastError();
        return ok;
    }
    bool Flush(HANDLE handle, DWORD *error) override
    {
        const bool ok = FlushFileBuffers(handle) != FALSE;
        *error = ok ? ERROR_SUCCESS : GetLastError();
        return ok;
    }
    bool Close(HANDLE handle, DWORD *error) override
    {
        const bool ok = CloseHandle(handle) != FALSE;
        *error = ok ? ERROR_SUCCESS : GetLastError();
        return ok;
    }
    bool Commit(const std::wstring &temporary, const std::wstring &finalPath, bool overwrite, DWORD *error) override
    {
        const DWORD flags = MOVEFILE_WRITE_THROUGH | (overwrite ? MOVEFILE_REPLACE_EXISTING : 0);
        const bool ok = MoveFileExW(temporary.c_str(), finalPath.c_str(), flags) != FALSE;
        *error = ok ? ERROR_SUCCESS : GetLastError();
        return ok;
    }
    void Remove(const std::wstring &path) override
    {
        DeleteFileW(path.c_str());
    }
};

inline std::wstring UniqueSuffix()
{
    GUID guid = {};
    wchar_t text[40] = {};
    if (FAILED(CoCreateGuid(&guid)) || StringFromGUID2(guid, text, 40) == 0)
    {
        return {};
    }
    return std::wstring(text);
}

class ArtifactWriter
{
  public:
    explicit ArtifactWriter(ArtifactOperations *operations = nullptr, std::function<bool()> cancelled = {})
        : operations_(operations != nullptr ? operations : &DefaultOperations()), cancelled_(std::move(cancelled))
    {
    }
    ~ArtifactWriter()
    {
        Abort();
    }
    ArtifactWriter(const ArtifactWriter &) = delete;
    ArtifactWriter &operator=(const ArtifactWriter &) = delete;

    bool Open(const std::wstring &path, bool overwrite = false)
    {
        bool ok = false;
        Abort();
        error_ = ERROR_SUCCESS;
        failed_ = false;
        committed_ = false;
        bytes_ = 0;
        do
        {
            if (path.empty() || path.find(L'\0') != std::wstring::npos || path.back() == L'\\' || path.back() == L'/')
            {
                error_ = ERROR_INVALID_NAME;
                break;
            }
            const DWORD count = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
            if (count == 0 || count > 32768)
            {
                error_ = ERROR_INVALID_NAME;
                break;
            }
            std::wstring full(count, L'\0');
            const DWORD written = GetFullPathNameW(path.c_str(), count, full.data(), nullptr);
            if (written == 0 || written >= count)
            {
                error_ = ERROR_INVALID_NAME;
                break;
            }
            full.resize(written);
            const auto suffix = UniqueSuffix();
            if (suffix.empty())
            {
                error_ = ERROR_GEN_FAILURE;
                break;
            }
            path_ = std::move(full);
            temporary_ = path_ + L".knx-" + suffix + L".tmp";
            overwrite_ = overwrite;
            handle_ = operations_->Create(temporary_, &error_);
            ok = handle_ != INVALID_HANDLE_VALUE;
            if (!ok)
            {
                temporary_.clear();
            }
        } while (false);
        failed_ = !ok;
        return ok;
    }

    bool Write(std::span<const unsigned char> bytes)
    {
        if (failed_ || handle_ == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        size_t offset = 0;
        while (offset < bytes.size())
        {
            if (Cancelled())
            {
                break;
            }
            const size_t chunk = std::min<size_t>(bytes.size() - offset, 65536);
            DWORD transferred = 0;
            const bool ok = operations_->Write(handle_, bytes.subspan(offset, chunk), &transferred, &error_);
            if (transferred <= chunk)
            {
                bytes_ += transferred;
            }
            if (!ok || transferred == 0 || transferred > chunk)
            {
                if (error_ == ERROR_SUCCESS)
                {
                    error_ = ERROR_WRITE_FAULT;
                }
                failed_ = true;
                break;
            }
            offset += transferred;
        }
        return !failed_;
    }

    bool WriteText(const std::wstring &text)
    {
        const std::string bytes = WideToUtf8(text);
        if (!text.empty() && bytes.empty())
        {
            failed_ = true;
            error_ = ERROR_NO_UNICODE_TRANSLATION;
            return false;
        }
        return Write(std::span(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size()));
    }

    template <typename Producer> bool ProduceNative(Producer producer)
    {
        if (!IsOpen() || !producer(handle_))
        {
            failed_ = true;
            error_ = ERROR_WRITE_FAULT;
            return false;
        }
        LARGE_INTEGER size = {};
        if (!GetFileSizeEx(handle_, &size) || size.QuadPart <= 0)
        {
            failed_ = true;
            error_ = ERROR_INVALID_DATA;
            return false;
        }
        bytes_ = static_cast<uint64_t>(size.QuadPart);
        return true;
    }

    bool Commit()
    {
        bool ok = false;
        do
        {
            if (failed_ || handle_ == INVALID_HANDLE_VALUE || committed_ || Cancelled())
            {
                break;
            }
            if (!operations_->Flush(handle_, &error_))
            {
                break;
            }
            if (!operations_->Close(handle_, &error_))
            {
                break;
            }
            handle_ = INVALID_HANDLE_VALUE;
            if (Cancelled())
            {
                break;
            }
            if (!operations_->Commit(temporary_, path_, overwrite_, &error_))
            {
                break;
            }
            temporary_.clear();
            committed_ = true;
            ok = true;
        } while (false);
        if (!ok)
        {
            failed_ = true;
        }
        return ok;
    }

    void Abort()
    {
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            DWORD ignored = 0;
            operations_->Close(handle_, &ignored);
            handle_ = INVALID_HANDLE_VALUE;
        }
        if (!temporary_.empty())
        {
            operations_->Remove(temporary_);
            temporary_.clear();
        }
    }

    bool IsOpen() const
    {
        return handle_ != INVALID_HANDLE_VALUE && !failed_;
    }
    DWORD Error() const
    {
        return error_;
    }
    uint64_t Written() const
    {
        return bytes_;
    }
    const std::wstring &Path() const
    {
        return path_;
    }

  private:
    bool Cancelled()
    {
        if (cancelled_ && cancelled_())
        {
            error_ = ERROR_CANCELLED;
            failed_ = true;
        }
        return error_ == ERROR_CANCELLED;
    }
    static ArtifactOperations &DefaultOperations()
    {
        static WindowsArtifactOperations operations;
        return operations;
    }
    ArtifactOperations *operations_;
    std::function<bool()> cancelled_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    DWORD error_ = ERROR_SUCCESS;
    uint64_t bytes_ = 0;
    bool failed_ = false;
    bool committed_ = false;
    bool overwrite_ = false;
    std::wstring path_;
    std::wstring temporary_;
};
} // namespace knutil
