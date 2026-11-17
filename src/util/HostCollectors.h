#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <fwpmu.h>
#include <memory>
#include "../core/Result.h"

namespace knutil
{
inline const wchar_t *WfpActionName(FWP_ACTION_TYPE action)
{
    switch (action)
    {
    case FWP_ACTION_BLOCK:
        return L"Block";
    case FWP_ACTION_PERMIT:
        return L"Permit";
    case FWP_ACTION_CALLOUT_TERMINATING:
        return L"Terminating callout";
    case FWP_ACTION_CALLOUT_INSPECTION:
        return L"Inspection callout";
    case FWP_ACTION_CALLOUT_UNKNOWN:
        return L"Callout (unknown termination)";
    case FWP_ACTION_CONTINUE:
        return L"Continue";
    case FWP_ACTION_NONE:
        return L"None";
    case FWP_ACTION_NONE_NO_MATCH:
        return L"No match";
    default:
        return L"Unknown";
    }
}

struct HashResult
{
    kncore::Status State = kncore::Status::IOError;
    kncore::NativeError Error;
    std::wstring Digest;
    uint64_t Bytes = 0;
};

template <typename ReadBlock> HashResult Sha256Stream(ReadBlock read)
{
    struct CngHandles
    {
        BCRYPT_ALG_HANDLE Algorithm = nullptr;
        BCRYPT_HASH_HANDLE Hash = nullptr;
        ~CngHandles()
        {
            if (Hash != nullptr)
            {
                BCryptDestroyHash(Hash);
            }
            if (Algorithm != nullptr)
            {
                BCryptCloseAlgorithmProvider(Algorithm, 0);
            }
        }
    };
    std::vector<unsigned char> object;
    CngHandles handles;
    HashResult result;
    do
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&handles.Algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        ULONG length = 0;
        ULONG objectLength = 0;
        ULONG returned = 0;
        if (BCRYPT_SUCCESS(status))
        {
            status =
                BCryptGetProperty(handles.Algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &returned, 0);
        }
        if (!BCRYPT_SUCCESS(status) || returned != sizeof(length) || length != 32)
        {
            result.Error = {L"NTSTATUS", static_cast<uint32_t>(status), L"BCryptGetProperty", L"invalid SHA-256 length"};
            break;
        }
        status = BCryptGetProperty(handles.Algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                                   &returned, 0);
        if (!BCRYPT_SUCCESS(status) || returned != sizeof(objectLength) || objectLength == 0 || objectLength > 1024 * 1024)
        {
            result.Error = {L"NTSTATUS", static_cast<uint32_t>(status), L"BCryptGetProperty", L"invalid hash object length"};
            break;
        }
        object.resize(objectLength);
        status = BCryptCreateHash(handles.Algorithm, &handles.Hash, object.data(), objectLength, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            result.Error = {L"NTSTATUS", static_cast<uint32_t>(status), L"BCryptCreateHash", L"hash initialization failed"};
            break;
        }
        std::vector<unsigned char> chunk(65536);
        bool eof = false;
        bool valid = true;
        while (!eof)
        {
            size_t transferred = 0;
            const DWORD error = read(std::span(chunk), &transferred, &eof);
            if (error != ERROR_SUCCESS || transferred > chunk.size() || (transferred == 0 && !eof) || (eof && transferred != 0))
            {
                result.State = error == ERROR_CANCELLED ? kncore::Status::Cancelled
                               : error == ERROR_TIMEOUT ? kncore::Status::Partial
                                                        : kncore::Status::IOError;
                result.Error = {L"Win32", error != 0 ? error : ERROR_INVALID_DATA, L"ReadFile", L"hash input incomplete"};
                valid = false;
                break;
            }
            if (transferred != 0)
            {
                status = BCryptHashData(handles.Hash, chunk.data(), static_cast<ULONG>(transferred), 0);
                if (!BCRYPT_SUCCESS(status))
                {
                    result.Error = {L"NTSTATUS", static_cast<uint32_t>(status), L"BCryptHashData", L"hash input failed"};
                    valid = false;
                    break;
                }
                result.Bytes += transferred;
            }
        }
        if (!valid || !eof)
        {
            break;
        }
        unsigned char digest[32] = {};
        status = BCryptFinishHash(handles.Hash, digest, sizeof(digest), 0);
        if (!BCRYPT_SUCCESS(status))
        {
            result.Error = {L"NTSTATUS", static_cast<uint32_t>(status), L"BCryptFinishHash", L"hash finalization failed"};
            break;
        }
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (const auto byte : digest)
        {
            result.Digest += hex[byte >> 4];
            result.Digest += hex[byte & 15];
        }
        result.State = kncore::Status::Success;
    } while (false);
    // The CNG object storage must outlive the hash handle.
    if (handles.Hash != nullptr)
    {
        BCryptDestroyHash(handles.Hash);
        handles.Hash = nullptr;
    }
    return result;
}

inline HashResult Sha256File(const std::wstring &path, const std::function<DWORD()> &stop = {})
{
    const auto close = [](void *handle)
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
    };
    std::unique_ptr<void, decltype(close)> file(
        CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), close);
    if (file.get() == INVALID_HANDLE_VALUE)
    {
        HashResult result;
        result.Error = {L"Win32", GetLastError(), L"CreateFileW", L"hash input cannot be opened"};
        return result;
    }
    return Sha256Stream(
        [&](std::span<unsigned char> buffer, size_t *count, bool *eof)
        {
            if (stop)
            {
                const DWORD interrupted = stop();
                if (interrupted != ERROR_SUCCESS)
                {
                    return interrupted;
                }
            }
            DWORD received = 0;
            const bool ok = ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &received, nullptr) != FALSE;
            const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            *count = received;
            *eof = ok && received == 0;
            return error;
        });
}

struct EnumerationResult
{
    kncore::Status State = kncore::Status::Unavailable;
    kncore::Coverage Coverage;
    DWORD Error = ERROR_SUCCESS;
};

template <typename Object, typename Create, typename Next, typename Destroy, typename Free, typename Visit>
EnumerationResult EnumerateWfp(
    HANDLE engine, Create create, Next next, Destroy destroy, Free free, Visit visit,
    const std::function<bool()> &cancelled =
        []
    {
        return false;
    })
{
    EnumerationResult result;
    HANDLE enumeration = nullptr;
    result.Error = create(engine, nullptr, &enumeration);
    if (result.Error != ERROR_SUCCESS || enumeration == nullptr)
    {
        if (result.Error == ERROR_SUCCESS)
        {
            result.Error = ERROR_INVALID_HANDLE;
        }
        return result;
    }
    const auto closeEnumeration = [&](void *handle)
    {
        destroy(engine, handle);
    };
    std::unique_ptr<void, decltype(closeEnumeration)> lease(enumeration, closeEnumeration);
    const auto started = std::chrono::steady_clock::now();
    while (true)
    {
        if (cancelled())
        {
            result.State = kncore::Status::Cancelled;
            result.Coverage.StopReason = L"Cancelled";
            break;
        }
        if (result.Coverage.Read >= 100000 || std::chrono::steady_clock::now() - started > std::chrono::seconds(5))
        {
            result.State = kncore::Status::Partial;
            result.Coverage.StopReason = L"BudgetExceeded";
            break;
        }
        Object **objects = nullptr;
        UINT32 count = 0;
        const UINT32 requested = static_cast<UINT32>(std::min<uint64_t>(256, 100000 - result.Coverage.Read));
        result.Error = next(engine, enumeration, requested, &objects, &count);
        const auto freePage = [&](void *pointer)
        {
            free(&pointer);
        };
        std::unique_ptr<void, decltype(freePage)> page(objects, freePage);
        if (result.Error != ERROR_SUCCESS || count > requested || (count != 0 && objects == nullptr))
        {
            if (result.Error == ERROR_SUCCESS)
            {
                result.Error = ERROR_INVALID_DATA;
            }
            result.State = result.Coverage.Read != 0 ? kncore::Status::Partial : kncore::Status::IOError;
            result.Coverage.StopReason = L"EnumerationError";
            break;
        }
        bool valid = true;
        for (UINT32 i = 0; i < count; ++i)
        {
            if (objects[i] == nullptr)
            {
                valid = false;
                break;
            }
            visit(*objects[i]);
            ++result.Coverage.Visited;
            ++result.Coverage.Read;
            ++result.Coverage.Decoded;
        }
        if (!valid)
        {
            result.State = kncore::Status::Partial;
            result.Error = ERROR_INVALID_DATA;
            result.Coverage.StopReason = L"InvalidEntry";
            break;
        }
        if (count == 0)
        {
            result.State = kncore::Status::Success;
            result.Coverage.Complete = true;
            result.Coverage.Expected = result.Coverage.Read;
            result.Coverage.StopReason = L"EndOfEnumeration";
            break;
        }
    }
    const DWORD closeError = destroy(engine, enumeration);
    lease.release();
    if (closeError != ERROR_SUCCESS)
    {
        result.Error = closeError;
        result.State = kncore::Status::IOError;
        result.Coverage.Complete = false;
    }
    return result;
}

struct FirmwareObservation
{
    DWORD Bytes = 0;
    DWORD Error = 0;
};

template <typename Query, typename LastError> FirmwareObservation QueryAcpi(DWORD table, Query query, LastError lastError)
{
    FirmwareObservation result;
    result.Bytes = query(0x41435049U, table, nullptr, 0);
    result.Error = result.Bytes == 0 ? lastError() : ERROR_SUCCESS;
    return result;
}
} // namespace knutil
