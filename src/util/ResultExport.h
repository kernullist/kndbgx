#pragma once

#include "ArtifactWriter.h"
#include "../core/ResultStore.h"
#include <bcrypt.h>

namespace knutil
{
class JsonArtifactSection
{
  public:
    JsonArtifactSection(ArtifactWriter &writer, const std::function<bool()> &cancelled) : writer_(writer), cancelled_(cancelled)
    {
        buffer_.reserve(65536 + 16384);
        ready_ = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
                 BCRYPT_SUCCESS(BCryptCreateHash(algorithm_, &hash_, nullptr, 0, nullptr, 0, 0));
    }
    ~JsonArtifactSection()
    {
        if (hash_ != nullptr)
        {
            BCryptDestroyHash(hash_);
        }
        if (algorithm_ != nullptr)
        {
            BCryptCloseAlgorithmProvider(algorithm_, 0);
        }
    }
    JsonArtifactSection(const JsonArtifactSection &) = delete;
    JsonArtifactSection &operator=(const JsonArtifactSection &) = delete;
    bool Emit(std::wstring_view text)
    {
        if (!ready_ || (cancelled_ && cancelled_()))
        {
            ready_ = false;
            return false;
        }
        const auto encoded = WideToUtf8(std::wstring(text));
        if ((!text.empty() && encoded.empty()) || encoded.size() > ULONG_MAX ||
            !BCRYPT_SUCCESS(
                BCryptHashData(hash_, reinterpret_cast<PUCHAR>(const_cast<char *>(encoded.data())), static_cast<ULONG>(encoded.size()), 0)))
        {
            ready_ = false;
            return false;
        }
        buffer_.append(encoded);
        return buffer_.size() < 65536 || Flush();
    }
    std::wstring Finish()
    {
        unsigned char digest[32] = {};
        if (!ready_ || !Flush() || (cancelled_ && cancelled_()) || !BCRYPT_SUCCESS(BCryptFinishHash(hash_, digest, sizeof(digest), 0)))
        {
            ready_ = false;
            return {};
        }
        ready_ = false;
        std::wstring text;
        for (unsigned char byte : digest)
        {
            constexpr wchar_t digits[] = L"0123456789abcdef";
            text.push_back(digits[byte >> 4]);
            text.push_back(digits[byte & 15]);
        }
        return text;
    }

  private:
    bool Flush()
    {
        if ((cancelled_ && cancelled_()) ||
            !writer_.Write(std::span(reinterpret_cast<const unsigned char *>(buffer_.data()), buffer_.size())))
        {
            ready_ = false;
            return false;
        }
        buffer_.clear();
        return true;
    }
    ArtifactWriter &writer_;
    const std::function<bool()> &cancelled_;
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::string buffer_;
    bool ready_ = false;
};

inline kncore::Result ExportStoredResult(const kncore::StoredResult &stored, const std::wstring &path,
                                         const std::function<bool()> &cancelled = {}, ArtifactOperations *operations = nullptr)
{
    kncore::Result result;
    result.CommandId = L"result-export";
    result.Stamp = stored.Data.Stamp;
    result.Source = L"immutable-retained-result";
    result.State = kncore::Status::IOError;
    ArtifactWriter writer(operations, cancelled);
    try
    {
        do
        {
            if ((cancelled && cancelled()) || !writer.Open(path) ||
                !writer.WriteText(L"{\"schema\":\"kndbgx.saved-result.v3\",\"resultId\":" + knjson::Value(stored.Id).Write() +
                                  L",\"result\":"))
            {
                break;
            }
            JsonArtifactSection data(writer, cancelled);
            if (!stored.Data.ToJson().WriteStream(
                    [&](std::wstring_view fragment)
                    {
                        return data.Emit(fragment);
                    }))
            {
                break;
            }
            const auto dataHash = data.Finish();
            if (dataHash.empty() || !writer.WriteText(L",\"output\":"))
            {
                break;
            }
            JsonArtifactSection output(writer, cancelled);
            if (!knjson::WriteStringStream(stored.Text,
                                           [&](std::wstring_view fragment)
                                           {
                                               return output.Emit(fragment);
                                           }))
            {
                break;
            }
            const auto outputHash = output.Finish();
            auto completion = knjson::Value::MakeObject();
            completion.Set(L"complete", knjson::Value(true));
            completion.Set(L"resultSha256", knjson::Value(dataHash));
            completion.Set(L"outputSha256", knjson::Value(outputHash));
            completion.Set(L"hashEncoding", knjson::Value(L"UTF-8 JSON value bytes written to this file"));
            if (outputHash.empty() || !writer.WriteText(L",\"completion\":" + completion.Write() + L"}\n"))
            {
                break;
            }
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"ResultArtifact"));
            row.Set(L"resultId", knjson::Value(stored.Id));
            row.Set(L"path", knjson::Value(writer.Path()));
            row.Set(L"bytes", knjson::Value(std::to_wstring(writer.Written())));
            result.Rows.Push(row);
            result.Collected.StopReason = L"ArtifactCommitted";
            if ((cancelled && cancelled()) || !writer.Commit())
            {
                result.Rows = knjson::Value::MakeArray();
                break;
            }
            result.State = kncore::Status::Success;
            result.Collected.Complete = true;
        } while (false);
    }
    catch (const std::exception &)
    {
        result.State = kncore::Status::IOError;
    }
    if (result.State != kncore::Status::Success)
    {
        result.Rows = knjson::Value::MakeArray();
        result.State = cancelled && cancelled() ? kncore::Status::Cancelled : kncore::Status::IOError;
        result.Collected.StopReason = L"ArtifactNotCommitted";
        const DWORD error = writer.Error() != 0                         ? writer.Error()
                            : result.State == kncore::Status::Cancelled ? ERROR_CANCELLED
                                                                        : ERROR_WRITE_FAULT;
        std::wstring message = L"Could not export result to \"" + path + L"\" (Win32 " + std::to_wstring(error) + L"). ";
        if (error == ERROR_DISK_FULL || error == ERROR_HANDLE_DISK_FULL)
        {
            message += L"Not enough free disk space. ";
        }
        message += L"Stored data is still available. Use result-export " + stored.Id + L" \"<path>\" to save to another destination.";
        result.Error = {L"Win32", error, L"ExportResult", std::move(message)};
    }
    return result;
}
} // namespace knutil
