#pragma once

#include "../core/Snapshot.h"
#include "FileReader.h"
#include "ArtifactWriter.h"
#include "HostCollectors.h"
#include <filesystem>
#include <stdexcept>

namespace knutil
{
inline std::wstring Sha256Bytes(std::span<const unsigned char> bytes)
{
    size_t offset = 0;
    return Sha256Stream(
               [&](std::span<unsigned char> chunk, size_t *count, bool *eof)
               {
                   *count = std::min(chunk.size(), bytes.size() - offset);
                   std::copy_n(bytes.begin() + offset, *count, chunk.begin());
                   offset += *count;
                   *eof = *count == 0;
                   return DWORD(ERROR_SUCCESS);
               })
        .Digest;
}

inline bool StrictUtf8(std::span<const unsigned char> bytes, std::wstring &text)
{
    text.clear();
    if (bytes.empty() || bytes.size() > INT_MAX)
    {
        return false;
    }
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char *>(bytes.data()),
                                          static_cast<int>(bytes.size()), nullptr, 0);
    if (count <= 0)
    {
        return false;
    }
    text.resize(count);
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char *>(bytes.data()), static_cast<int>(bytes.size()),
                               text.data(), count) == count;
}

inline bool ReadArtifact(const std::wstring &path, std::vector<unsigned char> &bytes, uint64_t maximum)
{
    FileReader file(path, true);
    if (!file.IsOpen() || file.Size() == 0 || file.Size() > maximum)
    {
        return false;
    }
    bytes.resize(static_cast<size_t>(file.Size()));
    return file.Read(0, bytes);
}

inline bool ReadArtifactJson(const std::wstring &path, knjson::Value &value, uint64_t maximum = 1024 * 1024)
{
    std::vector<unsigned char> bytes;
    std::wstring text;
    return ReadArtifact(path, bytes, maximum) && StrictUtf8(bytes, text) && knjson::Parse(text, &value);
}

inline bool EncodeSnapshotJson(const knjson::Value &value, size_t maximumUnits, size_t maximumBytes, std::wstring &text)
{
    try
    {
        text = value.Write();
        knjson::Value decoded;
        return text.size() <= maximumUnits && WideToUtf8(text).size() <= maximumBytes && knjson::Parse(text, &decoded);
    }
    catch (const std::logic_error &)
    {
        return false;
    }
}

inline bool MatchesSnapshotHash(std::span<const unsigned char> bytes, const std::wstring &expected)
{
    // An unavailable digest must never match an absent checksum.
    return expected.size() == 64 && Sha256Bytes(bytes) == expected;
}

inline kncore::Result SaveSnapshot(const std::wstring &path, const kncore::Snapshot &snapshot, const std::function<bool()> &cancelled = {})
{
    kncore::Result report;
    report.Source = L"SnapshotArtifactWriter";
    report.State = kncore::Status::IOError;
    const auto stop = [&]()
    {
        if (cancelled && cancelled())
        {
            report.State = kncore::Status::Cancelled;
            report.Error = {L"Win32", ERROR_CANCELLED, L"SaveSnapshot", L"Snapshot cancelled before directory publication"};
            return true;
        }
        return false;
    };
    if (stop())
    {
        return report;
    }
    if (path.find(L'\0') != std::wstring::npos || !kncore::ValidSnapshot(snapshot))
    {
        report.State = kncore::Status::InvalidInput;
        report.Error.Message = L"Snapshot schema invalid";
        return report;
    }
    const auto suffix = UniqueSuffix();
    std::error_code error;
    const auto finalPath = std::filesystem::absolute(std::filesystem::path(path), error).lexically_normal();
    if (error || path.empty() || suffix.empty() || finalPath.filename().empty() || std::filesystem::exists(finalPath, error))
    {
        report.Error.Message = L"Snapshot destination invalid or already exists";
        return report;
    }
    const auto temporary = std::filesystem::path(finalPath.wstring() + L".knx-" + suffix + L".tmp");
    if (!CreateDirectoryW(temporary.c_str(), nullptr))
    {
        report.Error = {L"Win32", GetLastError(), L"CreateDirectoryW", L"Snapshot staging directory unavailable"};
        return report;
    }
    struct Staging
    {
        std::filesystem::path Directory;
        std::vector<std::wstring> Files;
        bool Committed = false;
        ~Staging()
        {
            if (!Committed)
            {
                // Only exact files created by this operation are removed.
                for (const auto &leaf : Files)
                {
                    DeleteFileW((Directory / leaf).c_str());
                }
                RemoveDirectoryW(Directory.c_str());
            }
        }
    } staging{temporary};
    auto manifest = snapshot.Metadata;
    auto files = knjson::Value::MakeArray();
    auto checksums = knjson::Value::MakeObject();
    checksums.Set(L"schema", knjson::Value(L"kndbgx.checksums.v1"));
    auto digests = knjson::Value::MakeObject();
    uint64_t total = 0;
    for (const auto &[name, collection] : snapshot.Collections)
    {
        if (stop())
        {
            return report;
        }
        const auto leaf = name + L".jsonl";
        if (!kncore::SnapshotLeaf(leaf))
        {
            report.State = kncore::Status::InvalidInput;
            return report;
        }
        ArtifactWriter writer(nullptr, stop);
        if (!writer.Open((temporary / leaf).wstring()))
        {
            return report;
        }
        auto metadata = collection;
        metadata.Set(L"rows", knjson::Value::MakeArray());
        auto first = knjson::Value::MakeObject();
        first.Set(L"type", knjson::Value(L"metadata"));
        first.Set(L"schema", knjson::Value(L"kndbgx.snapshot-collection.v2"));
        first.Set(L"collector", knjson::Value(name));
        first.Set(L"result", metadata);
        std::wstring line;
        if (!EncodeSnapshotJson(first, 512 * 1024, 64 * 1024 * 1024, line))
        {
            report.State = kncore::Status::InvalidInput;
            report.Error.Message = L"Snapshot metadata exceeds import limits";
            return report;
        }
        bool written = writer.WriteText(line + L"\n");
        for (const auto &row : collection.Get(L"rows").Items())
        {
            auto record = knjson::Value::MakeObject();
            record.Set(L"type", knjson::Value(L"record"));
            record.Set(L"data", row);
            if (!EncodeSnapshotJson(record, 512 * 1024, 64 * 1024 * 1024, line))
            {
                report.State = kncore::Status::InvalidInput;
                report.Error.Message = L"Snapshot row exceeds import limits";
                return report;
            }
            written = written && writer.WriteText(line + L"\n") && writer.Written() <= 64 * 1024 * 1024;
            if (!written)
            {
                break;
            }
        }
        auto footer = knjson::Value::MakeObject();
        footer.Set(L"type", knjson::Value(L"completion"));
        footer.Set(L"records", knjson::Value(std::to_wstring(collection.Get(L"rows").Items().size())));
        footer.Set(L"complete", collection.Get(L"coverage").Get(L"complete"));
        if (!written || !writer.WriteText(footer.Write() + L"\n") || !writer.Commit())
        {
            report.Error.Message = L"Snapshot collection write/commit failed";
            return report;
        }
        staging.Files.push_back(leaf);
        total += writer.Written();
        const auto hash = Sha256File((temporary / leaf).wstring(),
                                     [&]()
                                     {
                                         return stop() ? ERROR_CANCELLED : ERROR_SUCCESS;
                                     });
        if (hash.State != kncore::Status::Success || total > 64 * 1024 * 1024)
        {
            report.Error.Message = L"Snapshot hashing failed or total size budget exceeded";
            return report;
        }
        auto entry = knjson::Value::MakeObject();
        entry.Set(L"collector", knjson::Value(name));
        entry.Set(L"file", knjson::Value(leaf));
        entry.Set(L"bytes", knjson::Value(std::to_wstring(writer.Written())));
        files.Push(entry);
        digests.Set(leaf, knjson::Value(hash.Digest));
    }
    manifest.Set(L"files", files);
    std::wstring manifestText;
    if (!EncodeSnapshotJson(manifest, 1024 * 1024, 1024 * 1024, manifestText))
    {
        report.State = kncore::Status::InvalidInput;
        report.Error.Message = L"Snapshot manifest exceeds import limits";
        return report;
    }
    ArtifactWriter manifestWriter(nullptr, stop);
    if (!manifestWriter.Open((temporary / L"manifest.json").wstring()) || !manifestWriter.WriteText(manifestText) ||
        !manifestWriter.Commit())
    {
        return report;
    }
    staging.Files.push_back(L"manifest.json");
    const auto manifestHash = Sha256File((temporary / L"manifest.json").wstring(),
                                         [&]()
                                         {
                                             return stop() ? ERROR_CANCELLED : ERROR_SUCCESS;
                                         });
    if (manifestHash.State != kncore::Status::Success)
    {
        return report;
    }
    digests.Set(L"manifest.json", knjson::Value(manifestHash.Digest));
    checksums.Set(L"sha256", digests);
    ArtifactWriter checksumWriter(nullptr, stop);
    if (!checksumWriter.Open((temporary / L"checksums.json").wstring()) || !checksumWriter.WriteText(checksums.Write()) ||
        !checksumWriter.Commit())
    {
        return report;
    }
    staging.Files.push_back(L"checksums.json");
    if (stop())
    {
        return report;
    }
    if (!MoveFileExW(temporary.c_str(), finalPath.c_str(), MOVEFILE_WRITE_THROUGH))
    {
        report.Error = {L"Win32", GetLastError(), L"MoveFileExW", L"Snapshot directory commit failed"};
        return report;
    }
    staging.Committed = true;
    report.State = kncore::Status::Success;
    report.Analysis = knjson::Value::MakeObject();
    report.Analysis.Set(L"artifactCommitted", knjson::Value(true));
    report.Analysis.Set(L"artifactPath", knjson::Value(finalPath.wstring()));
    report.Collected.Complete = true;
    report.Rows.Push(manifest);
    return report;
}

inline bool ParseSnapshotCollection(const std::wstring &text, const std::wstring &name, knjson::Value &collection,
                                    size_t maximumRows = 100000)
{
    size_t cursor = 0;
    bool metadata = false;
    bool footer = false;
    auto rows = knjson::Value::MakeArray();
    while (cursor < text.size())
    {
        auto end = text.find(L'\n', cursor);
        if (end == std::wstring::npos)
        {
            end = text.size();
        }
        const auto line = text.substr(cursor, end - cursor);
        cursor = end + 1;
        knjson::Value record;
        if (footer || line.empty() || line.size() > 512 * 1024 || !knjson::Parse(line, &record))
        {
            return false;
        }
        const auto type = record.Get(L"type").AsString(L"");
        if (!metadata)
        {
            if (type != L"metadata" || record.Get(L"schema").AsString(L"") != L"kndbgx.snapshot-collection.v2" ||
                record.Get(L"collector").AsString(L"") != name || !kncore::ValidCollection(record.Get(L"result")) ||
                !record.Get(L"result").Get(L"rows").Items().empty())
            {
                return false;
            }
            collection = record.Get(L"result");
            metadata = true;
        }
        else if (type == L"record" && record.Get(L"data").IsObject() && rows.Items().size() < maximumRows)
        {
            rows.Push(record.Get(L"data"));
        }
        else if (type == L"completion")
        {
            if (record.Get(L"records").AsString(L"") != std::to_wstring(rows.Items().size()) || !record.Get(L"complete").IsBool() ||
                record.Get(L"complete").AsBool(false) != collection.Get(L"coverage").Get(L"complete").AsBool(false))
            {
                return false;
            }
            footer = true;
        }
        else
        {
            return false;
        }
    }
    if (!metadata)
    {
        return false;
    }
    collection.Set(L"rows", rows);
    if (!footer)
    {
        collection.Set(L"status", knjson::Value(L"Partial"));
        auto coverage = collection.Get(L"coverage");
        coverage.Set(L"complete", knjson::Value(false));
        coverage.Set(L"stopReason", knjson::Value(L"MissingCompletionFooter"));
        collection.Set(L"coverage", coverage);
    }
    return true;
}

inline kncore::Result LoadSnapshot(const std::wstring &path, kncore::Snapshot &snapshot)
{
    snapshot = {};
    kncore::Result report;
    report.State = kncore::Status::InvalidInput;
    report.Error.Message = L"Snapshot manifest, checksum, path, size, or collection schema invalid";
    if (path.empty() || path.find(L'\0') != std::wstring::npos)
    {
        return report;
    }
    const auto close = [](void *handle)
    {
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
    };
    std::unique_ptr<void, decltype(close)> directory(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                                 nullptr, OPEN_EXISTING,
                                                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr),
                                                     close);
    FILE_ATTRIBUTE_TAG_INFO attributes = {};
    if (directory.get() == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return report;
    }
    const std::filesystem::path root(path);
    knjson::Value checksums;
    std::vector<unsigned char> bytes;
    std::wstring text;
    if (!ReadArtifactJson((root / L"checksums.json").wstring(), checksums) ||
        checksums.Get(L"schema").AsString(L"") != L"kndbgx.checksums.v1" ||
        !ReadArtifact((root / L"manifest.json").wstring(), bytes, 1024 * 1024) ||
        !MatchesSnapshotHash(bytes, checksums.Get(L"sha256").Get(L"manifest.json").AsString(L"")) || !StrictUtf8(bytes, text) ||
        !knjson::Parse(text, &snapshot.Metadata))
    {
        return report;
    }
    const auto &files = snapshot.Metadata.Get(L"files");
    if (!files.IsArray() || files.Items().empty() || files.Items().size() > 32 ||
        checksums.Get(L"sha256").Fields().size() != files.Items().size() + 1)
    {
        return report;
    }
    std::set<std::wstring> seen;
    uint64_t total = 0;
    size_t totalRows = 0;
    for (const auto &entry : files.Items())
    {
        const auto name = entry.Get(L"collector").AsString(L"");
        const auto leaf = entry.Get(L"file").AsString(L"");
        uint64_t size = 0;
        if (!kncore::SnapshotLeaf(name) || !kncore::SnapshotLeaf(leaf) || leaf != name + L".jsonl" || !seen.insert(name).second ||
            !kncore::ParseUnsigned(entry.Get(L"bytes").AsString(L""), 10, &size) || size == 0 || size > 64 * 1024 * 1024 - total)
        {
            return report;
        }
        total += size;
        if (!ReadArtifact((root / leaf).wstring(), bytes, size) || bytes.size() != size ||
            !MatchesSnapshotHash(bytes, checksums.Get(L"sha256").Get(leaf).AsString(L"")) || !StrictUtf8(bytes, text))
        {
            return report;
        }
        knjson::Value collection;
        if (!ParseSnapshotCollection(text, name, collection, 100000 - totalRows))
        {
            return report;
        }
        totalRows += collection.Get(L"rows").Items().size();
        snapshot.Collections.emplace(name, collection);
    }
    if (kncore::ValidSnapshot(snapshot))
    {
        report.State = kncore::Status::Success;
        report.Error = {};
        report.Collected.Complete = true;
    }
    return report;
}
} // namespace knutil
