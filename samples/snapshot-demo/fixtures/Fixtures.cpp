#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>
#include "../../../src/util/SnapshotStore.h"

namespace
{
unsigned g_Failed = 0;
unsigned g_Passed = 0;

void Check(bool condition, const wchar_t *name)
{
    std::wprintf(L"[%ls] %ls\n", condition ? L"PASS" : L"FAIL", name);
    if (condition)
    {
        ++g_Passed;
    }
    else
    {
        ++g_Failed;
    }
}

knjson::Value Routine(const wchar_t *family, const wchar_t *address)
{
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"RoutineObservation"));
    row.Set(L"family", knjson::Value(family));
    row.Set(L"index", knjson::Value(L"0"));
    row.Set(L"routine", knjson::Value(address));
    row.Set(L"synthetic", knjson::Value(true));
    return row;
}

knjson::Value Collection(const std::vector<knjson::Value> &rows, bool complete = true)
{
    kncore::Result result;
    result.Source = L"Synthetic:SnapshotDemo";
    result.State = complete ? kncore::Status::Success : kncore::Status::Partial;
    result.Collected.Complete = complete;
    result.Collected.StopReason = complete ? L"SyntheticEnd" : L"SyntheticMissingObservation";
    result.Collected.Expected = rows.size() + (complete ? 0 : 1);
    result.Collected.Visited = rows.size();
    result.Collected.Read = rows.size();
    result.Collected.Unknown = complete ? 0 : 1;
    result.Limitations.Push(knjson::Value(L"Synthetic demonstration data; not captured from a kernel."));
    for (const auto &row : rows)
    {
        result.Rows.Push(row);
    }
    return result.ToJson();
}

kncore::Snapshot MakeSnapshot(bool changed, bool incomplete = false)
{
    kncore::Snapshot snapshot;
    snapshot.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
    snapshot.Metadata.Set(L"target", kncore::SessionStamp{L"SYNTHETIC-SNAPSHOT-DEMO-ONLY", 1, changed ? 2u : 1u, 1, 1}.ToJson());
    snapshot.Metadata.Set(L"targetStable", knjson::Value(true));
    snapshot.Metadata.Set(L"synthetic", knjson::Value(true));
    snapshot.Metadata.Set(L"scenario", knjson::Value(changed ? L"Synthetic changed pointers and omitted module" : L"Synthetic baseline"));
    snapshot.Metadata.Set(L"rawMemoryIncluded", knjson::Value(false));

    auto module = knjson::Value::MakeObject();
    module.Set(L"kind", knjson::Value(L"Module"));
    module.Set(L"moduleIdentity", knjson::Value(L"SYNTHETIC-DEMO-MODULE"));
    module.Set(L"moduleIdentityKind", knjson::Value(L"Synthetic"));
    module.Set(L"name", knjson::Value(L"SyntheticDemo.sys"));
    module.Set(L"base", knjson::Value(L"0xfffff80010000000"));
    module.Set(L"size", knjson::Value(L"65536"));
    module.Set(L"synthetic", knjson::Value(true));
    snapshot.Collections[L"modules"] = Collection(changed ? std::vector<knjson::Value>{} : std::vector<knjson::Value>{module}, !incomplete);
    snapshot.Collections[L"callbacks"] = Collection({Routine(L"SyntheticProcessNotify", changed ? L"0xfffff80010002000" : L"0xfffff80010001000")});
    snapshot.Collections[L"ssdt"] = Collection({Routine(L"SyntheticServiceTable", changed ? L"0xfffff80020002000" : L"0xfffff80020001000")});
    auto gate = knjson::Value::MakeObject();
    gate.Set(L"kind", knjson::Value(L"IdtGate"));
    gate.Set(L"cpu", knjson::Value(L"0"));
    gate.Set(L"vector", knjson::Value(L"128"));
    gate.Set(L"handler", knjson::Value(changed ? L"0xfffff80030002000" : L"0xfffff80030001000"));
    gate.Set(L"synthetic", knjson::Value(true));
    snapshot.Collections[L"idt"] = Collection({gate});
    auto control = knjson::Value::MakeObject();
    control.Set(L"kind", knjson::Value(L"ControlRegister"));
    control.Set(L"cpu", knjson::Value(L"0"));
    control.Set(L"register", knjson::Value(L"cr4"));
    control.Set(L"value", knjson::Value(changed ? L"0x0000000000005678" : L"0x0000000000001234"));
    control.Set(L"synthetic", knjson::Value(true));
    snapshot.Collections[L"control-registers"] = Collection({control});
    return snapshot;
}

const knjson::Value &Find(const kncore::Result &result, const wchar_t *collector)
{
    static const knjson::Value empty;
    for (const auto &row : result.Rows.Items())
    {
        if (row.Get(L"collector").AsString(L"") == collector)
        {
            return row;
        }
    }
    return empty;
}

bool WriteJson(const std::filesystem::path &path, const knjson::Value &data)
{
    knutil::ArtifactWriter writer;
    return writer.Open(path.wstring()) && writer.WriteText(data.Write()) && writer.Commit();
}
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 2)
    {
        std::fwprintf(stderr, L"Usage: KnSnapshotDemoFixtures.exe <new-output-directory>\n");
        return 2;
    }
    const std::filesystem::path root(argv[1]);
    std::error_code error;
    if (!std::filesystem::create_directory(root, error))
    {
        std::fwprintf(stderr, L"A new output directory is required; existing paths are preserved. Error=%d\n", error.value());
        return 1;
    }
    const auto before = MakeSnapshot(false);
    const auto after = MakeSnapshot(true);
    const auto incomplete = MakeSnapshot(true, true);
    const std::pair<const wchar_t *, kncore::Snapshot> snapshots[] = {
        {L"synthetic-before", before}, {L"synthetic-after", after}, {L"synthetic-incomplete", incomplete}, {L"checksum-negative-control", before}};
    for (const auto &[name, snapshot] : snapshots)
    {
        const auto path = (root / name).wstring();
        const auto saved = knutil::SaveSnapshot(path, snapshot);
        Check(saved.State == kncore::Status::Success, name);
        kncore::Snapshot loaded;
        const auto read = knutil::LoadSnapshot(path, loaded);
        Check(read.State == kncore::Status::Success && loaded.Metadata.Get(L"synthetic").AsBool(false), L"production reader roundtrip");
    }
    const auto comparison = kncore::DiffSnapshots(before, after);
    for (const auto *name : {L"callbacks", L"ssdt", L"idt", L"control-registers"})
    {
        Check(Find(comparison, name).Get(L"state").AsString(L"") == L"Changed", name);
    }
    Check(Find(comparison, L"modules").Get(L"state").AsString(L"") == L"Removed", L"complete omitted module is Removed, not a hiding verdict");
    Check(Find(kncore::DiffSnapshots(after, before), L"modules").Get(L"state").AsString(L"") == L"Added", L"reverse comparison reports Added");
    const auto unchanged = kncore::DiffSnapshots(before, before);
    Check(unchanged.State == kncore::Status::Success &&
              std::all_of(unchanged.Rows.Items().begin(), unchanged.Rows.Items().end(),
                          [](const auto &row)
                          {
                              return row.Get(L"state").AsString(L"") == L"Unchanged";
                          }),
          L"identical complete synthetic snapshots remain Unchanged");
    const auto unknown = kncore::DiffSnapshots(before, incomplete);
    Check(unknown.State == kncore::Status::Partial && Find(unknown, L"modules").Get(L"state").AsString(L"") == L"Unknown",
          L"incomplete omitted module remains Unknown");
    Check(Find(unknown, L"callbacks").Get(L"state").AsString(L"") == L"Changed", L"known changes survive another collector's missing data");
    Check(WriteJson(root / L"synthetic-diff.json", comparison.ToJson()) && WriteJson(root / L"synthetic-incomplete-diff.json", unknown.ToJson()),
          L"write synthetic comparison artifacts");

    const auto altered = root / L"checksum-negative-control" / L"callbacks.jsonl";
    HANDLE file = CreateFileW(altered.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD written = 0;
    const bool appended = file != INVALID_HANDLE_VALUE && WriteFile(file, "\n", 1, &written, nullptr) && written == 1;
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    kncore::Snapshot rejected;
    Check(appended && knutil::LoadSnapshot((root / L"checksum-negative-control").wstring(), rejected).State != kncore::Status::Success,
          L"production reader rejects modified artifact bytes");
    Check(knutil::SaveSnapshot((root / L"synthetic-before").wstring(), before).State != kncore::Status::Success,
          L"existing snapshot directory is preserved");
    std::wprintf(L"Synthetic checks passed=%u failed=%u. No driver, SCM or kernel memory access performed.\n", g_Passed, g_Failed);
    return g_Failed == 0 ? 0 : 1;
}
