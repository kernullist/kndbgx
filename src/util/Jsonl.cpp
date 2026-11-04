#include "Jsonl.h"
#include "Json.h"

namespace knutil
{
bool JsonlWriter::Open(const std::wstring &path)
{
    written_ = 0;
    failed_ = !writer_.Open(path);
    if (!failed_)
    {
        failed_ = !writer_.WriteText(L"{\"schema\":\"kndbgx.jsonl.v2\",\"type\":\"metadata\"}\n");
    }
    return !failed_;
}

bool JsonlWriter::WriteLine(const std::wstring &jsonText)
{
    knjson::Value record;
    if (failed_ || !knjson::Parse(jsonText, &record) || !record.IsObject())
    {
        failed_ = true;
        return false;
    }
    auto envelope = knjson::Value::MakeObject();
    envelope.Set(L"type", knjson::Value(L"record"));
    envelope.Set(L"data", record);
    failed_ = !writer_.WriteText(envelope.Write() + L"\n");
    if (!failed_)
    {
        ++written_;
    }
    return !failed_;
}

bool JsonlWriter::Commit(bool collectionComplete)
{
    auto footer = knjson::Value::MakeObject();
    footer.Set(L"type", knjson::Value(L"completion"));
    footer.Set(L"complete", knjson::Value(collectionComplete));
    footer.Set(L"records", knjson::Value(std::to_wstring(written_)));
    failed_ = failed_ || !writer_.WriteText(footer.Write() + L"\n") || !writer_.Commit();
    return !failed_;
}

bool JsonlWriter::IsOpen() const
{
    return writer_.IsOpen() && !failed_;
}

unsigned long JsonlWriter::Written() const
{
    return written_;
}
} // namespace knutil
