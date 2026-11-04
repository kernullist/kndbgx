#pragma once

#include "CollectorRead.h"
#include <cwctype>

namespace kncore
{
struct ProcessRow
{
    uint64_t Eprocess = 0;
    uint64_t Pid = 0;
    std::wstring Image;
    uint64_t DirectoryTableBase = 0;
    uint64_t CreateTime = 0;
    bool PidKnown = false;
    bool ImageKnown = false;
    bool DtbKnown = false;
    bool CreateTimeKnown = false;

    knjson::Value ToJson() const
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"Process"));
        row.Set(L"eprocess", knjson::Value(Hex(Eprocess)));
        row.Set(L"pid", PidKnown ? knjson::Value(std::to_wstring(Pid)) : knjson::Value());
        row.Set(L"image", ImageKnown ? knjson::Value(Image) : knjson::Value());
        row.Set(L"dtb", DtbKnown ? knjson::Value(Hex(DirectoryTableBase)) : knjson::Value());
        row.Set(L"createTime", CreateTimeKnown ? knjson::Value(std::to_wstring(CreateTime)) : knjson::Value());
        return row;
    }
};

struct ProcessLayout
{
    std::optional<FieldInfo> Links;
    std::optional<FieldInfo> Pid;
    std::optional<FieldInfo> Image;
    std::optional<FieldInfo> Dtb;
    std::optional<FieldInfo> CreateTime;
    std::wstring Profile;
    std::wstring LinksDiagnostic;
};

class ProcessRecordReader final : public TargetReader
{
  public:
    ProcessRecordReader(TargetReader &reader, const ProcessLayout &layout, WalkBudget &budget)
        : reader_(reader), budget_(budget)
    {
        uint64_t first = UINT32_MAX;
        uint64_t last = 0;
        for (const auto &field : {layout.Links, layout.Pid, layout.Image, layout.Dtb, layout.CreateTime})
        {
            if (field && field->Size != 0)
            {
                first = (std::min)(first, static_cast<uint64_t>(field->Offset));
                last = (std::max)(last, static_cast<uint64_t>(field->Offset) + field->Size);
            }
        }
        // Bound speculative reads; unusual layouts retain individual field reads.
        if (last > first && last - first <= 4096)
        {
            offset_ = first;
            length_ = static_cast<size_t>(last - first);
        }
    }

    void Prepare(uint64_t object)
    {
        cached_ = {};
        if (length_ != 0 && ValidRange(object, offset_ + length_) && CheckBudget())
        {
            cached_ = reader_.Read(AddressSpace::Virtual, object + offset_, length_);
            if (cached_.State == Status::Cancelled)
            {
                budget_.Stop(Status::Cancelled, L"Cancelled");
            }
            CheckBudget();
        }
    }

    ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
    {
        ReadResult read;
        read.Space = space;
        read.Address = address;
        read.Requested = length;
        if (!CheckBudget())
        {
            read.State = budget_.Report.State;
        }
        else if (space == AddressSpace::Virtual && ExactBytes(cached_, length_) && address >= cached_.Address &&
                 address - cached_.Address <= length_ && length <= length_ - (address - cached_.Address))
        {
            const auto begin = cached_.Bytes.begin() + static_cast<size_t>(address - cached_.Address);
            read.Bytes.assign(begin, begin + length);
            read.Valid.assign(length, 1);
            read.Transferred = length;
            read.State = Status::Success;
        }
        else
        {
            // A short read may only reflect unreadable padding between valid fields.
            read = reader_.Read(space, address, length);
            if (read.State == Status::Cancelled)
            {
                budget_.Stop(Status::Cancelled, L"Cancelled");
            }
            CheckBudget();
        }
        return read;
    }

  private:
    bool CheckBudget()
    {
        if (!budget_.Stopped && budget_.Cancelled && budget_.Cancelled())
        {
            budget_.Stop(Status::Cancelled, L"Cancelled");
        }
        if (!budget_.Stopped && std::chrono::steady_clock::now() >= budget_.Deadline)
        {
            budget_.Stop(Status::Partial, L"GlobalWalkBudget");
        }
        return !budget_.Stopped;
    }

    TargetReader &reader_;
    WalkBudget &budget_;
    uint64_t offset_ = 0;
    size_t length_ = 0;
    ReadResult cached_;
};

inline bool ReadProcess(TargetReader &reader, uint64_t object, const ProcessLayout &layout, ProcessRow &row)
{
    row = {};
    row.Eprocess = object;
    const auto pid = ReadField(reader, object, layout.Pid);
    const auto dtb = ReadField(reader, object, layout.Dtb);
    const auto time = ReadField(reader, object, layout.CreateTime);
    row.PidKnown = pid.has_value();
    row.DtbKnown = dtb.has_value();
    row.CreateTimeKnown = time.has_value();
    row.Pid = pid.value_or(0);
    row.DirectoryTableBase = dtb.value_or(0);
    row.CreateTime = time.value_or(0);
    if (layout.Image && layout.Image->Size <= 256 && layout.Image->Size != 0 &&
        ValidRange(object, static_cast<uint64_t>(layout.Image->Offset) + layout.Image->Size))
    {
        const auto read = reader.Read(AddressSpace::Virtual, object + layout.Image->Offset, layout.Image->Size);
        if (ExactBytes(read, layout.Image->Size))
        {
            row.ImageKnown = true;
            for (const unsigned char byte : read.Bytes)
            {
                if (byte == 0)
                {
                    break;
                }
                row.Image.push_back(byte >= 32 && byte < 127 ? byte : L'?');
            }
        }
    }
    return row.PidKnown && row.ImageKnown && row.DtbKnown && row.CreateTimeKnown;
}

inline void SetSelectedProcessCoverage(const ProcessRow &row, Result &report)
{
    const bool complete = row.PidKnown && row.ImageKnown && row.DtbKnown && row.CreateTimeKnown;
    report.State = complete ? Status::Success : Status::Partial;
    report.Source = L"TargetMemory:SelectedProcess";
    report.Collected = {};
    report.Collected.Expected = 1;
    report.Collected.Visited = 1;
    report.Collected.Read = 1;
    report.Collected.Decoded = 1;
    report.Collected.Unknown = complete ? 0 : 1;
    report.Collected.Complete = complete;
    report.Collected.StopReason = complete ? L"SelectedProcessRead" : L"ProcessFieldsUnavailable";
}

inline bool CollectProcessList(TargetReader &reader, uint64_t head, const ProcessLayout &layout, const TargetArchitecture &architecture,
                               WalkBudget &budget, std::vector<ProcessRow> &rows)
{
    rows.clear();
    budget.Report.LayoutProfile = layout.Profile;
    if (!layout.Links || layout.Links->Size != 2 * architecture.PointerBytes)
    {
        budget.Report.Error.Domain = L"Symbols";
        budget.Report.Error.Operation = L"ResolveProcessLayout";
        budget.Report.Error.Message = L"nt!_EPROCESS.ActiveProcessLinks: " +
                                      (layout.Links ? L"LIST_ENTRY storage size does not match the target pointer width"
                                       : !layout.LinksDiagnostic.empty() ? layout.LinksDiagnostic
                                                                        : L"matching PDB field metadata unavailable");
        return budget.Stop(Status::Unavailable, L"ProcessListLayoutUnavailable");
    }
    // Remote KD round trips can outlast the general scanner's five-second budget.
    // Keep inventory bounded and cancellable without renewing it for each record.
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    ProcessRecordReader records(reader, layout, budget);
    const bool walked = WalkList(records, head, architecture, budget,
                                 [&](uint64_t node)
                                 {
                                     if (node < layout.Links->Offset || !architecture.KernelPointer(node - layout.Links->Offset))
                                     {
                                         return VisitDecision::Failed;
                                     }
                                     ProcessRow row;
                                     const bool known = ReadProcess(records, node - layout.Links->Offset, layout, row);
                                     if (budget.Stopped)
                                     {
                                         return VisitDecision::Failed;
                                     }
                                     if (!known)
                                     {
                                         ++budget.Report.Collected.Unknown;
                                     }
                                     rows.push_back(row);
                                     budget.Report.Rows.Push(row.ToJson());
                                     return VisitDecision::Continue;
                                 },
                                 [&](uint64_t node)
                                 {
                                     if (node >= layout.Links->Offset && architecture.KernelPointer(node - layout.Links->Offset))
                                     {
                                         records.Prepare(node - layout.Links->Offset);
                                     }
                                 });
    if (!budget.Stopped && budget.Report.Collected.Unknown != 0)
    {
        budget.Stop(Status::Partial, L"ProcessFieldsUnavailable");
    }
    budget.Complete();
    return walked && budget.Report.State == Status::Success;
}

inline std::wstring FoldName(std::wstring name)
{
    for (auto &character : name)
    {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return name;
}

inline bool SelectProcess(const std::vector<ProcessRow> &rows, const std::wstring &token, ProcessRow *match, bool inventoryComplete)
{
    enum class Selection
    {
        Pid,
        Image,
        Address
    };
    Selection selection = Selection::Image;
    std::wstring value = token;
    const auto colon = value.find(L':');
    bool explicitKind = false;
    if (colon != std::wstring::npos)
    {
        const auto prefix = FoldName(value.substr(0, colon));
        value.erase(0, colon + 1);
        explicitKind = true;
        if (prefix == L"pid")
        {
            selection = Selection::Pid;
        }
        else if (prefix == L"eprocess")
        {
            selection = Selection::Address;
        }
        else if (prefix != L"image")
        {
            return false;
        }
    }
    if (value.empty() || match == nullptr)
    {
        return false;
    }
    uint64_t number = 0;
    if (!explicitKind)
    {
        if (ParseUnsigned(value, 16, &number) && (number >> 63) != 0)
        {
            selection = Selection::Address;
        }
        else if (ParseUnsigned(value, 10, &number))
        {
            selection = Selection::Pid;
        }
    }
    if (selection != Selection::Image && !ParseUnsigned(value, selection == Selection::Pid ? 10 : 16, &number))
    {
        return false;
    }
    if (selection == Selection::Image && !inventoryComplete)
    {
        // An unobserved process may have the same name. Numeric identities
        // can still select a record observed in a partial inventory.
        return false;
    }
    const auto wanted = FoldName(value);
    const ProcessRow *found = nullptr;
    for (const auto &row : rows)
    {
        const bool matches = selection == Selection::Pid       ? row.PidKnown && row.Pid == number
                             : selection == Selection::Address ? row.Eprocess == number
                                                               : row.ImageKnown && FoldName(row.Image).find(wanted) != std::wstring::npos;
        if (matches)
        {
            if (found != nullptr)
            {
                return false;
            }
            found = &row;
        }
    }
    if (found != nullptr)
    {
        *match = *found;
    }
    return found != nullptr;
}
} // namespace kncore
