#pragma once

#include "CollectorRegression.h"
#include "WfpRegression.h"
#include "../core/BfeRead.h"

namespace knself
{
template <typename Check> void RunBfeRegression(Check check)
{
    using namespace kncore;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    for (const auto status : {Status::Cancelled, Status::StaleContext, Status::InternalFault})
    {
        WfpTerminalReader physical;
        physical.State = status;
        BfeProcessReader memory(physical, [](uint64_t) -> std::optional<uint64_t>
        {
            return 0x8000;
        });
        WalkBudget bytesBudget;
        BfeReader bytesRead(memory, bytesBudget);
        check(!bytesRead.Bytes(0x10000, 8) && bytesBudget.Stopped && bytesBudget.Report.State == status &&
              !bytesRead.Bytes(0x10008, 8) && physical.Reads == 1,
              "bfe.physical-terminal-read-preserves-status-and-stops");
        WalkBudget textBudget;
        BfeReader textRead(memory, textBudget);
        check(textRead.Text(0x10000).Get(L"value").IsNull() && textBudget.Stopped && textBudget.Report.State == status,
              "bfe.terminal-read-cannot-publish-a-string");
    }
    {
        ByteFixture physical;
        physical.Put(0x8ffe, 0x2211, 2);
        physical.Put(0xc000, 0x4433, 2);
        physical.Put(0x9ffe, 0x6655, 2);
        const auto translate = [](uint64_t address) -> std::optional<uint64_t>
        {
            return address == 0x10000 ? 0x8000 : address == 0x11000 ? 0xc000 : std::optional<uint64_t>{};
        };
        BfeProcessReader first(physical, translate);
        const auto bytes = first.Read(AddressSpace::Virtual, 0x10ffe, 4);
        check(ExactBytes(bytes, 4) && WfpInteger(bytes.Bytes, 0, 4) == 0x44332211, "bfe.user-read-crosses-noncontiguous-physical-pages");
        BfeProcessReader second(physical, [](uint64_t) -> std::optional<uint64_t>
        {
            return 0x9000;
        });
        check(WfpInteger(second.Read(AddressSpace::Virtual, 0x10ffe, 2).Bytes, 0, 2) == 0x6655,
              "bfe.user-translations-are-process-scoped");
        check(!ExactBytes(first.Read(AddressSpace::Virtual, 0x12000, 2), 2), "bfe.unmapped-user-page-not-fabricated");
    }
    constexpr uint64_t module = 0x1000000, manager = 0x100000, directory = 0x200000, object = 0x300000;
    constexpr uint64_t value = 0x400000, text = 0x500000;
    const auto wide = [](ByteFixture &memory, uint64_t address, const std::wstring &s)
    {
        for (size_t i = 0; i <= s.size(); ++i)
        {
            memory.Put(address + i * 2, i < s.size() ? s[i] : 0, 2);
        }
    };
    const auto fixture = [&](unsigned type)
    {
        ByteFixture memory;
        const auto descriptor = manager + type * 0x198;
        memory.Text(descriptor, {}, 0x118);
        memory.Put(descriptor, 1, 4);
        memory.Put(descriptor + 8, type, 4);
        memory.Put(descriptor + 0x70, module + 0x3c1c0);
        memory.Put(descriptor + 0x78, module + 0x3b5e0);
        memory.Put(descriptor + 0xf8, 128, 4);
        memory.Put(descriptor + 0x100, 127, 4);
        memory.Put(descriptor + 0x104, 1, 4);
        memory.Put(descriptor + 0x108, 1, 4);
        memory.Put(descriptor + 0x110, directory);
        for (unsigned i = 0; i < 128; ++i)
        {
            memory.Put(directory + i * 16, directory + i * 16);
            memory.Put(directory + i * 16 + 8, directory + i * 16);
        }
        memory.Put(directory, object + 0x10);
        memory.Put(directory + 8, object + 0x10);
        memory.Text(object, {}, 0x98);
        memory.Put(object, descriptor);
        memory.Put(object + 8, 0x71, 4);
        memory.Put(object + 0x10, directory);
        memory.Put(object + 0x18, directory);
        memory.Put(object + 0x20, type + 1);
        memory.Put(object + 0x90, value);
        memory.Text(value, {}, 0xc8);
        memory.Put(value, type + 1, 4);
        memory.Put(value + 0x10, text);
        wide(memory, text, L"Target name");
        if (type == 2)
        {
            memory.Put(value + 0x40, 80, 2);
        }
        if (type == 3)
        {
            memory.Put(value + 0x40, 12, 2);
        }
        if (type == 4)
        {
            memory.Put(value + 0x50, 7, 4);
        }
        if (type == 5)
        {
            memory.Put(value + 0xb0, 0x20000000000001ULL);
            memory.Put(value + 0x40, 4, 4);
            memory.Put(value + 0x50, 3, 4);
            memory.Put(value + 0x80, 0x1002, 4);
        }
        return memory;
    };
    std::vector<BfeRecord> records;
    for (const auto status : {Status::Cancelled, Status::StaleContext, Status::InternalFault})
    {
        auto memory = fixture(0);
        WfpTerminalReader fault;
        fault.State = status;
        fault.Fallback = &memory;
        fault.FailAt = text;
        WalkBudget budget;
        BfeReader read(fault, budget);
        read.RecordUnits = 2 * 1024 * 1024;
        std::vector<BfeRecord> rows;
        check(!ReadBfeTable(read, architecture, module, manager, 0, rows) && rows.empty() && budget.Report.State == status,
              "bfe.text-read-terminal-status-survives-record-budget");
    }
    for (const auto type : {0u, 2u, 3u, 4u, 5u})
    {
        auto memory = fixture(type);
        WalkBudget budget;
        BfeReader read(memory, budget);
        check(ReadBfeTable(read, architecture, module, manager, type, records), "bfe.table-public-schema-decoded");
        check(records.back().Row.Get(L"name").AsString(L"") == L"Target name" &&
              records.back().Row.Get(L"description").IsNull() &&
              records.back().Row.Get(L"descriptionState").AsString(L"") == L"Absent", "bfe.target-text-and-null-description");
    }
    for (const auto mode : {0, 1, 2, 3, 4, 5, 6})
    {
        auto memory = fixture(0);
        if (mode == 0)
        {
            memory.Put(object + 0x18, 0);
        }
        else if (mode == 1)
        {
            memory.Put(object, manager + 0x198);
        }
        else if (mode == 2)
        {
            memory.Put(manager + 0x104, 2, 4);
        }
        else if (mode == 3)
        {
            memory.Put(manager + 0x10c, 1, 4);
        }
        else if (mode == 4)
        {
            memory.Put(object + 0x90, 0xffff800000000000ULL);
        }
        else if (mode == 5)
        {
            memory.Put(object + 0x10, object + 0x10);
        }
        else
        {
            memory.Put(manager + 0x78, module + 0x3b5e1);
        }
        WalkBudget budget;
        BfeReader read(memory, budget);
        std::vector<BfeRecord> rows;
        check(!ReadBfeTable(read, architecture, module, manager, 0, rows) && budget.Report.State == Status::Partial,
              "bfe.corrupt-table-is-not-complete");
    }
    {
        auto memory = fixture(0);
        memory.Put(object + 8, 8, 4);
        memory.Bytes.erase(object + 0x90);
        WalkBudget budget;
        BfeReader read(memory, budget);
        std::vector<BfeRecord> rows;
        check(!ReadBfeTable(read, architecture, module, manager, 0, rows), "bfe.short-object-header-rejected");
        memory.Put(object + 0x90, 0);
        WalkBudget retry;
        BfeReader again(memory, retry);
        check(ReadBfeTable(again, architecture, module, manager, 0, rows) && rows.empty(), "bfe.deleted-object-not-dereferenced");
    }
    {
        ByteFixture memory;
        wide(memory, text, L"");
        wide(memory, text + 0x100, L"@bfe.dll,-522");
        wide(memory, text + 0x200, std::wstring(1, wchar_t(0xd800)));
        wide(memory, text + 0x300, std::wstring(1, wchar_t(0xdc00)));
        wide(memory, text + 0x400, std::wstring(1, wchar_t(0xd83d)) + wchar_t(0xde00));
        WalkBudget budget;
        BfeReader read(memory, budget);
        check(read.Text(text).Get(L"state").AsString(L"") == L"Empty", "bfe.empty-text-differs-from-absent");
        check(read.Text(text + 0x100).Get(L"state").AsString(L"") == L"IndirectResource", "bfe-resource-reference-not-host-localized");
        check(read.Text(text + 0x200).Get(L"state").AsString(L"") == L"InvalidUtf16" &&
              read.Text(text + 0x300).Get(L"state").AsString(L"") == L"InvalidUtf16", "bfe.invalid-surrogates-rejected");
        check(read.Text(text + 0x400).Get(L"value").AsString(L"").size() == 2, "bfe.surrogate-pair-preserved");
        check(read.Text(text + 0x500).Get(L"value").IsNull(), "bfe.unreadable-is-not-empty");
        const auto reads = memory.Reads;
        check(!read.Bytes(0xffff800000000000ULL, 8) && memory.Reads == reads, "bfe.user-reader-rejects-kernel-address");
    }
    {
        auto memory = fixture(0);
        WalkBudget budget;
        BfeReader read(memory, budget);
        read.RecordUnits = 2 * 1024 * 1024;
        std::vector<BfeRecord> rows;
        check(!ReadBfeTable(read, architecture, module, manager, 0, rows) && rows.empty() &&
              budget.Report.Collected.StopReason == L"BfeRecordBudget", "bfe.aggregate-output-budget-before-retention");
    }
    {
        auto memory = fixture(0);
        WalkBudget budget;
        BfeReader read(memory, budget);
        std::vector<BfeRecord> rows;
        memory.BeforeRead = [&]()
        {
            if (memory.Reads > 10)
            {
                memory.Put(manager + 0x104, 2, 4);
            }
        };
        check(!ReadBfeTable(read, architecture, module, manager, 0, rows) &&
              budget.Report.Collected.StopReason == L"BfeTableChangedOrCountMismatch", "bfe.detects-root-change-after-enumeration");
    }
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"filters"));
        row.Set(L"filterId", knjson::Value(L"9007199254740993"));
        row.Set(L"action", knjson::Value(Hex(0x1002)));
        row.Set(L"conditionCount", knjson::Value(L"0"));
        row.Set(L"layerId", knjson::Value(L"12"));
        row.Set(L"subLayerWeight", knjson::Value(L"80"));
        check(EnrichBfeRow(row, records, true) && row.Get(L"managementState").AsString(L"") == L"Matched" &&
              row.Get(L"subLayerName").AsString(L"") == L"Target name" && row.Get(L"subLayerWeight").AsString(L"") == L"80",
              "bfe.join-exact-64bit-id-layer-action-sublayer");
        row.Set(L"action", knjson::Value(Hex(0x1001)));
        check(!EnrichBfeRow(row, records, true) && row.Get(L"managementState").AsString(L"") == L"RuntimeIdentityMismatch",
              "bfe.action-mismatch-rejected");
        auto absent = knjson::Value::MakeObject();
        absent.Set(L"kind", knjson::Value(L"callouts"));
        absent.Set(L"calloutId", knjson::Value(L"99"));
        check(EnrichBfeRow(absent, records, true) && absent.Get(L"managementState").AsString(L"") == L"NotPresentInBfe",
              "bfe.registration-only-not-fabricated");
        EnrichBfeRow(absent, records, false);
        check(absent.Get(L"managementState").AsString(L"") == L"Unavailable", "bfe.incomplete-table-not-absence");
        auto callout = knjson::Value::MakeObject();
        callout.Set(L"kind", knjson::Value(L"callouts"));
        callout.Set(L"calloutId", knjson::Value(L"7"));
        callout.Set(L"calloutKey", knjson::Value(records[3].Key));
        check(EnrichBfeRow(callout, records, true) && callout.Get(L"key").IsNull() &&
              callout.Get(L"calloutKey").AsString(L"") == records[3].Key, "bfe.callout-keeps-one-guid-column");
    }
    {
        auto memory = fixture(0);
        WalkBudget budget;
        budget.Cancelled = []()
        {
            return true;
        };
        BfeReader read(memory, budget);
        check(!VerifyBfeImage(read, module) && budget.Report.State == Status::Cancelled && memory.Reads == 0,
              "bfe.profile-preserves-cancellation");
    }
    {
        ByteFixture memory;
        constexpr uint64_t peb = 0x600000, ldr = 0x610000, entry = 0x620000;
        memory.Put(peb + 0x18, ldr);
        memory.Put(ldr + 0x10, entry);
        memory.Put(ldr + 0x18, entry);
        memory.Text(entry, {}, 0x68);
        memory.Put(entry, ldr + 0x10);
        memory.Put(entry + 8, ldr + 0x10);
        memory.Put(entry + 0x30, module);
        memory.Put(entry + 0x58, 14, 2);
        memory.Put(entry + 0x5a, 16, 2);
        memory.Put(entry + 0x60, text);
        wide(memory, text, L"bfe.dll");
        WalkBudget budget;
        BfeReader read(memory, budget);
        check(FindBfeModule(read, peb) == module, "bfe.discovers-loaded-user-module");
    }
}
} // namespace knself
