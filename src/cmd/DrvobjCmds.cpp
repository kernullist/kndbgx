#include "CollectorSupport.h"
#include "../core/ObjectRead.h"
#include "../core/KernelAnalysis.h"
#include <tuple>
#include "../engine/ObjectDirectory.h"

namespace kncmd
{
namespace
{
bool DriverObject(Ctx &ctx, knengine::LayoutResolver &layout, uint64_t *address)
{
    if (ctx.Args.size() < 2)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"[drvobj] usage: !drvobj <driver-name|address>");
        return false;
    }
    uint64_t numeric = 0;
    const bool isAddress = kncore::ParseUnsigned(ctx.Args[1], 16, &numeric) && (numeric >> 63) != 0;
    knengine::ObjectDirectoryWalker objects(ctx.Session);
    unsigned driverType = UINT32_MAX;
    const bool typeVerified = objects.ResolveTypeIndex(L"Driver", &driverType);
    const auto nameFieldAlways = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverName");
    if (!typeVerified && isAddress)
    {
        // Address form has no name to corroborate; a type index is required.
        ctx.Out.Fail(kncore::Status::Unavailable, L"Driver object type unavailable; name form supports the DriverName echo fallback");
        return false;
    }
    if (typeVerified && isAddress)
    {
        unsigned actual = UINT32_MAX;
        if (!objects.ObjectTypeIndex(numeric, &actual) || actual != driverType)
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Address is not a verified Driver object");
            return false;
        }
        *address = numeric;
        return true;
    }
    const auto wanted = kncore::NormalizeDriverName(ctx.Args[1]);
    if (!wanted || !nameFieldAlways)
    {
        ctx.Out.Fail(!wanted ? kncore::Status::InvalidInput : kncore::Status::Unavailable, L"Driver name or DriverName layout unavailable");
        return false;
    }
    const auto wantedFold = kncore::FoldName(*wanted);
    uint64_t found = 0;
    uint64_t unreadable = 0;
    const bool walked = objects.VisitDirectoryNamed(
        L"Driver",
        [&](ULONG64 body, const std::wstring &entryName)
        {
            unsigned type = UINT32_MAX;
            std::wstring name;
            const bool readable = kncore::ValidRange(body, static_cast<uint64_t>(nameFieldAlways->Offset) + nameFieldAlways->Size) &&
                                  ReadUnicodeString(ctx.Session, layout, body + nameFieldAlways->Offset, &name);
            // With a verified type index the object type must match; without
            // one, the object's own DriverName must echo its directory entry.
            const bool typeOk = !typeVerified || (objects.ObjectTypeIndex(body, &type) && type == driverType);
            const bool echoOk = typeVerified || (readable && !entryName.empty() &&
                                                 kncore::FoldName(name).ends_with(L"\\" + kncore::FoldName(entryName)));
            if (!typeOk || !echoOk || !readable)
            {
                ++unreadable;
                return true;
            }
            if (kncore::FoldName(name) == wantedFold)
            {
                found = body;
                return false;
            }
            return true;
        },
        nullptr);
    if (found == 0 || !walked)
    {
        ctx.Out.Details = objects.Report();
        ctx.Out.Fail(kncore::Status::Unavailable, unreadable != 0 ? L"Driver name not resolved; some directory candidates unreadable"
                                                                  : L"Driver not observed in directory");
        return false;
    }
    *address = found;
    return true;
}

knjson::Value DeviceRow(Ctx &ctx, knengine::LayoutResolver &layout, uint64_t device,
                       const kncore::TargetArchitecture &architecture, kncore::WalkBudget &budget)
{
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"Device"));
    row.Set(L"device", knjson::Value(kncore::Hex(device)));
    for (const auto &[label, field, hex] : {std::tuple(L"type", L"DeviceType", true), std::tuple(L"flags", L"Flags", true),
                                         std::tuple(L"stackSize", L"StackSize", false)})
    {
        const auto value = kncore::ReadField(ctx.Session, device, layout.Field(L"nt", L"_DEVICE_OBJECT", field));
        row.Set(label, kncore::OptionalNumber(value, hex));
        if (!value)
        {
            ++budget.Report.Collected.Unknown;
        }
    }
    const auto driver = kncore::ReadField(ctx.Session, device, layout.Field(L"nt", L"_DEVICE_OBJECT", L"DriverObject"));
    const auto name = driver && architecture.KernelPointer(*driver) ?
        RecordUnicode(ctx.Session, layout, *driver, layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverName")) : knjson::Value();
    row.Set(L"driverObject", kncore::OptionalNumber(driver, true));
    row.Set(L"driverName", name);
    if (name.IsNull())
    {
        ++budget.Report.Collected.Unknown;
    }
    return row;
}

void DeviceChain(Ctx &ctx, knengine::LayoutResolver &layout, uint64_t first, const wchar_t *nextName,
                 const kncore::TargetArchitecture &architecture, kncore::WalkBudget &budget)
{
    const auto next = layout.Field(L"nt", L"_DEVICE_OBJECT", nextName);
    if (!next || next->Size != architecture.PointerBytes)
    {
        budget.Stop(kncore::Status::Unavailable, L"DeviceChainLayoutUnavailable");
        return;
    }
    budget.StartTraversal();
    kncore::WalkChain(ctx.Session, first, 0, next->Offset, architecture, budget,
                      [&](uint64_t device)
                      {
                          if (!architecture.KernelPointer(device))
                          {
                              return kncore::VisitDecision::Failed;
                          }
                          auto row = DeviceRow(ctx, layout, device, architecture, budget);
                          row.Set(L"link", knjson::Value(nextName));
                          budget.Report.Rows.Push(row);
                          ctx.Out.AddLine(L"[device] " + row.Write());
                          return kncore::VisitDecision::Continue;
                      });
}
} // namespace

void ScanDrvobj(Ctx &ctx)
{
    kncore::WalkBudget budget;
    budget.MaxNodes = 4096;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:DriverObject"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    uint64_t object = 0;
    if (!DriverObject(ctx, layout, &object))
    {
        return;
    }
    const auto nameField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverName");
    const auto startField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverStart");
    const auto sizeField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverSize");
    const auto deviceField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DeviceObject");
    const auto majors = layout.Field(L"nt", L"_DRIVER_OBJECT", L"MajorFunction");
    if (!nameField || !sizeField || sizeField->Size != sizeof(ULONG) || !majors || !majors->ArrayCount || !majors->ElementSize ||
        *majors->ElementSize != 8 || *majors->ArrayCount > 256)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Driver layout width/array metadata unavailable");
        return;
    }
    std::wstring name;
    const bool nameKnown = kncore::ValidRange(object, static_cast<uint64_t>(nameField->Offset) + nameField->Size) &&
                           ReadUnicodeString(ctx.Session, layout, object + nameField->Offset, &name);
    const auto start = kncore::ReadField(ctx.Session, object, startField);
    const auto size = kncore::ReadField(ctx.Session, object, sizeField);
    const auto device = kncore::ReadField(ctx.Session, object, deviceField);
    auto driver = knjson::Value::MakeObject();
    driver.Set(L"kind", knjson::Value(L"Driver"));
    driver.Set(L"object", knjson::Value(kncore::Hex(object)));
    driver.Set(L"name", nameKnown ? knjson::Value(name) : knjson::Value());
    driver.Set(L"start", kncore::OptionalNumber(start, true));
    driver.Set(L"size", kncore::OptionalNumber(size, true));
    driver.Set(L"firstDevice", kncore::OptionalNumber(device, true));
    budget.Report.Rows.Push(driver);
    if (!nameKnown || !start || !size || !device)
    {
        ++budget.Report.Collected.Unknown;
    }
    ctx.Out.AddLine(L"[driver] " + driver.Write());
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    for (uint32_t index = 0; index < *majors->ArrayCount; ++index)
    {
        if (ctx.Session.Cancelled())
        {
            budget.Stop(kncore::Status::Cancelled, L"DriverDispatchCancelled");
            break;
        }
        auto field = *majors;
        field.Offset += index * *majors->ElementSize;
        field.Size = *majors->ElementSize;
        const auto handler = kncore::ReadField(ctx.Session, object, field);
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"DriverDispatch"));
        row.Set(L"driverObject", knjson::Value(kncore::Hex(object)));
        row.Set(L"major", knjson::Value(std::to_wstring(index)));
        row.Set(L"majorName", knjson::Value(kncore::IrpMajorName(index)));
        row.Set(L"handler", kncore::OptionalNumber(handler, true));
        std::wstring ownership = L"Unknown";
        if (handler && *handler != 0)
        {
            const auto owner = owners.Find(*handler, ctx.Session.RefreshStamp());
            ownership = OwnershipText(owner);
            if (owner.State == kncore::OwnershipState::Unknown)
            {
                ++budget.Report.Collected.Unknown;
            }
        }
        else if (handler)
        {
            ownership = L"NullObserved";
        }
        else
        {
            ++budget.Report.Collected.Unreadable;
        }
        row.Set(L"ownership", knjson::Value(ownership));
        budget.Report.Rows.Push(row);
        ++budget.Report.Collected.Visited;
        ctx.Out.AddLine(L"[dispatch] " + row.Write());
    }
    if (!budget.Stopped && device)
    {
        DeviceChain(ctx, layout, *device, L"NextDevice", architecture, budget);
    }
    budget.Report.Limitations.Push(
        knjson::Value(L"Ownership describes observed module ranges; it does not establish pointer integrity or maliciousness."));
    FinishCollection(ctx, budget);
}

void ScanDevstack(Ctx &ctx)
{
    kncore::WalkBudget budget;
    budget.MaxNodes = 256;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:DeviceAttachments"))
    {
        return;
    }
    ULONG64 device = 0;
    if (!EvalAddress(ctx.Session, ctx.Args[1], &device) || !architecture.KernelPointer(device))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid device address");
        return;
    }
    knengine::ObjectDirectoryWalker objects(ctx.Session);
    unsigned deviceType = UINT32_MAX;
    unsigned actual = UINT32_MAX;
    if (!objects.ResolveTypeIndex(L"Device", &deviceType) || !objects.ObjectTypeIndex(device, &actual) || actual != deviceType)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Device object type not corroborated");
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    DeviceChain(ctx, layout, device, L"AttachedDevice", architecture, budget);
    const auto extensionField = layout.Field(L"nt", L"_DEVICE_OBJECT", L"DeviceObjectExtension");
    const auto attachedTo = layout.Field(L"nt", L"_DEVOBJ_EXTENSION", L"AttachedTo");
    if (!extensionField || !attachedTo)
    {
        ++budget.Report.Collected.Unknown;
        budget.Report.Limitations.Push(knjson::Value(L"Cannot read downward attachments; upward attachments are included."));
    }
    else
    {
        uint64_t current = device;
        while (!budget.Stopped)
        {
            const auto extension = kncore::ReadField(ctx.Session, current, extensionField);
            const auto lower =
                extension && architecture.KernelPointer(*extension) ? kncore::ReadField(ctx.Session, *extension, attachedTo) : std::nullopt;
            if (!lower)
            {
                ++budget.Report.Collected.Unreadable;
                break;
            }
            if (*lower == 0)
            {
                break;
            }
            if (!architecture.KernelPointer(*lower) || !budget.Consume(*lower, architecture))
            {
                if (!budget.Stopped)
                {
                    budget.Stop(kncore::Status::Partial, L"InvalidLowerDevice");
                }
                break;
            }
            auto row = DeviceRow(ctx, layout, *lower, architecture, budget);
            row.Set(L"attachedFrom", knjson::Value(kncore::Hex(current)));
            row.Set(L"link", knjson::Value(L"AttachedTo"));
            budget.Report.Rows.Push(row);
            ctx.Out.AddLine(L"[device.down] " + row.Write());
            current = *lower;
        }
    }
    FinishCollection(ctx, budget);
}
} // namespace kncmd
