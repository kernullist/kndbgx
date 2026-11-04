#pragma once

#include "Process.h"

namespace kncore
{
struct EventThreadLayout
{
    std::optional<FieldInfo> Tcb;
    std::optional<FieldInfo> Tid;
    std::optional<FieldInfo> OwnerPid;
    std::optional<FieldInfo> Process;
    std::optional<FieldInfo> Pcb;
    ProcessLayout Owner;
};

inline knjson::Value ReadEventThread(TargetReader &reader, uint64_t kthread, const TargetArchitecture &architecture,
                                     const EventThreadLayout &layout)
{
    auto result = knjson::Value::MakeObject();
    for (const auto *field : {L"pid", L"tid", L"image", L"eprocess", L"ethread"})
    {
        result.Set(field, knjson::Value());
    }
    std::wstring reason = L"Thread layout or memory unavailable";
    do
    {
        if (!layout.Tcb || layout.Tcb->Kind != FieldKind::Composite || layout.Tcb->BitOffset || layout.Tcb->BitWidth ||
            !layout.Tcb->ValidFor(UINT32_MAX) || kthread < layout.Tcb->Offset ||
            !architecture.KernelPointer(kthread - layout.Tcb->Offset))
        {
            break;
        }
        const auto ethread = kthread - layout.Tcb->Offset;
        result.Set(L"ethread", knjson::Value(Hex(ethread)));
        const auto readId = [&](const std::optional<FieldInfo> &field) -> std::optional<uint64_t>
        {
            if (!field || field->Size != architecture.PointerBytes || field->BitOffset || field->BitWidth)
            {
                return {};
            }
            const auto id = ReadField(reader, ethread, field);
            return id && *id <= UINT32_MAX ? id : std::nullopt;
        };
        const auto tid = readId(layout.Tid);
        const auto ownerPid = readId(layout.OwnerPid);
        result.Set(L"tid", OptionalNumber(tid));
        result.Set(L"pid", OptionalNumber(ownerPid));
        if (!layout.Process || layout.Process->Kind != FieldKind::Pointer ||
            layout.Process->Size != architecture.PointerBytes || layout.Process->BitOffset || layout.Process->BitWidth ||
            !layout.Pcb || layout.Pcb->Kind != FieldKind::Composite || layout.Pcb->BitOffset || layout.Pcb->BitWidth ||
            !layout.Pcb->ValidFor(UINT32_MAX))
        {
            break;
        }
        const auto process = ReadField(reader, ethread, layout.Process);
        if (!process || *process < layout.Pcb->Offset || !architecture.KernelPointer(*process - layout.Pcb->Offset))
        {
            break;
        }
        ProcessRow owner;
        ReadProcess(reader, *process - layout.Pcb->Offset, layout.Owner, owner);
        if (!owner.PidKnown || owner.Pid > UINT32_MAX || (ownerPid && *ownerPid != owner.Pid))
        {
            reason = L"Thread owning process could not be verified";
            break;
        }
        result.Set(L"eprocess", knjson::Value(Hex(owner.Eprocess)));
        result.Set(L"pid", knjson::Value(std::to_wstring(owner.Pid)));
        result.Set(L"image", owner.ImageKnown && !owner.Image.empty() ? knjson::Value(owner.Image) : knjson::Value());
        if (tid && !result.Get(L"image").IsNull())
        {
            reason.clear();
        }
    } while (false);
    result.Set(L"reason", knjson::Value(reason));
    return result;
}
} // namespace kncore
