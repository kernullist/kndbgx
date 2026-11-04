#include <ntddk.h>
#include <wdmsec.h>
#include "../Protocol.h"

extern "C" DRIVER_INITIALIZE DriverEntry;

namespace
{
using namespace knsnapshot;

struct DeviceState
{
    KMUTEX Mutex;
    PFILE_OBJECT Owner;
    Phase ActivePhase;
    ULONG Mask;
    NTSTATUS OperationStatus;
    NTSTATUS CleanupStatus;
    NTSTATUS RegistrationStatus;
    ULONGLONG Generation;
    PVOID ObjectRegistration;
};

DeviceState *g_State = nullptr;
alignas(8) volatile LONG64 g_Events[2][5] = {};

// Private device-class GUID; no existing device class is modified.
const GUID kDeviceClass = {0xbc67ccbd, 0x1764, 0x4faa, {0xb0, 0x5d, 0xd8, 0xc8, 0x6f, 0xd7, 0xa5, 0x30}};

template <ULONG Bank> struct Callbacks
{
    __declspec(noinline) static OB_PREOP_CALLBACK_STATUS Pre(PVOID context, POB_PRE_OPERATION_INFORMATION operation)
    {
        UNREFERENCED_PARAMETER(context);
        const ULONG kind = operation->ObjectType == *PsProcessType ? 0 : 1;
        InterlockedIncrement64(&g_Events[Bank][kind]);
        InterlockedIncrement64(&g_Events[Bank][4]);
        return OB_PREOP_SUCCESS;
    }

    __declspec(noinline) static void Post(PVOID context, POB_POST_OPERATION_INFORMATION operation)
    {
        UNREFERENCED_PARAMETER(context);
        const ULONG kind = operation->ObjectType == *PsProcessType ? 2 : 3;
        InterlockedIncrement64(&g_Events[Bank][kind]);
    }
};

DRIVER_UNLOAD Unload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLEANUP)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH Dispatch;

NTSTATUS RemoveCallbacks()
{
    if (g_State->ObjectRegistration != nullptr)
    {
        // Unregister exactly once before any code or state can be released.
        ObUnRegisterCallbacks(g_State->ObjectRegistration);
        g_State->ObjectRegistration = nullptr;
    }
    g_State->Mask = 0;
    g_State->ActivePhase = Phase::Off;
    g_State->CleanupStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

NTSTATUS RegisterCallbacks(Phase phase)
{
    OB_OPERATION_REGISTRATION operations[2] = {};
    operations[0].ObjectType = PsProcessType;
    operations[1].ObjectType = PsThreadType;
    for (auto &operation : operations)
    {
        operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        operation.PreOperation = phase == Phase::A ? Callbacks<0>::Pre : Callbacks<1>::Pre;
        operation.PostOperation = phase == Phase::A ? Callbacks<0>::Post : Callbacks<1>::Post;
    }
    OB_CALLBACK_REGISTRATION registration = {};
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    RtlInitUnicodeString(&registration.Altitude, L"389615.7825");
    registration.OperationRegistration = operations;
    PVOID handle = nullptr;
    const NTSTATUS status = ObRegisterCallbacks(&registration, &handle);
    g_State->RegistrationStatus = status;
    if (NT_SUCCESS(status))
    {
        g_State->ObjectRegistration = handle;
        g_State->Mask = Registration::Required;
        g_State->ActivePhase = phase;
    }
    return status;
}

NTSTATUS ChangePhase(Phase phase)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (phase != g_State->ActivePhase || (phase != Phase::Off && (g_State->Mask & Registration::Required) != Registration::Required))
    {
        status = RemoveCallbacks();
        if (NT_SUCCESS(status) && phase != Phase::Off)
        {
            status = RegisterCallbacks(phase);
        }
        ++g_State->Generation;
    }
    g_State->OperationStatus = status;
    return status;
}

void CopyState(State &output)
{
    RtlZeroMemory(&output, sizeof(output));
    output.Size = sizeof(output);
    output.AbiVersion = Version;
    output.ActivePhase = g_State->ActivePhase;
    output.RegisteredMask = g_State->Mask;
    output.OperationStatus = g_State->OperationStatus;
    output.CleanupStatus = g_State->CleanupStatus;
    output.RegistrationStatus = g_State->RegistrationStatus;
    output.Generation = g_State->Generation;
    for (ULONG bank = 0; bank < 2; ++bank)
    {
        for (ULONG kind = 0; kind < 5; ++kind)
        {
            output.Events[bank][kind] = static_cast<uint64_t>(InterlockedCompareExchange64(&g_Events[bank][kind], 0, 0));
        }
    }
}

NTSTATUS Complete(PIRP irp, NTSTATUS status, ULONG_PTR bytes = 0)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

_Use_decl_annotations_ NTSTATUS Dispatch(PDEVICE_OBJECT device, PIRP irp)
{
    UNREFERENCED_PARAMETER(device);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return Complete(irp, STATUS_INVALID_DEVICE_STATE);
    }
    auto *stack = IoGetCurrentIrpStackLocation(irp);
    const auto major = stack->MajorFunction;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes = 0;
    KeWaitForSingleObject(&g_State->Mutex, Executive, KernelMode, FALSE, nullptr);
    do
    {
        if (major == IRP_MJ_CREATE)
        {
            if (g_State->Owner != nullptr || stack->FileObject->FileName.Length != 0)
            {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            g_State->Owner = stack->FileObject;
            stack->FileObject->FsContext = g_State;
            status = STATUS_SUCCESS;
            break;
        }
        if (major == IRP_MJ_CLEANUP || major == IRP_MJ_CLOSE)
        {
            if (g_State->Owner == stack->FileObject)
            {
                g_State->OperationStatus = RemoveCallbacks();
                ++g_State->Generation;
                g_State->Owner = nullptr;
                stack->FileObject->FsContext = nullptr;
            }
            status = STATUS_SUCCESS;
            break;
        }
        if (major != IRP_MJ_DEVICE_CONTROL || g_State->Owner != stack->FileObject || stack->FileObject->FsContext != g_State)
        {
            break;
        }
        const auto &control = stack->Parameters.DeviceIoControl;
        if (control.IoControlCode != Query && control.IoControlCode != SetPhase)
        {
            break;
        }
        if (control.OutputBufferLength < sizeof(State))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (irp->AssociatedIrp.SystemBuffer == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (control.IoControlCode == SetPhase)
        {
            if (control.InputBufferLength != sizeof(PhaseRequest))
            {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }
            // METHOD_BUFFERED aliases the request and response storage.
            const auto request = *static_cast<const PhaseRequest *>(irp->AssociatedIrp.SystemBuffer);
            if (request.Size != sizeof(request) || request.AbiVersion != Version || request.Reserved != 0 ||
                static_cast<uint32_t>(request.RequestedPhase) > static_cast<uint32_t>(Phase::B))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            ChangePhase(request.RequestedPhase);
        }
        else if (control.InputBufferLength != 0)
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        CopyState(*static_cast<State *>(irp->AssociatedIrp.SystemBuffer));
        bytes = sizeof(State);
        status = STATUS_SUCCESS;
    }
    while (false);
    KeReleaseMutex(&g_State->Mutex, FALSE);
    return Complete(irp, status, bytes);
}

_Use_decl_annotations_ void Unload(PDRIVER_OBJECT driver)
{
    // Open device handles prevent normal service unload. Cleanup is idempotent.
    KeWaitForSingleObject(&g_State->Mutex, Executive, KernelMode, FALSE, nullptr);
    RemoveCallbacks();
    NT_ASSERT(g_State->Owner == nullptr);
    KeReleaseMutex(&g_State->Mutex, FALSE);
    UNICODE_STRING link = RTL_CONSTANT_STRING(SymbolicLink);
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(driver->DeviceObject);
    g_State = nullptr;
}
}

_Use_decl_annotations_ extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(knsnapshot::DeviceName);
    UNICODE_STRING link = RTL_CONSTANT_STRING(knsnapshot::SymbolicLink);
    PDEVICE_OBJECT device = nullptr;
    NTSTATUS status = IoCreateDeviceSecure(driver, sizeof(DeviceState), &deviceName, knsnapshot::DeviceType, FILE_DEVICE_SECURE_OPEN,
                                          TRUE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, &kDeviceClass, &device);
    if (NT_SUCCESS(status))
    {
        g_State = static_cast<DeviceState *>(device->DeviceExtension);
        KeInitializeMutex(&g_State->Mutex, 0);
        g_State->RegistrationStatus = STATUS_SUCCESS;
        driver->MajorFunction[IRP_MJ_CREATE] = Dispatch;
        driver->MajorFunction[IRP_MJ_CLEANUP] = Dispatch;
        driver->MajorFunction[IRP_MJ_CLOSE] = Dispatch;
        driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch;
        driver->DriverUnload = Unload;
        status = IoCreateSymbolicLink(&link, &deviceName);
        if (NT_SUCCESS(status))
        {
            device->Flags &= ~DO_DEVICE_INITIALIZING;
        }
        else
        {
            IoDeleteDevice(device);
            g_State = nullptr;
        }
    }
    return status;
}
