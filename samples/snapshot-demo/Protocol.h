#pragma once

#if !defined(_KERNEL_MODE)
#include <stdint.h>
#include <stddef.h>
#endif

// Include ntddk.h or Windows.h and winioctl.h before this shared header.
namespace knsnapshot
{
#if defined(_KERNEL_MODE)
using uint32_t = UINT32;
using int32_t = INT32;
using uint64_t = UINT64;
#endif
constexpr wchar_t ServiceName[] = L"KnSnapshotDemo";
constexpr wchar_t DeviceName[] = L"\\Device\\KnSnapshotDemo";
constexpr wchar_t SymbolicLink[] = L"\\DosDevices\\KnSnapshotDemo";
constexpr wchar_t UserDevice[] = L"\\\\.\\KnSnapshotDemo";
constexpr uint32_t Version = 1;
constexpr uint32_t DeviceType = 0x8000u;
constexpr uint32_t Query = CTL_CODE(DeviceType, 0x800u, METHOD_BUFFERED, FILE_READ_DATA);
constexpr uint32_t SetPhase = CTL_CODE(DeviceType, 0x801u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);

enum class Phase : uint32_t
{
    Off = 0,
    A = 1,
    B = 2
};

enum Registration : uint32_t
{
    Process = 1,
    Thread = 2,
    Required = Process | Thread
};

struct PhaseRequest
{
    uint32_t Size;
    uint32_t AbiVersion;
    Phase RequestedPhase;
    uint32_t Reserved;
};

struct alignas(8) State
{
    uint32_t Size;
    uint32_t AbiVersion;
    Phase ActivePhase;
    uint32_t RegisteredMask;
    int32_t OperationStatus;
    int32_t CleanupStatus;
    int32_t RegistrationStatus;
    uint32_t Reserved;
    uint64_t Generation;
    // Per-bank counters: process pre, thread pre, process post, thread post, all pre.
    uint64_t Events[2][5];
};

static_assert(sizeof(PhaseRequest) == 16);
static_assert(sizeof(State) == 120);
#if defined(_KERNEL_MODE)
static_assert(FIELD_OFFSET(State, Events) == 40);
#else
static_assert(offsetof(State, Events) == 40);
#endif
static_assert(alignof(State) == 8);
}
