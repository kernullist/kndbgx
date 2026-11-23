#pragma once

// Kernel module enumeration and address ownership helpers built on the
// hosting debugger's module list.

#include <string>
#include <vector>

#include "EngineCore.h"
#include "../core/Ownership.h"

namespace knengine
{
struct KernelModuleInfo
{
    std::wstring ModuleName; // short name, e.g. nt
    std::wstring ImageName;  // e.g. ntoskrnl.exe (may be empty)
    ULONG64 Base = 0;
    ULONG Size = 0;
    ULONG Timestamp = 0;
};

// Enumerates every module in debugger load order.
bool EnumerateKernelModules(DbgSession &session, std::vector<KernelModuleInfo> *modules, kncore::Result *report = nullptr);

kncore::OwnershipIndex CollectOwnershipIndex(DbgSession &session, kncore::Result *report = nullptr);

// Same single inventory read, handed back to the caller so a command can judge
// ownership and match builds against exactly the snapshot it reports on.
kncore::OwnershipIndex CollectOwnershipIndex(DbgSession &session, std::vector<KernelModuleInfo> *modules,
                                            kncore::Result *report = nullptr);

// Returns the unique containing module, or nullptr for absent/ambiguous ownership.
const KernelModuleInfo *FindModuleForAddress(const std::vector<KernelModuleInfo> &modules, ULONG64 address);

bool IsKernelCanonical(ULONG64 address);
} // namespace knengine
