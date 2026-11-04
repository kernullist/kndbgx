#pragma once

// Kernel per-processor context helpers. In kernel debugging sessions the
// debugger's thread list mirrors processors, which enables per-CPU sampling
// (MSR / control register divergence detection) without a driver.

#include "EngineCore.h"

namespace knengine
{
// Calls fn(processorIndex) with the debugger context switched to that
// processor, restoring the previous context afterwards. Returns false
// when the session is not kernel mode or switching fails.
typedef bool (*ProcessorCallback)(ULONG processorIndex, void *context);

bool ForEachProcessor(DbgSession &session, ProcessorCallback callback, void *context);

ULONG CountProcessors(DbgSession &session);

// Executes "rdmsr <msr>" on the CURRENT processor context and parses the
// hex result. msrSpec accepts a symbol-ish expression or hex number.
bool ReadMsr(DbgSession &session, const std::wstring &msrSpec, ULONG64 *value);
} // namespace knengine
