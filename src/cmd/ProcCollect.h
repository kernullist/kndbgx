#pragma once

// Shared native process-list collection used by !dml_proc and the
// hidden-process cross-view scanner.

#include <string>
#include <vector>

#include "../engine/LayoutResolver.h"
#include "../engine/EngineCore.h"
#include "CmdTypes.h"
#include "../core/Process.h"

namespace kncmd
{
using ProcRow = kncore::ProcessRow;

bool KernelArchitecture(knengine::DbgSession &session, kncore::TargetArchitecture *architecture);
kncore::ProcessLayout ResolveProcessLayout(knengine::LayoutResolver &layout);

// Walks ActiveProcessLinks. Returns true for Success or Partial; other failures
// may still retain observed rows and diagnostics in `out`.
bool CollectProcesses(knengine::DbgSession &session, knengine::LayoutResolver &layout, std::vector<ProcRow> *rows, CmdText &out);

// Name selection requires a complete inventory; numeric identities can use
// observed rows from a partial walk. Unobserved addresses require a typed read.
bool MatchProcessTarget(const std::vector<ProcRow> &rows, const std::wstring &token, ProcRow *match, bool inventoryComplete);
bool ResolveProcessTarget(knengine::DbgSession &session, knengine::LayoutResolver &layout, const std::vector<ProcRow> &rows,
                          const std::wstring &token, ProcRow *match, bool inventoryComplete);
// Propagate selection diagnostics without publishing the prerequisite inventory as command rows.
// A nonempty selector identifies a failed lookup after successful or partial collection.
void ReportProcessSelectionFailure(const CmdText &inventory, CmdText &out, const std::wstring &unresolvedSelector = {});
// An empty selector uses the debugger's implicit process, including attached processes.
bool ResolveSelectedProcess(Ctx &ctx, knengine::LayoutResolver &layout, const std::wstring &selector, ProcRow &target);
bool CurrentKernelThread(Ctx &ctx, uint64_t &thread);
} // namespace kncmd
