#pragma once

// Mutation classification, preview and pending approval lifecycle.
// Changes use per-operation approval without a global write switch.

#include <string>
#include "../core/Result.h"

namespace knengine
{
class DbgSession;
}

namespace kncmd
{
void DiscardChangePlans();

// True when the raw command line mutates target memory or registers.
bool ClassifyAsWrite(const std::wstring &line);

// Prepares the complete bounded mutation plan for the UX confirmation dialog.
// Returns false when the form or target is unsupported.
bool PreviewWriteTarget(knengine::DbgSession &session, const std::wstring &line, std::wstring *previewText);
} // namespace kncmd
