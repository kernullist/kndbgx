#pragma once

// Formatting and argument helpers shared by native command handlers.

#include <string>
#include <vector>

#include "../engine/EngineCore.h"

namespace knengine
{
class LayoutResolver;
}

namespace kncmd
{
// 16-digit grouped form: fffff804`03800000
std::wstring FmtAddr(ULONG64 value);

// Zero-padded hex without grouping.
std::wstring FmtHexN(ULONG64 value, int digits);

// Unpadded hex.
std::wstring FmtHex(ULONG64 value);

std::wstring FmtDec(ULONG64 value);

// Loaded "module!symbol+0xdelta", module/RVA fallback, or empty without an owner.
std::wstring AnnotateSymbol(knengine::DbgSession &session, ULONG64 address);

// Annotate collected virtual addresses after traversal, loading owning PDBs on demand.
void AnnotateResultSymbols(knengine::DbgSession &session, kncore::Result &report);

// Resolves a token (hex, decimal, module!symbol, arithmetic).
bool EvalAddress(knengine::DbgSession &session, const std::wstring &token, ULONG64 *value);

// Parses "<start> L<count>" or "<start> <end-inclusive>" argument shapes.
// Returns false and fills errorText on malformed input.
bool ParseDisplayRange(knengine::DbgSession &session, const std::vector<std::wstring> &args, size_t index, ULONG64 defaultLength,
                       ULONG64 maxLength, ULONG64 *start, ULONG64 *length, std::wstring *errorText, unsigned unitBytes = 1);

std::vector<std::wstring> TokenizeLine(const std::wstring &line);

bool ReadUnicodeString(knengine::DbgSession &session, knengine::LayoutResolver &layout, ULONG64 uniAddress, std::wstring *value);

// Host Win32/NtQuery collectors are only valid on local live kernel.
bool SessionIsLocalLiveKernel(knengine::DbgSession &session);

// Tagged refusal line for host-only collectors.
std::wstring HostCollectorRefusal(const wchar_t *tag);

// Pulls `/json <path>` from anywhere in args. Remaining tokens (minus
// the flag pair) are returned in `rest` when rest is non-null.
bool ExtractJsonPath(const std::vector<std::wstring> &args, size_t startIndex, std::wstring *jsonPath, std::vector<std::wstring> *rest);
} // namespace kncmd
