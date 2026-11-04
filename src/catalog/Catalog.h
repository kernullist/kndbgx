#pragma once

// Registry-backed command catalog for the UX sidebar, help and completion.

#include <string>
#include <vector>
#include <optional>

namespace kncat
{
enum class Support
{
    Native,
    Host,
    Planned
};

struct CommandInfo
{
    const wchar_t *Group;
    const wchar_t *Name;
    const wchar_t *Synopsis;
    Support Level;
};

const std::vector<CommandInfo> &All();

const wchar_t *SupportText(Support level);

const std::vector<std::wstring> &WorkspaceHelp();

// Complete names, help operands, process selectors and registered options.
// Returns full drafts; values and quoted operands are never invented.
std::vector<std::wstring> CompletionsFor(const std::wstring &prefix);

struct SymbolCompletionQuery
{
    std::wstring Head;
    std::wstring Word;
};

std::vector<size_t> SymbolOperands(const std::wstring &command);
bool SymbolCompletionWord(const std::wstring &word);
std::optional<SymbolCompletionQuery> SymbolQueryFor(const std::wstring &prefix, const std::wstring &suffix = L"");
} // namespace kncat
