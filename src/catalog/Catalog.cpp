#include "Catalog.h"
#include "../cmd/CommandSpec.h"
#include "../util/Text.h"

#include <algorithm>
#include <cwctype>

namespace kncat
{
const std::vector<CommandInfo> &All()
{
    static const std::vector<CommandInfo> catalog = []()
    {
        std::vector<CommandInfo> result;
        for (const auto &spec : kncmd::CommandSpecs())
        {
            const auto level = kncmd::HasEffect(spec.Effects, kncmd::Effect::OpaqueEngine) ? Support::Host : Support::Native;
            result.push_back({spec.Group, spec.Name, spec.Synopsis, level});
            for (const auto *alias : spec.Aliases)
            {
                result.push_back({spec.Group, alias, spec.Synopsis, level});
            }
        }
        return result;
    }();
    return catalog;
}

const wchar_t *SupportText(Support level)
{
    switch (level)
    {
    case Support::Native:
        return L"native";
    case Support::Host:
        return L"host";
    case Support::Planned:
        return L"planned";
    }

    return L"?";
}

const std::vector<std::wstring> &WorkspaceHelp()
{
    static const std::vector<std::wstring> lines =
    {
        L"KNDbgX workspace: run !kndbgx in WinDbg to open the UI; enter commands without the !kndbgx prefix in the UI.",
        L"WinDbg input: names outside the KNDbgX registry run directly in WinDbg, including .echo, .formats and external extensions. "
        L"Registered names keep KNDbgX syntax and per-operation approval. WinDbg command effects are unverified. "
        L"Output is retained in Results and Console; existing approvals are discarded.",
        L"Current process: name, decimal PID and full EPROCESS stay visible across tabs. Click a value to copy it, or right-click for options. "
        L"Idle status refreshes every 3 seconds; running, disconnected or unreadable targets show Unavailable. Names can be truncated by the kernel ImageFileName field.",
        L"Processes: the right panel's Processes tab keeps a searchable inventory beside Results. Select a row for Details, Threads, VADs or Token. "
        L"Detail actions update Results while retaining the list; a narrow drawer hides to reveal the result. "
        L"Attach address space requires a stopped x64 remote kernel or dump with readable identity fields; refresh stale lists first.",
        L"Inspect: the toolbar button or Ctrl+M toggles a separate right panel with Processes, Memory, Disassembly and Registers tabs. "
        L"Drag its left divider to resize; Hide and tab switches preserve the captured data, process search and selections. "
        L"Processes and Registers collect on first use and after context changes while visible. Memory reads are explicit; Disassembly also supports Follow IP.",
        L"Floating views: each tab's Float opens its own resizable window, including from the floating group; all five windows can coexist. "
        L"Dock or an individual window's X returns that view to Inspect. Its tab offers Show window and Dock here; Dock all restores every view. "
        L"Drafts, captured data, selection and scroll are retained. Float group detaches the tab group while individual views stay open. "
        L"Drag a native title bar onto a workspace or group guide to dock. A workspace drop returns the group too; independent siblings stay open. "
        L"The grouped window's X/Hide hides it; Inspect reopens it. Dock returns the group. "
        L"Main-window close/reopen hides/restores all children; a recreated workspace starts docked. Approvals and the palette open in the main window. "
        L"A failed independent window returns its retained view to Inspect; a failed floating group returns to the main workspace. "
        L"Every view shares the same target context and Busy checks.",
        L"Memory: select the Memory tab. "
        L"Enter an address or debugger expression, choose Virtual/Physical, size and display width, then Read or Enter. "
        L"Previous/Next moves by the displayed range. ?? means unreadable bytes. Read details shows saved read counts, native errors and capture kind. "
        L"Click ?? or press Enter on the grid to open it without another read. Context changes require an explicit refresh; memory is read only.",
        L"Disassembly: select the Disassembly tab, enter an address or expression and choose 16/32/64 instructions, then Read or Enter. "
        L"Current IP reads the current instruction; Next instructions starts at the decoded boundary. Previous view restores a captured view. "
        L"Row details Disassemble opens this tab without replacing Results. Reads require a stopped target; failures preserve the previous view.",
        L"Registers: Inspect > Registers keeps values beside Results or in its own floating window. It refreshes on first use and each new stopped context while visible. "
        L"Filter All/Pinned/Changed or names, use Refresh to retry, and click a value to copy it. Changed marks compare the same debugger session and process/thread/CPU. "
        L"Scalar values and raw vector bytes retain their exact text; unavailable values are not zero. Running, failed or cancelled reads retain the previous capture with a notice. "
        L"The view is read only and uses the debugger's current thread/CPU; selecting or attaching a process does not switch that register context. "
        L"Use registers [name] (alias r) for a separate command-result snapshot without replacing Inspect.",
        L"Execution: the header Continue/Break button controls a supported live target. F5 continues; F10/F11 step over/into while Disassembly is visible, including in its own window. "
        L"Break interrupts target execution; Cancel operation cancels workspace work. Dumps and local KD cannot execute. "
        L"Follow IP updates Disassembly on new live stops without replacing Results or the command draft, and keeps an explicitly selected Registers tab visible. "
        L"Manual code browsing pauses following; Current IP or Follow IP enables it again. Reads wait for shared engine work and may be delayed by WinDbg.",
        L"Breakpoints: open Breakpoints to add a code breakpoint by address/expression, or select a row to Enable, Disable or Delete it. "
        L"Enable/Disable applies on click; Add/Delete requires preview approval. There is no global write switch. "
        L"Changes require a stopped live target and current breakpoint identity. "
        L"Disassembly reads also refresh breakpoints: filled/hollow BP markers show enabled/disabled code breakpoints. "
        L"Click a marker or select an instruction and press F9 to add or toggle it. Applied instruction changes refresh that decoded range.",
        L"Minifilters: !minifilter / !fltmgr uses one 60-second cooperative traversal deadline after layout and ownership setup. "
        L"Frames, filters and operations share the deadline; entry/row bounds, end-marker checks and cancellation remain enforced. "
        L"Unreadable or incomplete lists remain Partial; slow engine I/O can outlast the deadline.",
        L"Copy: click a cell or Row details value for its full text; right-click for value/row copy options. Ctrl+C on the grid copies the selected row; "
        L"focused cells copy their value. Selected text takes precedence. Shift+F10 opens copy options; clipboard failures offer manual copy.",
        L"Input: help <command> shows syntax, aliases and options; help ui (or :help in the UI) opens this guide. "
        L"Tab inserts completion without running it. Help operands, process selector prefixes and registered options complete at the end of input; fill unresolved fields before running.",
        L"Symbol completion: address and symbol operands suggest loaded debugger modules and symbols with full addresses. "
        L"For example, type u nt!KeBug, choose with Up/Down and press Tab. Later operands and unresolved template fields are preserved. "
        L"Memory and Disassembly address inputs offer the same completion without starting a read; Memory Physical mode uses manual addresses. "
        L"Click or refocus an address input to request suggestions again, including after a lookup failure. "
        L"Each address input's Recent list retains 20 completed reads across window reopen; selecting an entry reads it in the current context. "
        L"Memory history restores Virtual or Physical mode. Automatic Follow IP reads and internal breakpoint refreshes do not add entries. "
        L"Physical options anywhere in the draft exclude virtual symbols. Lookup failures retain required parameter templates. "
        L"Deferred symbols must first be loaded in WinDbg; automatic lookup never reloads symbols.",
        L"Shortcuts: Ctrl+K / Ctrl+Shift+P finds commands; Ctrl+L focuses input; Ctrl+B toggles Library; Ctrl+J toggles Console; Ctrl+M toggles Inspect. "
        L"Exact command names and aliases rank first in search. Enter runs a draft; Up/Down selects suggestions or history; "
        L"Shift+Tab moves focus; Escape closes a transient panel.",
        L"Windows: list, show, dock or bring floating views onto the current monitor. Restore adaptive layout keeps captures and drafts. "
        L"Compact/Comfortable density and Console/Row details visibility are saved separately from captured data.",
        L"Results: Rows/Findings and Capture info describe retained results. Export saves the full result. "
        L"Output Off skips new console text; View output retrieves saved text. Operations reads prior outcomes independently of Output On/Off without executing them again.",
        L"Defaults: !threads reads the current thread; !process and !vad use the current process; !token reads the effective token. "
        L"!dml_proc or !process 0 lists all processes. Omitted memory-display and u addresses continue their own previous display. "
        L"Without an address, ln and uf use the current instruction, independently of the u cursor. "
        L"procctx overrides translation DTB only; use Processes / Attach address space to select an EPROCESS.",
        L"Code: ln and x retain virtual addresses for Row details navigation. Unreadable or invalid instructions are not decoded rows; "
        L"failed u commands preserve the previous continuation cursor. uf retains native function text as Partial because full function coverage "
        L"is unverified; use Capture info / View output to read it.",
        L"Docs: README.md / README.ko.md, docs/UX.md, docs/COMMANDS.md and docs/SUPPORT.md. "
        L"Missing symbols or pages remain explicit limitations; Experimental does not mean complete coverage."
    };
    return lines;
}

std::vector<size_t> SymbolOperands(const std::wstring &command)
{
    std::vector<size_t> result;
    const auto *spec = kncmd::FindCommand(command);
    if (spec == nullptr)
    {
        if (_wcsicmp(command.c_str(), L"bp") == 0 || _wcsicmp(command.c_str(), L"bu") == 0 || _wcsicmp(command.c_str(), L"bm") == 0)
        {
            result.push_back(0);
        }
    }
    else
    {
        const std::wstring name(spec->Name);
        const bool physical = name == L"!db" || name == L"!dw" || name == L"!dd" || name == L"!dq" ||
                              name == L"!eb" || name == L"!ew" || name == L"!ed" || name == L"!eq";
        if (!physical)
        {
            const auto grammar = knutil::Tokenize(spec->Grammar);
            for (size_t i = 1; i < grammar.size(); ++i)
            {
                auto field = grammar[i];
                if (field.starts_with(L"[/"))
                {
                    break;
                }
                while (!field.empty() && (field.front() == L'[' || field.front() == L'<'))
                {
                    field.erase(field.begin());
                }
                while (!field.empty() && (field.back() == L']' || field.back() == L'>'))
                {
                    field.pop_back();
                }
                if (field == L"address" || field == L"hex-address" || field == L"virtual-address" || field == L"device-address" ||
                    field == L"module|address" || field == L"name|address" || field == L"symbol-pattern" || field == L"expression")
                {
                    result.push_back(i - 1);
                }
            }
        }
    }
    return result;
}

bool SymbolCompletionWord(const std::wstring &word)
{
    if (word.empty() || word.size() > 512 || (word.front() >= L'0' && word.front() <= L'9'))
    {
        return false;
    }
    unsigned separators = 0;
    for (const auto ch : word)
    {
        if (ch == L'!')
        {
            ++separators;
        }
        else if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') || (ch >= L'0' && ch <= L'9') ||
                   ch == L'_' || ch == L'$' || ch == L'?' || ch == L'@' || ch == L'.' || ch == L':'))
        {
            return false;
        }
    }
    return separators <= 1 && word.front() != L'!' && word.front() != L'@' && word.front() != L'?';
}

std::optional<SymbolCompletionQuery> SymbolQueryFor(const std::wstring &prefix, const std::wstring &suffix)
{
    std::optional<SymbolCompletionQuery> result;
    do
    {
        if (prefix.empty() || prefix.size() > 4096 || suffix.size() > 32768 - prefix.size() || iswspace(prefix.back()) ||
            (!suffix.empty() && !iswspace(suffix.front())) ||
            prefix.find_first_of(L"\";{}\r\n") != std::wstring::npos || prefix.find(L'\0') != std::wstring::npos)
        {
            break;
        }
        std::vector<std::wstring> draftTokens;
        std::vector<bool> quotedTokens;
        if (!knutil::Tokenize(prefix + suffix, &draftTokens, nullptr, &quotedTokens))
        {
            break;
        }
        bool physical = false;
        for (size_t i = 1; i < draftTokens.size(); ++i)
        {
            physical = physical || (!quotedTokens[i] && _wcsicmp(draftTokens[i].c_str(), L"/phys") == 0);
        }
        if (physical)
        {
            break;
        }
        const auto tokens = knutil::Tokenize(prefix);
        if (tokens.size() < 2 || !SymbolCompletionWord(tokens.back()))
        {
            break;
        }
        const auto *spec = kncmd::FindCommand(tokens[0]);
        size_t operand = 0;
        bool valid = true;
        for (size_t i = 1; i + 1 < tokens.size(); ++i)
        {
            const kncmd::OptionSpec *option = nullptr;
            if (spec != nullptr)
            {
                for (const auto &entry : spec->Options)
                {
                    if (_wcsicmp(entry.Name, tokens[i].c_str()) == 0)
                    {
                        option = &entry;
                        break;
                    }
                }
            }
            if (option != nullptr)
            {
                if (_wcsicmp(option->Name, L"/phys") == 0 || (option->TakesValue && ++i + 1 >= tokens.size()))
                {
                    valid = false;
                    break;
                }
            }
            else
            {
                ++operand;
            }
        }
        const auto operands = SymbolOperands(tokens[0]);
        if (!valid || std::find(operands.begin(), operands.end(), operand) == operands.end() ||
            (spec != nullptr && std::wstring(spec->Name) == L"navigate" && tokens.size() > 2 && tokens[1] == L"pa"))
        {
            break;
        }
        const auto start = prefix.find_last_of(L" \t");
        if (start != std::wstring::npos)
        {
            result = SymbolCompletionQuery{prefix.substr(0, start + 1), tokens.back()};
        }
    } while (false);
    return result;
}

std::vector<std::wstring> CompletionsFor(const std::wstring &prefix)
{
    std::vector<std::wstring> matches;
    if (prefix.empty() || prefix.size() > 32768 || prefix.find_first_of(L"\";{}\r\n") != std::wstring::npos ||
        prefix.find(L'\0') != std::wstring::npos)
    {
        return matches;
    }
    const auto start = prefix.find_last_of(L" \t");
    const auto head = start == std::wstring::npos ? L"" : prefix.substr(0, start + 1);
    const auto word = prefix.substr(head.size());
    std::vector<std::wstring> tokens;
    if (!knutil::Tokenize(head, &tokens))
    {
        return matches;
    }
    const auto add = [&](const std::wstring &candidate)
    {
        if (candidate.size() >= word.size() && _wcsnicmp(candidate.c_str(), word.c_str(), word.size()) == 0)
        {
            matches.push_back(head + candidate);
        }
    };
    if (tokens.empty())
    {
        if (!word.empty())
        {
            for (const auto &info : All())
            {
                add(info.Name);
            }
        }
    }
    else if (const auto *spec = kncmd::FindCommand(tokens[0]))
    {
        const std::wstring name(spec->Name);
        size_t positionals = 0;
        bool needsValue = false;
        std::vector<std::wstring> usedOptions;
        for (size_t i = 1; i < tokens.size(); ++i)
        {
            if (needsValue)
            {
                needsValue = false;
                continue;
            }
            const auto option = std::find_if(spec->Options.begin(), spec->Options.end(), [&](const auto &entry)
            {
                return _wcsicmp(entry.Name, tokens[i].c_str()) == 0;
            });
            if (option != spec->Options.end())
            {
                usedOptions.push_back(option->Name);
                needsValue = option->TakesValue;
            }
            else
            {
                ++positionals;
            }
        }
        if (!needsValue)
        {
            if (positionals == 0)
            {
                if (name == L"help")
                {
                    add(L"ui");
                    for (const auto &info : All())
                    {
                        add(info.Name);
                    }
                }
                if (name == L"!dml_proc" || name == L"!process" || name == L"!threads" || name == L"!vad" || name == L"!token" ||
                    name == L"procctx")
                {
                    add(L"pid:");
                    add(L"eprocess:");
                    if (name != L"procctx")
                    {
                        add(L"image:");
                    }
                }
                if (name == L"!threads")
                {
                    add(L"ethread:");
                }
                if (name == L"!process")
                {
                    add(L"0");
                }
                if (name == L"procctx")
                {
                    add(L"show");
                    add(L"reset");
                }
            }
            for (const auto &option : spec->Options)
            {
                if (std::find(usedOptions.begin(), usedOptions.end(), option.Name) == usedOptions.end())
                {
                    add(option.Name);
                }
            }
        }
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    return matches;
}
} // namespace kncat
