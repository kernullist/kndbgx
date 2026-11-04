#include "ModuleList.h"

#include <dbgeng.h>

namespace knengine
{
namespace
{
// The Windows SDK dbgeng.h does not export DEBUG_MOD_NAME_* values;
// 1 == short module name, 0 == image name.
const ULONG kModuleNameShort = 1;
const ULONG kModuleNameImage = 0;
} // namespace

bool EnumerateKernelModules(DbgSession &session, std::vector<KernelModuleInfo> *modules, kncore::Result *report)
{
    bool ok = false;
    kncore::Result result;
    result.Stamp = session.RefreshStamp();
    result.Source = L"DbgEngModuleInventory";
    result.Consistency = L"BestEffort";

    do
    {
        if (modules == nullptr || !session.IsReady())
        {
            break;
        }

        IDebugSymbols3 *symbols = session.Symbols();

        if (symbols == nullptr)
        {
            break;
        }

        modules->clear();

        ULONG loadedCount = 0;
        ULONG unloadedCount = 0;
        HRESULT hr = symbols->GetNumberModules(&loadedCount, &unloadedCount);

        if (FAILED(hr) || loadedCount == 0)
        {
            ok = SUCCEEDED(hr);
            result.State = ok ? kncore::Status::Success : kncore::Status::EngineError;
            result.Collected.Complete = ok;
            result.Collected.StopReason = ok ? L"EmptyModuleInventory" : L"ModuleCountUnavailable";
            break;
        }
        result.Collected.Expected = loadedCount;
        if (loadedCount > 65536)
        {
            result.State = kncore::Status::Partial;
            result.Collected.StopReason = L"ModuleCountBudget";
            break;
        }

        std::vector<DEBUG_MODULE_PARAMETERS> parameters(loadedCount);
        hr = symbols->GetModuleParameters(loadedCount, nullptr, 0, parameters.data());

        if (hr != S_OK)
        {
            result.State = kncore::Status::EngineError;
            result.Collected.StopReason = L"ModuleParametersUnavailable";
            break;
        }

        modules->reserve(loadedCount);

        for (ULONG i = 0; i < loadedCount; ++i)
        {
            if (session.Cancelled())
            {
                result.State = kncore::Status::Cancelled;
                result.Collected.StopReason = L"Cancelled";
                break;
            }
            ++result.Collected.Visited;
            if (parameters[i].Base == DEBUG_INVALID_OFFSET || parameters[i].Size == 0 ||
                !kncore::ValidRange(parameters[i].Base, parameters[i].Size))
            {
                ++result.Collected.Unknown;
                continue;
            }
            ++result.Collected.Read;
            KernelModuleInfo info;
            info.Base = parameters[i].Base;
            info.Size = parameters[i].Size;
            info.Timestamp = parameters[i].TimeDateStamp;

            wchar_t nameBuffer[512] = L"";

            const bool named = symbols->GetModuleNameStringWide(kModuleNameShort, i, 0, nameBuffer, 512, nullptr) == S_OK;
            if (named)
            {
                info.ModuleName = nameBuffer;
            }

            wchar_t imageBuffer[1024] = L"";

            const bool imageNamed = symbols->GetModuleNameStringWide(kModuleNameImage, i, 0, imageBuffer, 1024, nullptr) == S_OK;
            if (imageNamed)
            {
                info.ImageName = imageBuffer;
            }
            if (!named || !imageNamed)
            {
                ++result.Collected.Unknown;
            }

            modules->push_back(info);
            ++result.Collected.Decoded;
        }

        ok = result.Collected.Decoded == loadedCount && result.Collected.Unknown == 0;
        result.Collected.Complete = ok;
        if (result.State != kncore::Status::Cancelled)
        {
            result.State = ok ? kncore::Status::Success : kncore::Status::Partial;
            result.Collected.StopReason = ok ? L"EndOfModuleInventory" : L"ModuleRangesOrNamesUnavailable";
        }
    } while (false);

    if (!ok && result.State == kncore::Status::Success)
    {
        result.State = kncore::Status::Unavailable;
    }
    if (session.RefreshStamp() != result.Stamp && ok)
    {
        ok = false;
        result.State = kncore::Status::StaleContext;
        result.Collected.Complete = false;
    }
    if (report != nullptr)
    {
        *report = result;
    }

    return ok;
}

kncore::OwnershipIndex CollectOwnershipIndex(DbgSession &session, kncore::Result *report)
{
    std::vector<KernelModuleInfo> modules;
    kncore::Result result;
    EnumerateKernelModules(session, &modules, &result);
    std::vector<kncore::ImageRange> ranges;
    for (const auto &module : modules)
    {
        ranges.push_back({module.Base, module.Size, module.ModuleName,
                          module.ImageName + L":" + std::to_wstring(module.Timestamp) + L":" + std::to_wstring(module.Size)});
    }
    if (report != nullptr)
    {
        *report = result;
    }
    return kncore::OwnershipIndex(std::move(ranges), result.Collected.Complete, result.Stamp);
}

const KernelModuleInfo *FindModuleForAddress(const std::vector<KernelModuleInfo> &modules, ULONG64 address)
{
    const KernelModuleInfo *owner = nullptr;
    for (const KernelModuleInfo &info : modules)
    {
        if (info.Size == 0 || !kncore::ValidRange(info.Base, info.Size))
        {
            continue;
        }

        if (address >= info.Base && address - info.Base < info.Size)
        {
            if (owner != nullptr)
            {
                return nullptr;
            }
            owner = &info;
        }
    }

    return owner;
}

bool IsKernelCanonical(ULONG64 address)
{
    return address >= 0xFFFF800000000000ULL;
}
} // namespace knengine
