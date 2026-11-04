#pragma once

#include "../core/Result.h"
#include <windows.h>
#include <algorithm>

namespace knutil
{
struct SystemInformation
{
    kncore::Result Report;
    std::vector<unsigned char> Bytes;
};

inline SystemInformation QuerySystemInformation(ULONG informationClass, const std::function<bool()> &cancelled)
{
    using QueryFn = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);
    SystemInformation result;
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto query = module != nullptr ? reinterpret_cast<QueryFn>(GetProcAddress(module, "NtQuerySystemInformation")) : nullptr;
    result.Report.State = kncore::Status::Unavailable;
    result.Report.Source = L"Host:NtQuerySystemInformation";
    if (query == nullptr)
    {
        return result;
    }
    size_t size = 65536;
    for (unsigned attempt = 0; attempt < 12 && size <= 128 * 1024 * 1024; ++attempt)
    {
        if (cancelled && cancelled())
        {
            result.Report.State = kncore::Status::Cancelled;
            break;
        }
        result.Bytes.resize(size);
        ULONG received = 0;
        const auto status = query(informationClass, result.Bytes.data(), static_cast<ULONG>(size), &received);
        result.Report.Error = {L"NTSTATUS", static_cast<uint32_t>(status), L"NtQuerySystemInformation", L""};
        if (status == 0 && received <= size && received != 0)
        {
            result.Bytes.resize(received);
            result.Report.State = kncore::Status::Success;
            return result;
        }
        if (status != static_cast<LONG>(0xc0000004U) && status != static_cast<LONG>(0xc0000023U))
        {
            result.Report.State = kncore::Status::IOError;
            break;
        }
        size = std::max(size * 2, static_cast<size_t>(received));
    }
    result.Bytes.clear();
    result.Report.Collected.StopReason = L"NativeQueryFailedOrBudgetExceeded";
    return result;
}
} // namespace knutil
