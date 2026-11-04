#pragma once

#include "../core/PlatformPosture.h"
#include <windows.h>
#include <winternl.h>

namespace knutil
{
using CodeIntegrityQuery = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);

template <typename Query> kncore::CodeIntegrityState QueryCodeIntegrityWith(Query query)
{
    SYSTEM_CODEINTEGRITY_INFORMATION information = {};
    static_assert(sizeof(information) == 8);
    information.Length = sizeof(information);
    ULONG returned = 0;
    const auto status = query(103, &information, sizeof(information), &returned);
    return kncore::DecodeCodeIntegrityReply(true, static_cast<uint32_t>(status), returned, information.Length,
                                            information.CodeIntegrityOptions);
}

inline kncore::CodeIntegrityState QueryCodeIntegrity(CodeIntegrityQuery query)
{
    return query != nullptr ? QueryCodeIntegrityWith(query) : kncore::CodeIntegrityState{};
}

inline kncore::CodeIntegrityState QueryCodeIntegrity()
{
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto query =
        module != nullptr ? reinterpret_cast<CodeIntegrityQuery>(GetProcAddress(module, "NtQuerySystemInformation")) : nullptr;
    return QueryCodeIntegrity(query);
}
} // namespace knutil
