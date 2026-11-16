#pragma once

#include "KernelSymbolProfile.h"
#include "Win32kDispatch.h"

namespace kncore
{
inline bool Win32kBasePolicyIdentity(const ModuleIdentity &identity)
{
    return identity.Matched && identity.Machine == 0x8664 && identity.PdbAge == 1 && identity.Timestamp == 0xd072766b &&
        identity.ImageSize == 0x33f000 && identity.Base != 0 && ValidRange(identity.Base, identity.ImageSize) &&
        _wcsicmp(identity.PdbGuid.c_str(), L"{49EC72D0-0D46-EF4D-3193-C271992D24AA}") == 0;
}

struct PolicyCodeBinding
{
    uint32_t Offset;
    bool Win32k;
    uint32_t Rva;
};

struct PolicyCodeProfile
{
    const wchar_t *Module;
    const wchar_t *Symbol;
    uint32_t Rva;
    uint32_t Size;
    const wchar_t *Hash;
    std::vector<PolicyCodeBinding> Calls;
};

inline const std::array<PolicyCodeProfile, 3> &Win32kPolicyCode()
{
    // Whole function hashes normalize only independently bound cross-image calls.
    static const std::array<PolicyCodeProfile, 3> profiles{{
        {L"win32kbase", L"IsWin32KSyscallFiltered", 0x105450, 0x6c,
         L"42c0194ffdb3417c7cca42345d2af50b47b4944a103d6281c884cd709f399851",
         {{0x14, false, 0x4890b0}, {0x2a, true, 0x5530}}},
        {L"win32kbase", L"NtUserWin32kSysCallFilterStub", 0x1760b0, 0x1c9,
         L"2485997f03e9b6c4a345be819d3ed314fed4561e2edf2d5c12c3616d2133a114",
         {{0x38, false, 0x4890b0}, {0x82, false, 0x45d7c0}, {0x91, false, 0x487360},
          {0xb4, false, 0x3cbc70}, {0xc0, false, 0x4c7c10}, {0xd4, true, 0x5530}}},
        {L"win32k", L"W32GetUserSessionState", 0x5530, 0x93,
         L"28a9194d72ec6d2090d6dc1eb8a10348252f384ff728222ea7e3ca18089ae640",
         {{0xe, false, 0x45d7c0}, {0x1d, false, 0x2cb700}, {0x69, false, 0x45d7c0}, {0x8e, false, 0x5438f0}}}}};
    return profiles;
}

inline const std::array<CallbackCodeWindow, 4> &Win32kPolicyNtCode()
{
    static const std::array<CallbackCodeWindow, 4> windows{{
        {L"PsGetWin32KFilterSet", 0x4890b0, 0, L"65488b042588010000488b80b80000008b80e8060000c3"},
        {L"PsIsWin32KFilterEnabled", 0x4a1be0, 0, L"65488b042588010000488b88b80000008b8150070000c1e80e2401c3"},
        {L"PsIsWin32KFilterAuditEnabled", 0x4c7c10, 0, L"65488b042588010000488b88b80000008b8150070000c1e80f2401c3"},
        {L"PsGetProcessSessionIdEx", 0x2cb700, 0, L"488b81e80200004885c07507b8ffffffffc3cc8b89fc0500000fbae10c72ed8b4008c3"}}};
    return windows;
}

template <typename Hash>
bool VerifyPolicyFunction(std::vector<unsigned char> bytes, const PolicyCodeProfile &profile, uint64_t address,
                          uint64_t nt, uint64_t win32k, Hash hash)
{
    if (bytes.size() != profile.Size)
    {
        return false;
    }
    for (const auto &binding : profile.Calls)
    {
        const auto offset = binding.Offset;
        const auto target = (binding.Win32k ? win32k : nt) + binding.Rva;
        if (offset == 0 || offset > bytes.size() || bytes.size() - offset < 4 || bytes[offset - 1] != 0xe8 ||
            DispatchRelative(address + offset + 4, DispatchU32(bytes, offset)) != target)
        {
            return false;
        }
        std::fill_n(bytes.begin() + offset, 4, static_cast<unsigned char>(0));
    }
    return hash(bytes) == profile.Hash;
}

template <typename Resolve, typename Hash>
bool VerifyWin32kPolicyProfile(TargetReader &reader, const ModuleIdentity &nt, const ModuleIdentity &win32k,
                              const ModuleIdentity &base, Resolve resolve, Hash hash)
{
    if (!CallbackProfile28000Identity(nt) || !Win32kServiceProfileIdentity(win32k) || !Win32kBasePolicyIdentity(base))
    {
        return false;
    }
    for (const auto &window : Win32kPolicyNtCode())
    {
        if (resolve(L"nt", window.Symbol) != nt.Base + window.SymbolRva)
        {
            return false;
        }
        const auto length = std::wcslen(window.Bytes) / 2;
        const auto bytes = reader.Read(AddressSpace::Virtual, nt.Base + window.SymbolRva, length);
        if (!ExactBytes(bytes, length))
        {
            return false;
        }
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (size_t i = 0; i < length; ++i)
        {
            if (window.Bytes[i * 2] != hex[bytes.Bytes[i] >> 4] || window.Bytes[i * 2 + 1] != hex[bytes.Bytes[i] & 15])
            {
                return false;
            }
        }
    }
    for (const auto &profile : Win32kPolicyCode())
    {
        const auto address = (std::wstring_view(profile.Module) == L"win32k" ? win32k.Base : base.Base) + profile.Rva;
        if (resolve(profile.Module, profile.Symbol) != address)
        {
            return false;
        }
        const auto bytes = reader.Read(AddressSpace::Virtual, address, profile.Size);
        if (!ExactBytes(bytes, profile.Size) || !VerifyPolicyFunction(bytes.Bytes, profile, address, nt.Base, win32k.Base, hash))
        {
            return false;
        }
    }
    return true;
}
} // namespace kncore
