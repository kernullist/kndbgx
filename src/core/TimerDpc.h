#pragma once

#include "CollectorRead.h"
#include <bit>

namespace kncore
{
struct TimerDpcKeys
{
    uint64_t Never = 0;
    uint64_t Always = 0;
    bool operator==(const TimerDpcKeys &) const = default;
};

inline uint64_t DecodeTimerDpc(uint64_t raw, uint64_t timer, const TimerDpcKeys &keys)
{
    const uint64_t rotated = std::rotl(raw ^ keys.Never, static_cast<int>(keys.Never & 63)) ^ timer;
    uint64_t swapped = 0;
    for (unsigned i = 0; i < 8; ++i)
    {
        swapped = (swapped << 8) | ((rotated >> (i * 8)) & 0xff);
    }
    return swapped ^ keys.Always;
}

inline std::optional<uint64_t> ValidatedTimerDpc(TargetReader &reader, const TargetArchitecture &architecture, uint64_t timer,
                                                 std::optional<uint64_t> raw, const std::optional<TimerDpcKeys> &keys,
                                                 const std::optional<FieldInfo> &type,
                                                 const std::function<void(uint64_t)> &prepare = {})
{
    if (!raw || !keys || !architecture.KernelPointer(timer) || !type || type->Size != 1 || type->BitOffset || type->BitWidth)
    {
        return {};
    }
    // NULL is encoded as well. Never interpret the raw value as a pointer.
    const uint64_t dpc = DecodeTimerDpc(*raw, timer, *keys);
    if (dpc == 0)
    {
        return 0;
    }
    if (!architecture.KernelPointer(dpc) || dpc % 8 != 0)
    {
        return {};
    }
    if (prepare)
    {
        prepare(dpc);
    }
    const auto observed = ReadField(reader, dpc, type);
    return observed && (*observed == 0x13 || *observed == 0x1a) ? std::optional<uint64_t>(dpc) : std::nullopt;
}
} // namespace kncore
