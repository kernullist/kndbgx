#pragma once

#include <cstdint>
#include <vector>
#include <set>

namespace kncore
{
struct ProcessorIdentity
{
    uint32_t Processor = 0;
    uint32_t EngineThread = 0;
};

struct ProcessorMap
{
    bool Complete = false;
    std::vector<ProcessorIdentity> Entries;
};

template <typename Lookup> ProcessorMap MapProcessors(uint32_t expected, const std::vector<uint32_t> &availableThreads, Lookup lookup)
{
    ProcessorMap result;
    if (expected == 0 || expected > 4096 || availableThreads.size() > 4096)
    {
        return result;
    }
    const std::set<uint32_t> available(availableThreads.begin(), availableThreads.end());
    std::set<uint32_t> mapped;
    for (uint32_t cpu = 0; cpu < expected; ++cpu)
    {
        uint32_t thread = 0;
        if (lookup(cpu, &thread) && available.contains(thread) && mapped.insert(thread).second)
        {
            result.Entries.push_back({cpu, thread});
        }
    }
    result.Complete = result.Entries.size() == expected && mapped.size() == available.size();
    return result;
}
} // namespace kncore
