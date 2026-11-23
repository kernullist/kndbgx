#pragma once

// Shared acquisition of the target's own big-pool table.
//
// Defined in PoolCmds.cpp so the verified layout, symbol and storage checks
// exist exactly once; !payload, !pool and !mapper all read the same
// snapshot through it.

#include "CollectorSupport.h"
#include "../core/Pool.h"

namespace kncmd
{
// Reads nt!PoolBigPageTable into `entries`. Returns false after reporting the
// failure through ctx when the table, layout or storage contract cannot be
// verified. On success the caller owns `budget` state, including any stop the
// acquisition itself recorded.
bool CollectTargetBigPool(Ctx &ctx, kncore::WalkBudget &budget, const kncore::TargetArchitecture &architecture,
                          std::vector<kncore::BigPoolEntry> &entries);
} // namespace kncmd
