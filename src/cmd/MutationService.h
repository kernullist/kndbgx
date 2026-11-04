#pragma once

#include "CommandSpec.h"
#include "../core/Mutation.h"

namespace kncmd
{
struct PreparedMutation
{
    kncore::Result Result;
    kncore::MutationPlan Plan;
};
kncore::MutationPlans &PlanStore();
PreparedMutation PrepareMutation(knengine::DbgSession &session, const std::wstring &line);
kncore::Result ExecuteApproved(knengine::DbgSession &session, const std::wstring &id, const std::wstring &token);
} // namespace kncmd
