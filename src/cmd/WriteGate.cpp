#include "WriteGate.h"
#include "CommandSpec.h"
#include "MutationService.h"
#include "../core/DebugAction.h"

namespace kncmd
{
void DiscardChangePlans()
{
    PlanStore().Clear();
    kncore::ActionPlans().Clear();
}
bool ClassifyAsWrite(const std::wstring &line)
{
    ParsedCommand request;
    ParseCommand(line, &request);
    return request.Spec != nullptr && HasEffect(request.Spec->Effects, Effect::TargetMutation);
}
bool PreviewWriteTarget(knengine::DbgSession &session, const std::wstring &line, std::wstring *previewText)
{
    const auto prepared = PrepareMutation(session, line);
    if (previewText != nullptr)
    {
        *previewText = prepared.Plan.ToJson().Write();
    }
    return prepared.Result.State == kncore::Status::Success;
}
} // namespace kncmd
