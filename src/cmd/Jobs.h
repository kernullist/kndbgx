#pragma once

#include "CommandSpec.h"

namespace kncmd
{
kncore::Result SubmitJob(const std::wstring &command, bool deferStart = false, const kncore::SessionStamp *expected = nullptr);
bool ActivateJob(const std::wstring &id);
void JobCommand(Ctx &context);
void InitializeJobs();
void StopJobs();
bool DetachedCommand(const CommandSpec *spec);
} // namespace kncmd
