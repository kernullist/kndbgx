#pragma once

#include "EngineCore.h"

namespace knengine
{
inline thread_local unsigned SessionWalkDepth = 0;

class SessionWalk
{
  public:
    SessionWalk()
    {
        Epochs().EnterWalk();
        ++SessionWalkDepth;
    }
    ~SessionWalk()
    {
        --SessionWalkDepth;
        Epochs().LeaveWalk();
    }
    SessionWalk(const SessionWalk &) = delete;
    SessionWalk &operator=(const SessionWalk &) = delete;
};

inline void ReleaseAbandonedSessionWalks(unsigned savedDepth)
{
    // SEH may skip destructors. Release only this thread's abandoned scopes;
    // assigning the shared count would erase walks owned by other threads.
    while (SessionWalkDepth > savedDepth)
    {
        --SessionWalkDepth;
        Epochs().LeaveWalk();
    }
}
} // namespace knengine
