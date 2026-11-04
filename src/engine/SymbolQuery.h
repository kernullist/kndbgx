#pragma once

#include "../core/OperationProgress.h"

namespace knengine
{
inline thread_local unsigned PassiveSymbolQueryDepth = 0;

// Read APIs may populate deferred symbols. Explicit reloads never enter this scope.
class SymbolQueryScope
{
  public:
    SymbolQueryScope()
    {
        ++PassiveSymbolQueryDepth;
    }
    ~SymbolQueryScope()
    {
        --PassiveSymbolQueryDepth;
    }
    SymbolQueryScope(const SymbolQueryScope &) = delete;
    SymbolQueryScope &operator=(const SymbolQueryScope &) = delete;

  private:
    kncore::ObservedStage progress_{kncore::OperationStage::SymbolQuery};
};
} // namespace knengine
