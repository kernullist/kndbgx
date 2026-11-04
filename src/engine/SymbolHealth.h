#pragma once

#include "EngineCore.h"
#include "../core/SymbolHealth.h"

namespace knengine
{
// These functions require the existing owner-thread execution lease.
knjson::Value ReadSymbolModules(DbgSession &session, const kncore::SessionStamp &expected, uint64_t cursor);
knjson::Value InspectSymbolHealth(DbgSession &session, const kncore::SessionStamp &expected,
                                 const kncore::SymbolModuleKey &key, const std::wstring &type, const std::wstring &field);
} // namespace knengine
