#pragma once

// Bridge between the WebView2 front-end and the engine/catalog.
// Engine methods require a session owned by the calling executor thread.

#include "../util/Json.h"

#include <string>
#include <functional>

namespace knengine
{
class DbgSession;
}

namespace knbridge
{
// Versioned, generation-bound request and response objects defined by core/Rpc.h.
knjson::Value HandleRequest(const knjson::Value &request, knengine::DbgSession *ownedSession = nullptr,
                            const std::function<bool()> &cancelled = {}, const std::function<void(uint64_t)> &executionStarted = {});

// Event pushed to the front-end: { event, data }.
std::wstring MakeEvent(const wchar_t *name, const knjson::Value &data);
} // namespace knbridge
