#pragma once
#include "../core/ModelProjection.h"
#include <windows.h>

struct IDebugClient5;
namespace knengine
{
HRESULT PublishDataModel(IDebugClient5 *client, const knjson::Value &projection);
bool HasDataModel(IDebugClient5 *client);
knjson::Value ReadBreakpointConditions(IDebugClient5 *client);
} // namespace knengine
