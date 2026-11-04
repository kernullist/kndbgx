#include "DataModel.h"
#include <dbgeng.h>
#include <DbgModel.h>
#include <wrl/client.h>

namespace knengine
{
using Microsoft::WRL::ComPtr;
namespace
{
HRESULT Convert(IDataModelManager *manager, const knjson::Value &value, IModelObject **output, size_t depth, size_t &nodes)
{
    if (depth > 32 || ++nodes > 32768)
    {
        return E_BOUNDS;
    }
    ComPtr<IModelObject> object;
    HRESULT hr = S_OK;
    if (value.IsObject() || value.IsArray() || value.IsNull())
    {
        hr = manager->CreateSyntheticObject(nullptr, &object);
        if (SUCCEEDED(hr) && value.IsNull())
        {
            ComPtr<IModelObject> unknown;
            hr = Convert(manager, knjson::Value(true), &unknown, depth + 1, nodes);
            if (SUCCEEDED(hr))
            {
                hr = object->SetKey(L"Unknown", unknown.Get(), nullptr);
            }
        }
        const auto set = [&](const std::wstring &key, const knjson::Value &child)
        {
            ComPtr<IModelObject> converted;
            HRESULT status = Convert(manager, child, &converted, depth + 1, nodes);
            if (SUCCEEDED(status))
            {
                status = object->SetKey(key.c_str(), converted.Get(), nullptr);
            }
            return status;
        };
        if (SUCCEEDED(hr) && value.IsObject())
        {
            for (const auto &[key, child] : value.Fields())
            {
                hr = set(key, child);
                if (FAILED(hr))
                {
                    break;
                }
            }
        }
        if (SUCCEEDED(hr) && value.IsArray())
        {
            hr = set(L"Count", knjson::Value(std::to_wstring(value.Items().size())));
            for (size_t i = 0; SUCCEEDED(hr) && i < value.Items().size(); ++i)
            {
                hr = set(L"r" + std::to_wstring(i), value.Items()[i]);
            }
        }
    }
    else
    {
        VARIANT data;
        VariantInit(&data);
        if (value.IsBool())
        {
            data.vt = VT_BOOL;
            data.boolVal = value.AsBool(false) ? VARIANT_TRUE : VARIANT_FALSE;
        }
        else if (value.IsNumber())
        {
            data.vt = VT_R8;
            data.dblVal = value.AsDouble(0);
        }
        else
        {
            const auto text = value.AsString(L"");
            data.vt = VT_BSTR;
            data.bstrVal = SysAllocStringLen(text.data(), static_cast<UINT>(text.size()));
            if (data.bstrVal == nullptr)
            {
                return E_OUTOFMEMORY;
            }
        }
        hr = manager->CreateIntrinsicObject(ObjectIntrinsic, &data, &object);
        VariantClear(&data);
    }
    if (SUCCEEDED(hr))
    {
        *output = object.Detach();
    }
    return hr;
}
} // namespace

bool HasDataModel(IDebugClient5 *client)
{
    ComPtr<IHostDataModelAccess> access;
    ComPtr<IDataModelManager> manager;
    ComPtr<IDebugHost> host;
    return client != nullptr && SUCCEEDED(client->QueryInterface(IID_PPV_ARGS(&access))) &&
           SUCCEEDED(access->GetDataModel(&manager, &host));
}

knjson::Value ReadBreakpointConditions(IDebugClient5 *client)
{
    auto conditions = knjson::Value::MakeObject();
    do
    {
        ComPtr<IHostDataModelAccess> access;
        ComPtr<IDataModelManager> manager;
        ComPtr<IDebugHost> host;
        ComPtr<IModelObject> collection;
        if (client == nullptr || FAILED(client->QueryInterface(IID_PPV_ARGS(&access))) ||
            FAILED(access->GetDataModel(&manager, &host)) || FAILED(manager->GetRootNamespace(&collection)))
        {
            break;
        }
        // Read the host's condition strings. Never evaluate a breakpoint's expression or command.
        for (const auto *key : {L"Debugger", L"State", L"DebuggerVariables", L"curprocess", L"Debug", L"Breakpoints"})
        {
            ComPtr<IModelObject> next;
            if (FAILED(collection->GetKeyValue(key, &next, nullptr)) || next == nullptr)
            {
                collection.Reset();
                break;
            }
            collection = next;
        }
        ComPtr<IIterableConcept> iterable;
        ComPtr<IModelIterator> iterator;
        if (collection == nullptr || FAILED(collection->GetConcept(__uuidof(IIterableConcept), &iterable, nullptr)) ||
            FAILED(iterable->GetIterator(collection.Get(), &iterator)))
        {
            break;
        }
        for (size_t index = 0; index < 4096; ++index)
        {
            ComPtr<IModelObject> entry, id, condition;
            if (iterator->GetNext(&entry, 0, nullptr, nullptr) != S_OK || entry == nullptr)
            {
                break;
            }
            VARIANT idValue, conditionValue;
            VariantInit(&idValue);
            VariantInit(&conditionValue);
            if (SUCCEEDED(entry->GetKeyValue(L"Id", &id, nullptr)) && id != nullptr &&
                SUCCEEDED(id->GetIntrinsicValueAs(VT_UI4, &idValue)))
            {
                const HRESULT conditionStatus = entry->GetKeyValue(L"Condition", &condition, nullptr);
                ModelObjectKind conditionKind = ObjectError;
                const bool conditionRead = SUCCEEDED(conditionStatus) && condition != nullptr &&
                                           SUCCEEDED(condition->GetKind(&conditionKind));
                if (conditionRead && conditionKind == ObjectNoValue)
                {
                    // A known NoValue is distinct from a missing or failed condition getter.
                    conditions.Set(std::to_wstring(idValue.ulVal), knjson::Value(L""));
                }
                else if (conditionRead && conditionKind == ObjectIntrinsic &&
                         SUCCEEDED(condition->GetIntrinsicValueAs(VT_BSTR, &conditionValue)) &&
                         SysStringLen(conditionValue.bstrVal) <= 4096)
                {
                    conditions.Set(std::to_wstring(idValue.ulVal), knjson::Value(conditionValue.bstrVal == nullptr ? L"" :
                        std::wstring(conditionValue.bstrVal, SysStringLen(conditionValue.bstrVal))));
                }
            }
            VariantClear(&conditionValue);
            VariantClear(&idValue);
        }
    } while (false);
    return conditions;
}

HRESULT PublishDataModel(IDebugClient5 *client, const knjson::Value &projection)
{
    HRESULT hr = E_NOINTERFACE;
    do
    {
        ComPtr<IHostDataModelAccess> access;
        ComPtr<IDataModelManager> manager;
        ComPtr<IDebugHost> host;
        if (client == nullptr || FAILED(hr = client->QueryInterface(IID_PPV_ARGS(&access))) ||
            FAILED(hr = access->GetDataModel(&manager, &host)))
        {
            break;
        }
        ComPtr<IModelObject> root, debugger, models, existing, projected;
        if (FAILED(hr = manager->GetRootNamespace(&root)) || FAILED(hr = root->GetKeyValue(L"Debugger", &debugger, nullptr)))
        {
            break;
        }
        hr = debugger->GetKeyValue(L"Models", &models, nullptr);
        const bool createModels = hr == E_BOUNDS;
        if (FAILED(hr) && !createModels)
        {
            break;
        }
        if (createModels && FAILED(hr = manager->CreateSyntheticObject(nullptr, &models)))
        {
            break;
        }
        hr = models->GetKeyValue(L"KNDbgX", &existing, nullptr);
        if (SUCCEEDED(hr))
        {
            ComPtr<IModelObject> schema;
            VARIANT identity;
            VariantInit(&identity);
            const bool ours = SUCCEEDED(existing->GetKeyValue(L"Schema", &schema, nullptr)) &&
                              SUCCEEDED(schema->GetIntrinsicValueAs(VT_BSTR, &identity)) && identity.bstrVal != nullptr &&
                              wcscmp(identity.bstrVal, L"kndbgx.model.v1") == 0;
            VariantClear(&identity);
            if (!ours)
            {
                hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
                break;
            }
        }
        else if (hr != E_BOUNDS)
        {
            break;
        }
        size_t nodes = 0;
        if (FAILED(hr = Convert(manager.Get(), projection, &projected, 0, nodes)))
        {
            break;
        }
        // Entire graph is host-owned data. No accessor or concept points into this DLL.
        hr = models->SetKey(L"KNDbgX", projected.Get(), nullptr);
        if (SUCCEEDED(hr) && createModels)
        {
            hr = debugger->SetKey(L"Models", models.Get(), nullptr);
        }
    } while (false);
    return hr;
}
} // namespace knengine
