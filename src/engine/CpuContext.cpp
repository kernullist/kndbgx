#include "CpuContext.h"
#include "ContextGuard.h"
#include "SymbolQuery.h"

#include <dbgeng.h>

#include "../util/Text.h"
#include "../core/Input.h"
#include "../core/CpuMap.h"
#include <set>
#include <vector>

namespace knengine
{
ULONG CountProcessors(DbgSession &session)
{
    ULONG count = 0;

    do
    {
        SessionStatus status = {};
        session.QueryStatus(&status);

        if (!status.KernelMode)
        {
            break;
        }

        IDebugControl4 *control = session.Control();

        if (control != nullptr && SUCCEEDED(control->GetNumberProcessors(&count)) && count > 0)
        {
            break;
        }

        count = 0;
    } while (false);

    return count;
}

bool ForEachProcessor(DbgSession &session, ProcessorCallback callback, void *context)
{
    SymbolQueryScope query;
    bool ok = false;

    do
    {
        knengine::ScopedIoLock ioLock(session);
        IDebugSystemObjects4 *system = session.SystemObjects();

        if (system == nullptr || callback == nullptr)
        {
            break;
        }

        ContextGuard restore(session);
        if (!restore.Valid())
        {
            break;
        }
        // Switching to a processor's thread can make the engine resolve that
        // thread's context, lazily loading deferred PDBs for modules it sits
        // in. Symbol generation only tracks additive metadata; it cannot
        // invalidate the captured system/process/thread identity this guard
        // restores, so the read-only per-processor walk tolerates it (target,
        // stop and context generations still pin the restore).
        restore.AllowSymbolChanges();

        ULONG available = 0;
        const ULONG count = CountProcessors(session);
        ok = SUCCEEDED(system->GetNumberThreads(&available)) && available > 0 && available <= 4096;
        std::vector<ULONG> threadIds(ok ? available : 0);
        if (ok)
        {
            ok = system->GetThreadIdsByIndex(0, available, threadIds.data(), nullptr) == S_OK;
        }
        const std::vector<uint32_t> availableThreads(threadIds.begin(), threadIds.end());
        const auto mapped = kncore::MapProcessors(count, availableThreads,
                                                  [&](uint32_t processor, uint32_t *thread)
                                                  {
                                                      ULONG id = 0;
                                                      const bool found =
                                                          !session.Cancelled() && system->GetThreadIdByProcessor(processor, &id) == S_OK;
                                                      *thread = id;
                                                      return found;
                                                  });
        for (const auto &processor : mapped.Entries)
        {
            if (!ok || session.Cancelled())
            {
                ok = false;
                break;
            }
            if (FAILED(system->SetCurrentThreadId(processor.EngineThread)))
            {
                ok = false;
                break;
            }

            if (!callback(processor.Processor, context))
            {
                ok = false;
            }
        }

        ok = restore.Restore() && ok && mapped.Complete;
    } while (false);

    return ok;
}

bool ReadMsr(DbgSession &session, const std::wstring &msrSpec, ULONG64 *value)
{
    bool ok = false;

    do
    {
        uint64_t index = 0;
        if (!kncore::ParseUnsigned(msrSpec, 16, &index) || index > UINT32_MAX)
        {
            break;
        }
        ok = session.ReadMsrValue(static_cast<ULONG>(index), value);
    } while (false);

    return ok;
}
} // namespace knengine
