#pragma once

#include "../core/Execution.h"
#include "../core/Epochs.h"
#include "../core/ContextRestore.h"
#include <future>

namespace knself
{
template <typename Check> void RunExecutionRegression(Check check)
{
    {
        unsigned value = 7;
        unsigned writes = 0;
        const auto get = [&](unsigned *current)
        {
            *current = value;
            return true;
        };
        const auto set = [&](unsigned expected)
        {
            ++writes;
            value = expected;
            return true;
        };
        check(kncore::RestoreIfDifferent(7u, get, set) && writes == 0,
              "live.context-restore-unchanged-value-does-not-invoke-stateful-setter");
        check(kncore::RestoreIfDifferent(9u, get, set) && value == 9 && writes == 1,
              "live.context-restore-changed-value-is-restored");
        check(kncore::RestoreIfDifferent(7u, [](unsigned *)
              {
                  return false;
              }, set) && value == 7 && writes == 2,
              "live.context-restore-unreadable-current-value-still-attempts-restore");
        check(!kncore::RestoreIfDifferent(9u, get, [](unsigned)
              {
                  return false;
              }), "live.context-restore-setter-failure-is-preserved");
    }
    kncore::SessionStamp saved{L"context-test", 1, 2, 3, 4};
    size_t restored = 0;
    bool fault = false;
    const std::function<bool()> steps[] = {[&]()
                                           {
                                               ++restored;
                                               return false;
                                           },
                                           [&]()
                                           {
                                               ++restored;
                                               return true;
                                           }};
    check(!kncore::RestoreContext(L"selftest", saved, saved, steps,
                                  [&]()
                                  {
                                      fault = true;
                                  },
                                  []()
                                  {
                                  }) &&
              fault && restored == 2,
          "context.restore-failure-faults-and-retains-all-steps");
    restored = 0;
    fault = false;
    auto changed = saved;
    ++changed.StopEpoch;
    check(!kncore::RestoreContext(L"selftest", saved, changed, steps,
                                  [&]()
                                  {
                                      fault = true;
                                  },
                                  []()
                                  {
                                  }) &&
              fault && restored == 0,
          "context.stale-restore-never-applies-old-context");
    for (bool symbols : {false, true})
    {
        changed = saved;
        if (symbols)
        {
            ++changed.SymbolGeneration;
        }
        else
        {
            ++changed.ContextGeneration;
        }
        restored = 0;
        check(!kncore::RestoreContext(L"selftest", saved, changed, steps,
                                      []()
                                      {
                                      },
                                      []()
                                      {
                                      }) &&
                  restored == 0,
              "third.T13.external-context-or-scope-change-prevents-restore");
    }
    restored = 0;
    unsigned observations = 0;
    check(!kncore::RestoreContext(
              L"selftest", saved, saved, steps,
              []()
              {
              },
              []()
              {
              },
              [&]()
              {
                  return ++observations == 1 ? saved : changed;
              }) &&
              restored == 1,
          "third.T13.external-change-between-restore-groups-stops-further-overwrites");
    restored = 0;
    fault = false;
    changed = saved;
    ++changed.SymbolGeneration;
    const std::function<bool()> greenSteps[] = {[&]()
                                                {
                                                    ++restored;
                                                    return true;
                                                },
                                                [&]()
                                                {
                                                    ++restored;
                                                    return true;
                                                }};
    check(kncore::RestoreContext(L"selftest", saved, changed, greenSteps,
                                 [&]()
                                 {
                                     fault = true;
                                 },
                                 []()
                                 {
                                 },
                                 {}, true) &&
              restored == 2 && !fault,
          "context.additive-symbol-change-tolerated-when-allowed");
    changed = saved;
    ++changed.ContextGeneration;
    restored = 0;
    check(!kncore::RestoreContext(L"selftest", saved, changed, steps,
                                  [&]()
                                  {
                                  },
                                  []()
                                  {
                                  },
                                  {}, true) &&
              restored == 0,
          "context.symbol-tolerance-still-refuses-context-generation-change");
    // Identity steps restore, an auxiliary step (implicit offset/scope)
    // fails: the drift is recorded and the session stays usable.
    {
        bool faulted = false;
        bool drifted = false;
        const std::function<bool()> mixedSteps[6] = {[]()
                                                     {
                                                         return true;
                                                     },
                                                     []()
                                                     {
                                                         return true;
                                                     },
                                                     []()
                                                     {
                                                         return true;
                                                     },
                                                     []()
                                                     {
                                                         return true;
                                                     },
                                                     []()
                                                     {
                                                         return false;
                                                     },
                                                     []()
                                                     {
                                                         return true;
                                                     }};
        check(!kncore::RestoreContext(L"selftest", saved, saved, mixedSteps,
                                      [&]()
                                      {
                                          faulted = true;
                                      },
                                      [&]()
                                      {
                                          drifted = true;
                                      }) &&
                  !faulted && drifted,
              "context.auxiliary-restore-failure-drifts-instead-of-faulting");
        faulted = false;
        const std::function<bool()> identityFail[1] = {[]()
                                                       {
                                                           return false;
                                                       }};
        check(!kncore::RestoreContext(L"selftest", saved, saved, identityFail,
                                      [&]()
                                      {
                                          faulted = true;
                                      },
                                      []()
                                      {
                                      }) &&
                  faulted,
              "context.identity-restore-failure-still-faults");
    }
    kncore::OwnerThread owner;
    auto wrongThread = std::async(std::launch::async,
                                  [&]()
                                  {
                                      bool rejected = false;
                                      try
                                      {
                                          owner.Require();
                                      }
                                      catch (const std::logic_error &)
                                      {
                                          rejected = true;
                                      }
                                      return rejected;
                                  });
    check(wrongThread.get(), "thread.owner.reject-before-engine-call");
    kncore::ExecutionCoordinator coordinator;
    check(!coordinator.Cancel(), "cancel.idle-does-not-break-target");
    std::promise<void> entered;
    std::promise<void> released;
    std::atomic<unsigned> calls{0};
    struct Endpoint
    {
        std::promise<void> *Released;
        std::atomic<unsigned> *Calls;
    } endpoint = {&released, &calls};
    auto blocked = std::async(std::launch::async,
                              [&]()
                              {
                                  kncore::ExecutionLease lease(coordinator);
                                  coordinator.Arm(&endpoint,
                                                  [](void *context)
                                                  {
                                                      auto &state = *static_cast<Endpoint *>(context);
                                                      if (state.Calls->fetch_add(1) == 0)
                                                      {
                                                          state.Released->set_value();
                                                      }
                                                  });
                                  entered.set_value();
                                  const bool unblocked =
                                      released.get_future().wait_for(std::chrono::seconds(3)) == std::future_status::ready;
                                  coordinator.Disarm();
                                  return unblocked && coordinator.Cancelled();
                              });
    entered.get_future().wait();
    const auto start = std::chrono::steady_clock::now();
    check(!coordinator.Begin(), "thread.concurrent-cli-engine-busy");
    check(!coordinator.Cancel(kncore::ExecutionDomain::Ui) && !coordinator.Cancelled(), "cancel.closing-ui-does-not-cancel-cli");
    check(!coordinator.Cancel(kncore::ExecutionDomain::Any, coordinator.Serial() + 1), "cancel.stale-request-id-does-not-cancel-new-work");
    check(coordinator.Cancel(), "cancel.out-of-band-requested");
    check(blocked.get() && std::chrono::steady_clock::now() - start < std::chrono::seconds(2), "cancel.blocked-executor-finishes");
    check(!coordinator.Cancel() && calls.load() == 1, "cancel.released-endpoint-not-called");
    check(coordinator.Begin() && !coordinator.Cancelled(), "cancel.new-request-new-token");
    coordinator.End();

    unsigned interrupted = 0;
    unsigned unrelated = 0;
    const auto interrupt = [](void *context)
    {
        ++*static_cast<unsigned *>(context);
    };
    coordinator.Begin();
    try
    {
        kncore::InterruptEndpoint scopedEndpoint(coordinator, &interrupted, interrupt);
        throw std::runtime_error("injected engine output exception");
    }
    catch (const std::runtime_error &)
    {
    }
    check(coordinator.Cancel() && interrupted == 0, "review.interrupt-endpoint-detaches-on-exception-unwind");
    coordinator.End();
    coordinator.Begin();
    {
        kncore::InterruptEndpoint scopedEndpoint(coordinator, &interrupted, interrupt);
        coordinator.Disarm(&unrelated);
        const bool preserved = coordinator.Cancel() && interrupted == 1;
        coordinator.Disarm(&interrupted);
        check(preserved && coordinator.Cancel() && interrupted == 1, "review.session-release-only-detaches-its-own-interrupt-endpoint");
    }
    coordinator.End();

    kncore::EpochTracker epochs(L"test-session");
    kncore::TargetObservation target;
    target.Present = true;
    target.Stopped = true;
    target.Architecture = 0x8664;
    epochs.Observe(target);
    const auto first = epochs.Stamp();
    epochs.Observe(target);
    check(epochs.Stamp() == first, "epoch.same-observation-stable");
    target.Context.ImplicitProcess = 0x12340000;
    target.Context.ImplicitThread = 0x56780000;
    target.Context.EffectiveArchitecture = 0x8664;
    epochs.Observe(target);
    const auto implicit = epochs.Stamp();
    target.Context.ImplicitProcess = 0x22340000;
    epochs.Observe(target);
    check(epochs.Stamp().ContextGeneration > implicit.ContextGeneration && epochs.Stamp().TargetGeneration == implicit.TargetGeneration,
          "rereview.context-implicit-process-invalidates-with-same-engine-ids");
    const auto implicitThread = epochs.Stamp();
    target.Context.ImplicitThread.reset();
    epochs.Observe(target);
    check(epochs.Stamp() != implicitThread && !epochs.Stamp().Context.Complete(), "rereview.context-unknown-is-not-zero-or-old-context");
    const auto effective = epochs.Stamp();
    target.Context.EffectiveArchitecture = 0x14c;
    epochs.Observe(target);
    check(epochs.Stamp() != effective, "rereview.context-effective-architecture-invalidates");
    const auto scope = epochs.Stamp();
    target.Context.ScopeInstruction = 0x12345678;
    target.Context.ScopeIndex = 1;
    epochs.Observe(target);
    check(epochs.Stamp() != scope, "rereview.context-scope-invalidates");
    const auto internal = epochs.Stamp();
    target.Context.ScopeIndex = 2;
    epochs.Observe(target, true);
    check(epochs.Stamp() == internal, "rereview.context-internal-observation-preserves-captured-context");
    // A walk in flight must mask identity changes for observers on OTHER
    // threads too: CLI job polls run outside the switching thread's
    // thread-local depth and would otherwise record the walk's transient
    // thread switch as a session context change, stale-killing the walk's
    // restore (observed live as CollectionContextChanged / restore refusal).
    epochs.EnterWalk();
    target.Thread = 42;
    target.Process = 9;
    target.Stopped = false;
    epochs.Observe(target);
    check(epochs.Stamp() == internal, "epoch.walk-in-flight-masks-foreign-thread-observation");
    epochs.LeaveWalk();
    target.Thread = 43;
    epochs.Observe(target);
    check(epochs.Stamp().ContextGeneration > internal.ContextGeneration, "epoch.walk-leave-resumes-identity-tracking");
    target.Stopped = false;
    epochs.Observe(target);
    check(epochs.Stamp().StopEpoch > internal.StopEpoch, "epoch.walk-leave-resumes-stop-tracking");
    target.Stopped = true;
    epochs.Observe(target);
    target.Stopped = false;
    epochs.Observe(target);
    check(epochs.Stamp().StopEpoch > first.StopEpoch, "epoch.resume-invalidates-stop");
    const auto beforeContext = epochs.Stamp();
    target.Thread = 7;
    epochs.Observe(target);
    check(epochs.Stamp().ContextGeneration > beforeContext.ContextGeneration, "epoch.external-context-invalidates");
    const auto beforeSymbols = epochs.Stamp();
    epochs.SymbolsChanged();
    check(epochs.Stamp().SymbolGeneration > beforeSymbols.SymbolGeneration, "epoch.reload-invalidates-layout");
    epochs.Fault();
    epochs.Observe(target);
    check(epochs.State() == kncore::SessionState::Faulted, "epoch.fault-is-sticky");
    epochs.Reconnect();
    target.Stopped = true;
    epochs.Observe(target);
    check(epochs.State() == kncore::SessionState::ReadyStopped && epochs.Stamp().TargetGeneration > first.TargetGeneration,
          "epoch.reconnect-rebuilds-state");
}
} // namespace knself
