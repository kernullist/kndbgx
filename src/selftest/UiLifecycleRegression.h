#pragma once

#include "../core/UiLifecycle.h"
#include "SnapshotRpcRegression.h"

namespace knself
{
template <typename Check> void RunUiLifecycleRegression(Check check)
{
    using namespace kncore;
    for (unsigned index = static_cast<unsigned>(UiStep::CoreView); index < static_cast<unsigned>(UiStep::Count); ++index)
    {
        UiLifecycle lifecycle;
        lifecycle.Begin();
        unsigned navigations = 0;
        unsigned rollbacks = 0;
        const bool installed = lifecycle.Install(
            [&](UiStep step) -> int32_t
            {
                if (static_cast<unsigned>(step) == index)
                {
                    return static_cast<int32_t>(0x80004005u);
                }
                navigations += step == UiStep::Navigate;
                return 0;
            },
            [&]()
            {
                ++rollbacks;
            });
        check(!installed && lifecycle.Phase == UiPhase::Failed && !lifecycle.MessagesAllowed() &&
                  static_cast<unsigned>(lifecycle.FailedStep) == index && rollbacks == 1 && navigations == 0,
              "rereview.ui-mandatory-step-failure-rolls-back-with-zero-navigation");
    }
    for (const auto step : {UiStep::EnvironmentRequest, UiStep::EnvironmentComplete, UiStep::ControllerRequest, UiStep::ControllerComplete})
    {
        UiLifecycle lifecycle;
        lifecycle.Begin();
        check(!lifecycle.Check(step, static_cast<int32_t>(0x8007000eu)) && lifecycle.FailedStep == step && !lifecycle.MessagesAllowed(),
              "rereview.ui-immediate-or-completion-failure-records-stage");
        lifecycle.Begin();
        check(!lifecycle.Check(step, 0, false) && lifecycle.Error == static_cast<int32_t>(0x80004003u),
              "rereview.ui-null-completion-object-fails-closed");
    }
    for (const auto interrupted : {UiPhase::Failed, UiPhase::Closing})
    {
        UiLifecycle lifecycle;
        lifecycle.Begin();
        unsigned navigations = 0;
        const bool installed = lifecycle.Install(
            [&](UiStep step)
            {
                if (step == UiStep::Settings)
                {
                    lifecycle.Phase = interrupted;
                }
                navigations += step == UiStep::Navigate;
                return 0;
            },
            []()
            {
            });
        check(!installed && navigations == 0 && !lifecycle.MessagesAllowed(),
              "rereview.ui-reentrant-close-or-failure-cannot-resume-installation");
    }
    for (bool handshakeFirst : {false, true})
    {
        UiLifecycle lifecycle;
        lifecycle.Begin();
        check(!UiCallbackCurrent(1, 1, 1, 2, false) && !UiCallbackCurrent(1, 1, 2, 1, false) && !UiCallbackCurrent(1, 1, 1, 1, true) &&
                  UiCallbackCurrent(1, 1, 1, 1, false),
              "rereview.ui-late-completion-generation-rejected");
        unsigned navigations = 0;
        check(lifecycle.Install(
                  [&](UiStep step)
                  {
                      navigations += step == UiStep::Navigate;
                      return 0;
                  },
                  []()
                  {
                  }) &&
                  navigations == 1 && lifecycle.MessagesAllowed() && lifecycle.Phase != UiPhase::Ready,
              "rereview.ui-policy-installed-before-first-navigation");
        if (handshakeFirst)
        {
            lifecycle.AcceptedHandshake();
        }
        else
        {
            lifecycle.DocumentLoaded();
        }
        check(lifecycle.Phase != UiPhase::Ready, "rereview.ui-one-readiness-signal-is-insufficient");
        if (handshakeFirst)
        {
            lifecycle.DocumentLoaded();
        }
        else
        {
            lifecycle.AcceptedHandshake();
        }
        check(lifecycle.Phase == UiPhase::Ready, "rereview.ui-ready-requires-load-and-fresh-handshake");
        lifecycle.Check(UiStep::ProcessHandler, static_cast<int32_t>(0x80004005u));
        lifecycle.AcceptedHandshake();
        lifecycle.DocumentLoaded();
        check(!lifecycle.MessagesAllowed() && lifecycle.Phase == UiPhase::Failed, "rereview.ui-late-document-events-cannot-revive-failure");
    }
    for (const auto failure :
         {UiProcessFailure::GpuExited, UiProcessFailure::UtilityExited, UiProcessFailure::FrameExited, UiProcessFailure::OtherExited})
    {
        check(ProcessRecovery(failure) == UiRecovery::PreserveDocument, "rereview.ui-recoverable-component-preserves-document");
    }
    for (const auto failure : {UiProcessFailure::BrowserExited, UiProcessFailure::RendererExited, UiProcessFailure::Unknown})
    {
        check(ProcessRecovery(failure) == UiRecovery::RecreateControl, "rereview.ui-lost-document-requires-recreation");
    }
    check(ProcessRecovery(UiProcessFailure::RendererUnresponsive) == UiRecovery::WaitForRenderer,
          "rereview.ui-unresponsive-is-not-document-loss");
    RpcGate gate;
    gate.Navigate(7);
    std::wstring reason;
    const std::wstring origin = L"https://app.kndbgx.local/index.html";
    check(gate.Accept(FixtureRpc(L"hello", 1), origin, 256, reason) && gate.Accept(FixtureRpc(L"status", 2), origin, 256, reason),
          "rereview.ui-surviving-document-retains-rpc-session");
    gate.Navigate(8);
    check(!gate.Accept(FixtureRpc(L"status", 3), origin, 256, reason) && gate.Accept(FixtureRpc(L"hello", 1), origin, 256, reason) &&
              !gate.Accept(FixtureRpc(L"status", 4), origin, 256, reason),
          "rereview.ui-fatal-recovery-rejects-old-generation-without-replay");
    check(RpcNeedsWorker(L"navigateResult") && RpcNeedsWorker(L"saveLog") && RpcNeedsWorker(L"executePlan") &&
              !RpcNeedsWorker(L"resultPage") && !RpcNeedsWorker(L"resultInfo"),
          "rereview.ui-bound-navigation-routed-to-owner-worker");
    auto inspection = knjson::Value::MakeObject();
    inspection.Set(L"action", knjson::Value(L"show"));
    inspection.Set(L"token", knjson::Value(L"1"));
    check(!RpcShape(FixtureRpc(L"inspectionWindow", 5, inspection), reason),
          "ui.inspection-window-control-requires-visibility-epoch");
    inspection.Set(L"visibilityEpoch", knjson::Value(L"0"));
    check(!RpcNeedsWorker(L"inspectionWindow") && RpcShape(FixtureRpc(L"inspectionWindow", 5, inspection), reason),
          "ui.inspection-window-control-does-not-enter-engine-worker");
    inspection.Set(L"command", knjson::Value(L"g"));
    check(!RpcShape(FixtureRpc(L"inspectionWindow", 6, inspection), reason),
          "ui.inspection-window-control-rejects-extra-command-parameter");
}
} // namespace knself
