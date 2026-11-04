#pragma once

#include <cstdint>
#include <functional>

namespace kncore
{
enum class UiPhase
{
    Idle,
    EnvironmentPending,
    ControllerPending,
    PolicyInstalling,
    Navigating,
    Handshaken,
    Ready,
    Failed,
    Closing
};
enum class UiStep
{
    EnvironmentRequest,
    EnvironmentComplete,
    ControllerRequest,
    ControllerComplete,
    CoreView,
    Bounds,
    Settings,
    WebMessages,
    HostObjects,
    ScriptDialogs,
    ContextMenus,
    StatusBar,
    DevTools,
    ResourceFilter,
    ResourceHandler,
    MessageHandler,
    NavigationHandler,
    FrameHandler,
    NewWindowHandler,
    PermissionHandler,
    ProcessHandler,
    NavigationCompleteHandler,
    BrowserExitHandler,
    DownloadHandler,
    Visible,
    Navigate,
    Count,
    ResourceStream = Count,
    ResourceResponse,
    ResourceDelivery,
    HandshakeTimeout,
    StageCount
};
inline const wchar_t *UiStepName(UiStep step)
{
    static constexpr const wchar_t *names[] = {L"EnvironmentRequest",
                                               L"EnvironmentComplete",
                                               L"ControllerRequest",
                                               L"ControllerComplete",
                                               L"CoreView",
                                               L"Bounds",
                                               L"Settings",
                                               L"WebMessages",
                                               L"HostObjects",
                                               L"ScriptDialogs",
                                               L"ContextMenus",
                                               L"StatusBar",
                                               L"DevTools",
                                               L"ResourceFilter",
                                               L"ResourceHandler",
                                               L"MessageHandler",
                                               L"NavigationHandler",
                                               L"FrameHandler",
                                               L"NewWindowHandler",
                                               L"PermissionHandler",
                                               L"ProcessHandler",
                                               L"NavigationCompleteHandler",
                                               L"BrowserExitHandler",
                                               L"DownloadHandler",
                                               L"Visible",
                                               L"Navigate",
                                               L"ResourceStream",
                                               L"ResourceResponse",
                                               L"ResourceDelivery",
                                               L"HandshakeTimeout"};
    const auto index = static_cast<unsigned>(step);
    return index < static_cast<unsigned>(UiStep::StageCount) ? names[index] : L"UnknownStage";
}
enum class UiProcessFailure
{
    BrowserExited,
    RendererExited,
    RendererUnresponsive,
    FrameExited,
    GpuExited,
    UtilityExited,
    OtherExited,
    Unknown
};
enum class UiRecovery
{
    PreserveDocument,
    WaitForRenderer,
    RecreateControl
};
inline UiRecovery ProcessRecovery(UiProcessFailure failure)
{
    return failure == UiProcessFailure::RendererUnresponsive ? UiRecovery::WaitForRenderer
           : failure == UiProcessFailure::BrowserExited || failure == UiProcessFailure::RendererExited ||
                   failure == UiProcessFailure::Unknown
               ? UiRecovery::RecreateControl
               : UiRecovery::PreserveDocument;
}

inline bool UiCallbackCurrent(uint64_t capturedWindow, uint64_t capturedControl, uint64_t window, uint64_t control, bool closing)
{
    return !closing && capturedWindow == window && capturedControl == control;
}

class UiLifecycle
{
  public:
    UiPhase Phase = UiPhase::Idle;
    UiStep FailedStep = UiStep::Count;
    int32_t Error = 0;
    bool PolicyInstalled = false;
    bool Loaded = false;
    bool Handshake = false;

    void Begin()
    {
        Phase = UiPhase::EnvironmentPending;
        FailedStep = UiStep::Count;
        Error = 0;
        PolicyInstalled = Loaded = Handshake = false;
    }
    bool Check(UiStep step, int32_t status, bool present = true)
    {
        if (status < 0 || !present)
        {
            Phase = UiPhase::Failed;
            FailedStep = step;
            Error = status < 0 ? status : static_cast<int32_t>(0x80004003u);
            PolicyInstalled = Loaded = Handshake = false;
            return false;
        }
        return true;
    }
    bool Install(const std::function<int32_t(UiStep)> &call, const std::function<void()> &rollback)
    {
        Phase = UiPhase::PolicyInstalling;
        for (unsigned index = static_cast<unsigned>(UiStep::CoreView); index < static_cast<unsigned>(UiStep::Count); ++index)
        {
            const auto step = static_cast<UiStep>(index);
            if (step == UiStep::Navigate)
            {
                PolicyInstalled = true;
                NewDocument();
            }
            const auto status = call(step);
            if (Phase == UiPhase::Failed || Phase == UiPhase::Closing || !Check(step, status))
            {
                rollback();
                return false;
            }
        }
        return true;
    }
    void NewDocument()
    {
        Loaded = Handshake = false;
        Phase = UiPhase::Navigating;
    }
    bool MessagesAllowed() const
    {
        return PolicyInstalled && (Phase == UiPhase::Navigating || Phase == UiPhase::Handshaken || Phase == UiPhase::Ready);
    }
    void DocumentLoaded()
    {
        if (MessagesAllowed())
        {
            Loaded = true;
            Phase = Handshake ? UiPhase::Ready : UiPhase::Navigating;
        }
    }
    void AcceptedHandshake()
    {
        if (MessagesAllowed())
        {
            Handshake = true;
            Phase = Loaded ? UiPhase::Ready : UiPhase::Handshaken;
        }
    }
};
} // namespace kncore
