#pragma once

// UX window host: dedicated STA thread, Win32 top-level window, WebView2
// controller, embedded-asset serving and the JSON bridge hookup.
//
// Called from the engine thread:
//   knui::ShowWindowAsyncSafe()  open or raise the retained workspace
//   knui::ShutdownAsyncSafe()    release the workspace and stop the thread
// Closing the normal window hides it without releasing its document/results.

namespace knui
{
void ShowWindowAsyncSafe();
void ShutdownAsyncSafe();
} // namespace knui
