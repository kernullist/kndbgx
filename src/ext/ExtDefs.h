#pragma once

// Self-contained WinDbg classic-extension declarations.
//
// We intentionally do not include <wdbgexts.h> so the project builds with
// nothing but Visual Studio + the Windows SDK. Only the pieces KNDbgX needs
// are declared here:
//   - EXT_API_VERSION / ExtensionApiVersion export
//   - WinDbgExtensionDllInit receiving PWINDBG_EXTENSION_APIS64 (opaque)
//   - the standard five-argument extension command callback shape
//
// For host-console printing we peek at the first two fields of the extension
// API block (nSize, lpOutputRoutine). That prefix has been stable across every
// released debugger since wdbgexts was introduced, and we guard it with nSize.

#include <windows.h>

struct EXT_API_VERSION
{
    unsigned short MajorVersion;
    unsigned short MinorVersion;
    unsigned short Revision;
    unsigned short Reserved;
};

typedef struct EXT_API_VERSION EXT_API_VERSION_T;
typedef EXT_API_VERSION *LPEXT_API_VERSION;

struct WINDBG_EXTENSION_APIS64;
typedef struct WINDBG_EXTENSION_APIS64 WINDBG_EXTENSION_APIS64_T;
typedef WINDBG_EXTENSION_APIS64_T *PWINDBG_EXTENSION_APIS64;

// printf-style routine used by extensions to write into the host console.
typedef void (*KNDGX_OUTPUT_ROUTINE)(const char *format, ...);

// Minimal typed view over WINDBG_EXTENSION_APIS64. Only touch this after
// validating that the real block's nSize is at least sizeof(ExtApisView).
struct ExtApisView
{
    unsigned long nSize;
    KNDGX_OUTPUT_ROUTINE OutputRoutine;
};

// Standard wdbgexts command callback shape (x64).
#define KNDGX_COMMAND_ARGS HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG_PTR dwCurrentPc, ULONG dwProcessor, PCSTR lpArgumentString
