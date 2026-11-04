# Third-party components

## Microsoft WebView2 SDK 1.0.2792.45

Vendored SDK headers and the static x64 loader originate from the [official NuGet package](https://www.nuget.org/packages/Microsoft.Web.WebView2/1.0.2792.45). The package version is pinned; this is not a claim that it is the newest version. The SDK uses Microsoft's distribution license, copied at [deps/webview2/LICENSE.txt](deps/webview2/LICENSE.txt).

[deps/dependencies.lock.json](deps/dependencies.lock.json) records the official package URL/SHA-256 and each of the 12 vendored file hashes. Binary files match the package. Four text files differ only by line endings; the lock records upstream and normalized hashes. The verifier accepts only that documented normalization and rejects content changes. The static loader is linked into KNDbgX; the Evergreen browser runtime is a separately installed prerequisite.

## Microsoft DIA msdia140.dll

Builds stage the unmodified installed Visual Studio public x64 DIA provider under `runtime/dia/msdia140.dll`. No registration is performed. It provides matched-PDB type/symbol access and is distinct from WinDbg's private DIA implementation. The release manifest and SBOM record the distributed DLL hash.

Microsoft lists `DIA SDK\bin\amd64\msdia140.dll` in the [Visual Studio 2022 redistribution list](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution), subject to the applicable Visual Studio license terms. Copyright remains with Microsoft. No rights in Microsoft's components are granted by KNDbgX beyond their applicable licenses.

## kn-live-dbg reference adaptations

The CI/HVCI reply contract, hypervisor interface discovery and unload-event identity rules were adapted from
[kernullist/kn-live-dbg at b2aac96](https://github.com/kernullist/kn-live-dbg/tree/b2aac96c973dc74b7c688315de8c504f4bf21942),
particularly `user/CodeIntegrityState.h`, `user/VbsScanner.cpp` and `user/SnapshotCollector.cpp`.
KNDbgX integrates these rules through its own DbgEng command/result model.

MIT License

Copyright (c) 2026 kernullist

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## External prerequisites and test evidence

WinDbg, the Windows SDK, Visual Studio toolchain, Microsoft VC++ x64 runtime and WebView2 Evergreen Runtime remain separate products with their own terms. No `dbgeng.dll`, `dbgmodel.dll`, WinDbg test runtime, OS image or downloaded Microsoft PDB is included in the release ZIP. Public PDB/image hashes and provenance profiles are metadata; original artifacts remain local test evidence.

`sbom.cdx.json` and `release-manifest.json` inside each generated package identify its exact components and bytes. KNDbgX's dependency manifest does not establish the licensing or redistribution rights of arbitrary future inputs or user-supplied artifacts.
