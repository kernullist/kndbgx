# Build helper for shells missing ProgramFiles environment variables.
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$Project,
    [switch]$RunTests
)
$ErrorActionPreference = 'Stop'
if (-not $env:ProgramFiles) { $env:ProgramFiles = 'C:\Program Files' }
if (-not ${env:ProgramFiles(x86)}) { ${env:ProgramFiles(x86)} = 'C:\Program Files (x86)' }
if (-not $env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }
. (Join-Path $PSScriptRoot 'BuildCommon.ps1')
$msbuild = Get-KnMSBuild
$target = if ($Project) { Join-Path $PSScriptRoot ("..\" + $Project) } else { Join-Path $PSScriptRoot '..\kndbgx.sln' }
& $msbuild $target /p:Configuration=$Configuration /p:Platform=x64 /m /v:m /nologo
if ($LASTEXITCODE -ne 0) { throw "Build failed: $LASTEXITCODE" }
if ($RunTests)
{
    $exe = Join-Path $PSScriptRoot "..\x64\$Configuration\kndbgx-selftest.exe"
    & $exe
    if ($LASTEXITCODE -ne 0) { throw "Self-test failed: $LASTEXITCODE" }
}
