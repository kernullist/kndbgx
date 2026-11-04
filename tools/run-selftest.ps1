param([string]$Configuration = "Release")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

. "$PSScriptRoot\BuildCommon.ps1"
$msbuild = Get-KnMSBuild
& $msbuild `
    "$root\kndbgx-selftest.vcxproj" /p:Configuration=$Configuration /p:Platform=x64 /v:q /nologo

if ($LASTEXITCODE -ne 0)
{
    throw "Self-test build failed with exit code $LASTEXITCODE"
}

& "$root\x64\$Configuration\kndbgx-selftest.exe"
exit $LASTEXITCODE
