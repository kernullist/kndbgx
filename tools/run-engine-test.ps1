param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$EngineDirectory,
    [string]$EvidenceDirectory = "$PSScriptRoot\..\artifacts\evidence\engine",
    [switch]$WithoutAppLocalDia
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\BuildCommon.ps1"
$taskRoot = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$EvidenceDirectory = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
if (-not $EngineDirectory)
{
    $package = Get-AppxPackage Microsoft.WinDbg | Sort-Object Version -Descending | Select-Object -First 1
    if ($package)
    {
        $sourceRuntime = Join-Path $package.InstallLocation 'amd64'
        $EngineDirectory = Join-Path $EvidenceDirectory ("runtime-" + $package.Version)
        New-Item -ItemType Directory -Path $EngineDirectory -Force | Out-Null
        # Appx executable ACLs prevent an unpackaged test host loading in place.
        # Stage installed runtime DLLs for testing only; never package them.
        Get-ChildItem -LiteralPath $sourceRuntime -File -Filter '*.dll' | ForEach-Object {
            $destination = Join-Path $EngineDirectory $_.Name
            if (-not (Test-Path -LiteralPath $destination) -or
                (Get-FileHash -LiteralPath $_.FullName).Hash -ne (Get-FileHash -LiteralPath $destination).Hash)
            {
                Copy-Item -LiteralPath $_.FullName -Destination $destination
            }
        }
    }
}
if (-not $EngineDirectory -or -not (Test-Path -LiteralPath (Join-Path $EngineDirectory 'dbgeng.dll')))
{
    throw 'Install WinDbg or specify -EngineDirectory containing an x64 dbgeng.dll.'
}
$msbuild = Get-KnMSBuild
& $msbuild "$taskRoot\kndbgx-engine-test.vcxproj" /p:Configuration=$Configuration /p:Platform=x64 /m /v:m /nologo
if ($LASTEXITCODE -ne 0)
{
    throw 'Engine test build failed.'
}
$runId = [Guid]::NewGuid().ToString('N')
$dump = Join-Path $EvidenceDirectory "owned-$runId.dmp"
$exe = Join-Path $taskRoot "x64\$Configuration\kndbgx-engine-test.exe"
$dll = Join-Path $taskRoot "x64\$Configuration\kndbgx.dll"
if ($WithoutAppLocalDia)
{
    # Exercise the installed engine's DIA fallback without changing the build.
    $isolated = Join-Path $EvidenceDirectory "without-app-local-dia-$runId"
    New-Item -ItemType Directory -Path $isolated | Out-Null
    foreach ($name in @('kndbgx-engine-test.exe', 'kndbgx-engine-test.pdb', 'kndbgx.dll', 'kndbgx.pdb'))
    {
        Copy-Item -LiteralPath (Join-Path $taskRoot "x64\$Configuration\$name") -Destination $isolated
    }
    $exe = Join-Path $isolated 'kndbgx-engine-test.exe'
    $dll = Join-Path $isolated 'kndbgx.dll'
}
Get-FileHash -Algorithm SHA256 -LiteralPath $dll, (Join-Path $EngineDirectory 'dbgeng.dll') |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory "hashes-$runId.json")
& $exe $EngineDirectory $dll $dump
if ($LASTEXITCODE -ne 0)
{
    throw "Engine integration failed with exit code $LASTEXITCODE"
}
& $exe --deferred-symbols $EngineDirectory $dll $dump
if ($LASTEXITCODE -ne 0)
{
    throw "Deferred-symbol integration failed with exit code $LASTEXITCODE"
}
