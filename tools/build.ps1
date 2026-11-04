param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

. "$PSScriptRoot\BuildCommon.ps1"
$msbuild = Get-KnMSBuild
Write-Host "== Building kndbgx ($Configuration) =="
Write-Host "MSBuild: $msbuild"

& $msbuild "$root\kndbgx.sln" `
    /p:Configuration=$Configuration /p:Platform=x64 `
    /m /v:m /nologo

if ($LASTEXITCODE -ne 0)
{
    throw "Build failed with exit code $LASTEXITCODE"
}

$outDir = Join-Path $root "x64\$Configuration"

Write-Host ""
Write-Host "Artifacts:"
Get-ChildItem $outDir -File |
    Where-Object { $_.Name -in @("kndbgx.dll", "kndbgx-selftest.exe") } |
    ForEach-Object { Write-Host ("  {0}  {1}" -f $_.Name, $_.Length) }

if ($RunTests)
{
    Write-Host ""
    Write-Host "== Self-test =="

    $exe = Join-Path $outDir "kndbgx-selftest.exe"
    & $exe

    if ($LASTEXITCODE -ne 0)
    {
        throw "Self-test failed with exit code $LASTEXITCODE"
    }
    $taskNode = Get-Command node -ErrorAction Stop
    foreach ($testScript in @('test-bootstrap.mjs', 'test-ui-policy.mjs', 'test-ui-faults.mjs'))
    {
        & $taskNode.Source (Join-Path $PSScriptRoot $testScript)
        if ($LASTEXITCODE -ne 0)
        {
            throw "UI regression failed: $testScript"
        }
    }
}

Write-Host ""
Write-Host "Done. Load in WinDbg with:"
Write-Host "  .load $outDir\kndbgx.dll"
