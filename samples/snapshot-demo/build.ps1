param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$SdkVersion = '10.0.26100.0',
    [switch]$Analyze,
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Artifacts.ps1')

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere))
{
    throw 'vswhere.exe is required. Install Visual Studio 2022 C++ and the WDK VS extension.'
}
$installations = (& $vswhere -products '*' -version '[17.0,18.0)' `
    -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json) | ConvertFrom-Json
$installation = $installations | Where-Object {
    Test-Path -LiteralPath (Join-Path $_.installationPath 'MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0\Toolset.props')
} | Select-Object -First 1
if (-not $installation)
{
    throw 'No Visual Studio 2022 installation with both C++ and the WDK toolset was found.'
}
$msbuild = Join-Path $installation.installationPath 'MSBuild\Current\Bin\MSBuild.exe'
$kitRegistry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots'
$kitRoot = $kitRegistry.KitsRoot10
foreach ($relative in @("Include\$SdkVersion\km\ntddk.h", "Lib\$SdkVersion\km\x64\ntoskrnl.lib", "build\$SdkVersion\WindowsDriver.common.props"))
{
    if (-not (Test-Path -LiteralPath (Join-Path $kitRoot $relative)))
    {
        throw "Required WDK component is missing: $relative"
    }
}
$output = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\artifacts\snapshot-demo\$Configuration"))
$analysis = if ($Analyze) { 'true' } else { 'false' }
$sampleDirectory = $PSScriptRoot
$buildAction = {
    param([string]$buildDirectory)
    foreach ($project in @('driver\KnSnapshotDemo.vcxproj', 'controller\KnSnapshotDemoCtl.vcxproj', 'fixtures\KnSnapshotDemoFixtures.vcxproj'))
    {
        & $msbuild (Join-Path $sampleDirectory $project) /t:Rebuild /nologo /v:minimal /m:2 `
            "/p:Configuration=$Configuration" /p:Platform=x64 "/p:WindowsTargetPlatformVersion=$SdkVersion" "/p:RunCodeAnalysis=$analysis" `
            /p:SignMode=Off /p:EnableTestSign=false
        if ($LASTEXITCODE -ne 0)
        {
            throw "Build failed: $project ($LASTEXITCODE)"
        }
    }
    python (Join-Path $sampleDirectory 'verify-artifacts.py') $buildDirectory
    if ($LASTEXITCODE -ne 0)
    {
        throw 'Native image, PDB or callback-address verification failed.'
    }
    if ((Get-AuthenticodeSignature -LiteralPath (Join-Path $buildDirectory 'KnSnapshotDemo.sys')).Status -ne 'NotSigned')
    {
        throw 'The unsigned build produced an unexpected signature state.'
    }
    if (-not $SkipTests)
    {
        & (Join-Path $buildDirectory 'KnSnapshotDemoCtl.exe') --selftest
        if ($LASTEXITCODE -ne 0)
        {
            throw 'Controller self-test failed.'
        }
        $fixtureRoot = Join-Path $buildDirectory ('fixtures-' + [Guid]::NewGuid().ToString('N'))
        & (Join-Path $buildDirectory 'KnSnapshotDemoFixtures.exe') $fixtureRoot
        if ($LASTEXITCODE -ne 0)
        {
            throw 'Synthetic snapshot tests failed.'
        }
        & (Join-Path $sampleDirectory 'test-scripts.ps1')
        if ($LASTEXITCODE -ne 0)
        {
            throw 'Artifact transaction model tests failed.'
        }
        Write-Host "Synthetic input directory: $fixtureRoot"
    }
    Copy-Item -LiteralPath (Join-Path $sampleDirectory 'README.ko.md') -Destination (Join-Path $buildDirectory 'README.ko.md') -Force
}.GetNewClosure()
$manifest = [ordered]@{
    schema = 'kndbgx.snapshot-demo.build.v2'
    state = 'Building'
    buildId = [Guid]::NewGuid().ToString('N')
    configuration = $Configuration
    sdkVersion = $SdkVersion
    visualStudio = $installation.installationVersion
    staticAnalysisRequested = [bool]$Analyze
    offlineTestsExecuted = -not [bool]$SkipTests
    unsigned = $null
    liveDriverTested = $false
    files = @()
}
Invoke-DemoBuildTransaction $output $manifest $buildAction | Out-Null
Write-Host "Built unsigned x64 sample: $output"
Write-Host 'No service, driver load, certificate store, boot policy or VM state was changed.'
