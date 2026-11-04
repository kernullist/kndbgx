param(
    [string]$EvidenceDirectory = "$PSScriptRoot\..\artifacts\evidence\release",
    [switch]$SkipEngine,
    [switch]$ReleaseOnly
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\BuildCommon.ps1"
$taskRoot = Split-Path -Parent $PSScriptRoot
$msbuild = Get-KnMSBuild
$python = (Get-Command python -ErrorAction Stop).Source
$node = (Get-Command node -ErrorAction Stop).Source
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$EvidenceDirectory = (Resolve-Path -LiteralPath $EvidenceDirectory).Path

function Invoke-KnBuild
{
    param([string]$Project, [string]$Configuration, [string[]]$Extra = @())
    & $msbuild (Join-Path $taskRoot $Project) /t:Rebuild /p:Configuration=$Configuration /p:Platform=x64 /m /v:m /nologo @Extra
    if ($LASTEXITCODE -ne 0)
    {
        throw "Rebuild failed: $Project $Configuration"
    }
}

function Invoke-KnSelfTest
{
    param([string]$Directory)
    & (Join-Path $Directory 'kndbgx-selftest.exe')
    if ($LASTEXITCODE -ne 0)
    {
        throw "Self-test failed: $Directory"
    }
}

$configurations = if ($ReleaseOnly) { @('Release') } else { @('Debug', 'Release') }
foreach ($configuration in $configurations)
{
    Invoke-KnBuild 'kndbgx.sln' $configuration
    Invoke-KnSelfTest (Join-Path $taskRoot "x64\$configuration")
    Write-Host "PASS release.clean-solution-$configuration"
    if ($configuration -eq 'Release')
    {
        foreach ($name in @('kndbgx.dll', 'kndbgx.pdb'))
        {
            Copy-Item -LiteralPath (Join-Path $taskRoot "x64\Release\$name") -Destination (Join-Path $EvidenceDirectory "first-$name")
        }
    }

    # Debug direct builds additionally cover a Unicode and space-containing output path.
    $directDirectory = if ($configuration -eq 'Debug') { Join-Path $taskRoot 'artifacts\build-matrix\Debug \uAC80\uC99D' } else { Join-Path $taskRoot 'x64\Release' }
    $directDirectory = $directDirectory.Replace('\uAC80\uC99D', ([string][char]0xAC80 + [char]0xC99D))
    foreach ($project in @('kndbgx', 'kndbgx-selftest', 'kndbgx-engine-test'))
    {
        $extra = @()
        if ($configuration -eq 'Debug')
        {
            # Avoid a trailing backslash escaping native argument quotes.
            $propertyDirectory = $directDirectory.Replace('\', '/')
            $extra = @("/p:OutDir=$propertyDirectory/", "/p:IntDir=$propertyDirectory/obj-$project/")
        }
        Invoke-KnBuild "$project.vcxproj" $configuration $extra
        Write-Host "PASS release.direct-project-$project-$configuration"
    }
    Invoke-KnSelfTest $directDirectory
    if ($configuration -eq 'Release')
    {
        & $python (Join-Path $PSScriptRoot 'release.py') check-rebuilds --first-directory $EvidenceDirectory
        if ($LASTEXITCODE -ne 0)
        {
            throw 'Clean Release DLL or matching PDB verification failed.'
        }
    }
}
foreach ($script in @('test-bootstrap.mjs', 'test-ui-policy.mjs', 'test-ui-faults.mjs'))
{
    & $node (Join-Path $PSScriptRoot $script)
    if ($LASTEXITCODE -ne 0)
    {
        throw "UI regression failed: $script"
    }
}
& $msbuild (Join-Path $taskRoot 'kndbgx.vcxproj') /t:PrepareForBuild /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=0.0 /nologo /v:m *> (Join-Path $EvidenceDirectory 'invalid-sdk.log')
if ($LASTEXITCODE -eq 0 -or -not (Select-String -LiteralPath (Join-Path $EvidenceDirectory 'invalid-sdk.log') -Pattern 'MSB8036' -Quiet))
{
    throw 'Invalid SDK negative control did not produce MSB8036.'
}
Write-Host 'PASS release.invalid-sdk-diagnostic'
& $python (Join-Path $PSScriptRoot 'release.py') docs
if ($LASTEXITCODE -ne 0)
{
    throw 'Command document generation failed.'
}
& $python (Join-Path $PSScriptRoot 'release.py') check-artifacts
if ($LASTEXITCODE -ne 0)
{
    throw 'Release artifact validation failed.'
}
& $python (Join-Path $PSScriptRoot 'test-release-privacy.py')
if ($LASTEXITCODE -ne 0)
{
    throw 'Release privacy regression failed.'
}
& $python (Join-Path $PSScriptRoot 'release.py') check-privacy
if ($LASTEXITCODE -ne 0)
{
    throw 'Publication privacy check failed.'
}
if (-not $SkipEngine)
{
    & "$PSScriptRoot\run-engine-test.ps1" -Configuration Release -EvidenceDirectory (Join-Path $EvidenceDirectory 'engine')
}
Write-Host 'PASS release.validation-run-complete'
