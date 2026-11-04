param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Artifacts.ps1')
if (-not $OutputDirectory)
{
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('knsnapshot-scripts-' + [Guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $OutputDirectory)
{
    throw 'Script test output must be a new directory.'
}
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$script:demoPassed = 0

function Assert-Demo([bool]$Condition, [string]$Name)
{
    if (-not $Condition)
    {
        throw "FAIL $Name"
    }
    $script:demoPassed++
    Write-Host "PASS $Name"
}

function Assert-DemoThrows([scriptblock]$Action, [string]$Name)
{
    $rejected = $false
    try
    {
        & $Action | Out-Null
    }
    catch
    {
        $rejected = $true
    }
    Assert-Demo $rejected $Name
}

function New-DemoFixture([string]$Name)
{
    $directory = Join-Path $OutputDirectory $Name
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    foreach ($file in (Get-DemoFileNames))
    {
        [IO.File]::WriteAllText((Join-Path $directory $file), ('SYNTHETIC-SCRIPT-TEST-' + $file))
    }
    $manifest = [ordered]@{
        schema = 'kndbgx.snapshot-demo.build.v2'
        state = 'Ready'
        unsigned = $true
        liveDriverTested = $false
        files = @(Get-DemoFileRecords $directory)
    }
    Write-DemoJsonAtomic (Join-Path $directory 'build-manifest.json') $manifest
    return $directory
}

$valid = New-DemoFixture 'valid'
Assert-Demo ((Read-DemoReadyManifest $valid).state -eq 'Ready') 'complete manifest accepted'
$lock = Open-DemoArtifactLock $valid
try
{
    Assert-DemoThrows { Open-DemoArtifactLock $valid } 'concurrent writer refused'
}
finally
{
    $lock.Dispose()
}
$lock = Open-DemoArtifactLock $valid
$lock.Dispose()
Assert-Demo $true 'artifact lock released after disposal'

$transcript = New-DemoFixture 'transcript'
$metadata = Read-DemoReadyManifest $transcript
$transcriptPath = Join-Path $transcript 'build-output.log'
Invoke-DemoBuildTransaction $transcript $metadata {
    param($directory)
    Write-Output 'NATIVE-STDOUT-CONTROL'
} *> $transcriptPath
Assert-Demo ((Get-Content -LiteralPath $transcriptPath -Raw).Contains('NATIVE-STDOUT-CONTROL')) `
    'build output remains capturable in redirected validation logs'

$manifestPath = Join-Path $valid 'build-manifest.json'
$originalManifest = [IO.File]::ReadAllBytes($manifestPath)
$pin = [IO.File]::Open($manifestPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try
{
    Assert-DemoThrows { Write-DemoJsonAtomic $manifestPath @{state='Failed'} } 'failed manifest replacement reported'
    Assert-Demo ([Convert]::ToBase64String([IO.File]::ReadAllBytes($manifestPath)) -eq [Convert]::ToBase64String($originalManifest)) `
        'failed manifest replacement preserves original bytes'
}
finally
{
    $pin.Dispose()
}

$mismatch = New-DemoFixture 'mismatch'
[IO.File]::AppendAllText((Join-Path $mismatch 'KnSnapshotDemo.sys'), '-changed')
Assert-DemoThrows { Read-DemoReadyManifest $mismatch } 'changed driver hash refused'
$duplicate = New-DemoFixture 'duplicate'
$metadata = Read-DemoReadyManifest $duplicate
$metadata.files[1] = $metadata.files[0]
Write-DemoJsonAtomic (Join-Path $duplicate 'build-manifest.json') $metadata
Assert-DemoThrows { Read-DemoReadyManifest $duplicate } 'duplicate manifest entry refused'
$pending = New-DemoFixture 'pending'
$metadata = Read-DemoReadyManifest $pending
$metadata.state = 'Building'
Write-DemoJsonAtomic (Join-Path $pending 'build-manifest.json') $metadata
Assert-DemoThrows { Read-DemoReadyManifest $pending } 'in-progress output refused'

$failedBuild = New-DemoFixture 'failed-build'
$metadata = [ordered]@{schema='kndbgx.snapshot-demo.build.v2';state='Building';unsigned=$null;liveDriverTested=$false;files=@()}
Assert-DemoThrows {
    Invoke-DemoBuildTransaction $failedBuild $metadata {
        param($directory)
        [IO.File]::AppendAllText((Join-Path $directory 'KnSnapshotDemo.sys'), '-partial-build')
        throw 'Injected compiler failure'
    }
} 'partial build failure propagated'
$failedManifest = Get-Content -LiteralPath (Join-Path $failedBuild 'build-manifest.json') -Raw | ConvertFrom-Json
Assert-Demo ($failedManifest.state -eq 'Failed' -and $null -eq $failedManifest.unsigned -and $failedManifest.files.Count -eq 0) `
    'partial build cannot retain a Ready manifest'
Assert-DemoThrows { Read-DemoReadyManifest $failedBuild } 'failed build cannot be signed'

$signFailure = New-DemoFixture 'sign-failure'
$before = Read-DemoReadyManifest $signFailure
$failedSigner = {
    param($path)
    [IO.File]::AppendAllText($path, '-partial-signature')
    return 7
}
$verifySuccess = { param($path, $policy) return 0 }
Assert-DemoThrows { Invoke-DemoSignTransaction $signFailure ('A' * 40) $failedSigner $verifySuccess } 'partial signer failure propagated'
$after = Read-DemoReadyManifest $signFailure
Assert-Demo ($after.unsigned -and $after.files[0].sha256 -eq $before.files[0].sha256 -and $after.lastSigningAttempt.status -eq 'Failed') `
    'partial signer failure preserves original driver and coherent manifest'

$successSigner = {
    param($path)
    [IO.File]::AppendAllText($path, '-synthetic-signature')
    return 0
}
$policyFailure = New-DemoFixture 'policy-failure'
$failedVerifier = {
    param($path, $policy)
    if ($policy -eq 'pa')
    {
        return 1
    }
    return 2
}
Assert-DemoThrows { Invoke-DemoSignTransaction $policyFailure ('B' * 40) $successSigner $failedVerifier } 'policy failure is not signing success'
$signed = Read-DemoReadyManifest $policyFailure
Assert-Demo (-not $signed.unsigned -and $signed.signing.applied -and $signed.signing.authenticodeVerifyExit -eq 1 -and
    $signed.signing.hostKernelPolicyVerifyExit -eq 2) 'applied bytes and failed policy exits remain distinct'

$verifyFailure = New-DemoFixture 'verify-exception'
$before = Read-DemoReadyManifest $verifyFailure
Assert-DemoThrows { Invoke-DemoSignTransaction $verifyFailure ('C' * 40) $successSigner { throw 'Injected verification failure' } } `
    'verification exception propagated'
$after = Read-DemoReadyManifest $verifyFailure
Assert-Demo ($after.unsigned -and $after.files[0].sha256 -eq $before.files[0].sha256) 'verification exception cannot publish staged driver'

$signSuccess = New-DemoFixture 'sign-success'
$result = Invoke-DemoSignTransaction $signSuccess ('D' * 40) $successSigner $verifySuccess
Assert-Demo ($result.state -eq 'Ready' -and -not (Read-DemoReadyManifest $signSuccess).unsigned) 'successful model signing publishes coherent files'

$externalChange = New-DemoFixture 'external-change'
$alterOtherFile = {
    param($path)
    [IO.File]::AppendAllText((Join-Path ([IO.Path]::GetDirectoryName($path)) 'KnSnapshotDemo.pdb'), '-external-change')
    return 7
}
Assert-DemoThrows { Invoke-DemoSignTransaction $externalChange ('E' * 40) $alterOtherFile $verifySuccess } 'out-of-band file change reported'
$failed = Get-Content -LiteralPath (Join-Path $externalChange 'build-manifest.json') -Raw | ConvertFrom-Json
Assert-Demo ($failed.state -eq 'Failed' -and $null -eq $failed.unsigned) 'recovery cannot restore Ready over changed input files'

$publicationFailure = New-DemoFixture 'publication-failure'
$before = Read-DemoReadyManifest $publicationFailure
$holding = [pscustomobject]@{ Pin = $null }
$blockPublication = {
    param($path, $policy)
    if ($policy -eq 'kp')
    {
        $manifestPath = Join-Path ([IO.Path]::GetDirectoryName($path)) 'build-manifest.json'
        $holding.Pin = [IO.File]::Open($manifestPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    }
    return 0
}.GetNewClosure()
try
{
    Assert-DemoThrows { Invoke-DemoSignTransaction $publicationFailure ('F' * 40) $successSigner $blockPublication } `
        'manifest publication failure after SYS replacement is reported'
    $hash = (Get-FileHash -LiteralPath (Join-Path $publicationFailure 'KnSnapshotDemo.sys') -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Demo ($hash -eq $before.files[0].sha256) 'failed publication rolls back original SYS bytes'
    Assert-DemoThrows { Read-DemoReadyManifest $publicationFailure } 'uncertain signing publication cannot appear Ready'
}
finally
{
    if ($null -ne $holding.Pin)
    {
        $holding.Pin.Dispose()
    }
}

$partialReplacement = New-DemoFixture 'partial-replacement'
$before = Read-DemoReadyManifest $partialReplacement
$publisher = ${function:Publish-DemoSignedDriver}
try
{
    function Publish-DemoSignedDriver([string]$Staged, [string]$Driver, [string]$Backup)
    {
        # Model ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: original exists only as backup.
        [IO.File]::Move($Driver, $Backup)
        throw 'Injected partial replacement failure'
    }
    Assert-DemoThrows { Invoke-DemoSignTransaction $partialReplacement ('A' * 40) $successSigner $verifySuccess } `
        'partial filesystem replacement failure reported'
    $restored = Read-DemoReadyManifest $partialReplacement
    Assert-Demo ($restored.unsigned -and $restored.files[0].sha256 -eq $before.files[0].sha256) `
        'original SYS restored when replacement failed before returning'
}
finally
{
    Set-Item -LiteralPath Function:Publish-DemoSignedDriver -Value $publisher
}

Write-Host "Script-model checks passed=$script:demoPassed. No certificate, signing tool, SCM, service or driver was used."
