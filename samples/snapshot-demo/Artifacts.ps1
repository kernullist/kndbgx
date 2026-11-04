Set-StrictMode -Version Latest

function Get-DemoFileNames
{
    return @('KnSnapshotDemo.sys', 'KnSnapshotDemo.pdb', 'KnSnapshotDemoCtl.exe', 'KnSnapshotDemoCtl.pdb',
        'KnSnapshotDemoFixtures.exe', 'KnSnapshotDemoFixtures.pdb')
}

function Open-DemoArtifactLock([string]$Directory)
{
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    return [IO.File]::Open((Join-Path $Directory '.artifact.lock'), [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
}

function Write-DemoJsonAtomic([string]$Path, [object]$Value)
{
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $stream = $null
    try
    {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12))
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        if ([IO.File]::Exists($Path))
        {
            [IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value)
        }
        else
        {
            [IO.File]::Move($temporary, $Path)
        }
    }
    finally
    {
        if ($null -ne $stream)
        {
            $stream.Dispose()
        }
        if ([IO.File]::Exists($temporary))
        {
            [IO.File]::Delete($temporary)
        }
    }
}

function Get-DemoFileRecords([string]$Directory)
{
    foreach ($name in (Get-DemoFileNames))
    {
        $file = Get-Item -LiteralPath (Join-Path $Directory $name) -ErrorAction Stop
        if ($file.PSIsContainer)
        {
            throw "Expected a file: $name"
        }
        [ordered]@{
            file = $name
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
}

function Assert-DemoFileRecords([string]$Directory, [object[]]$Recorded)
{
    $expected = @(Get-DemoFileRecords $Directory)
    if ($Recorded.Count -ne $expected.Count)
    {
        throw 'Build manifest file count mismatch.'
    }
    foreach ($record in $expected)
    {
        $matches = @($Recorded | Where-Object { $_.file -ceq $record.file })
        if ($matches.Count -ne 1 -or $matches[0].bytes -ne $record.bytes -or $matches[0].sha256 -cne $record.sha256)
        {
            throw "Build manifest identity mismatch: $($record.file)"
        }
    }
}

function Read-DemoReadyManifest([string]$Directory)
{
    $manifest = Get-Content -LiteralPath (Join-Path $Directory 'build-manifest.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($manifest.schema -ne 'kndbgx.snapshot-demo.build.v2' -or $manifest.state -ne 'Ready' -or
        $manifest.unsigned -isnot [bool] -or $manifest.liveDriverTested -isnot [bool])
    {
        throw 'A complete v2 Ready build manifest is required. Rebuild incomplete or older output.'
    }
    Assert-DemoFileRecords $Directory @($manifest.files)
    return $manifest
}

function Invoke-DemoBuildTransaction([string]$Directory, [object]$Manifest, [scriptblock]$Build)
{
    $lock = Open-DemoArtifactLock $Directory
    $manifestPath = Join-Path $Directory 'build-manifest.json'
    try
    {
        $Manifest.state = 'Building'
        $Manifest.unsigned = $null
        $Manifest.files = @()
        Write-DemoJsonAtomic $manifestPath $Manifest
        & $Build $Directory | ForEach-Object {
            Write-Information -MessageData $_ -InformationAction Continue
        }
        $Manifest.files = @(Get-DemoFileRecords $Directory)
        $Manifest.state = 'Ready'
        $Manifest.unsigned = $true
        Write-DemoJsonAtomic $manifestPath $Manifest
        return $Manifest
    }
    catch
    {
        $failure = $_
        $Manifest.state = 'Failed'
        $Manifest.unsigned = $null
        $Manifest.files = @()
        try
        {
            Write-DemoJsonAtomic $manifestPath $Manifest
        }
        catch
        {
            Write-Warning 'Build failure could not be recorded. Only a new Ready manifest authorizes use of this output.'
        }
        throw $failure
    }
    finally
    {
        $lock.Dispose()
    }
}

function Publish-DemoSignedDriver([string]$Staged, [string]$Driver, [string]$Backup)
{
    [IO.File]::Replace($Staged, $Driver, $Backup)
}

function Invoke-DemoSignTransaction([string]$Directory, [string]$Thumbprint, [scriptblock]$Sign, [scriptblock]$Verify)
{
    $lock = Open-DemoArtifactLock $Directory
    $driver = Join-Path $Directory 'KnSnapshotDemo.sys'
    $manifestPath = Join-Path $Directory 'build-manifest.json'
    $suffix = [Guid]::NewGuid().ToString('N')
    $staged = Join-Path $Directory ('.KnSnapshotDemo.' + $suffix + '.sys')
    $backup = Join-Path $Directory ('.KnSnapshotDemo.' + $suffix + '.backup.sys')
    $source = $null
    $committed = $false
    $signExit = $null
    try
    {
        $source = Read-DemoReadyManifest $Directory
        $pending = $source | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        $pending.state = 'Signing'
        $pending.unsigned = $null
        Write-DemoJsonAtomic $manifestPath $pending
        [IO.File]::Copy($driver, $staged, $false)
        $signExit = & $Sign $staged
        if ($signExit -isnot [int] -or $signExit -ne 0)
        {
            throw "Driver signing failed: $signExit"
        }
        $authenticodeExit = & $Verify $staged 'pa'
        $kernelPolicyExit = & $Verify $staged 'kp'
        if ($authenticodeExit -isnot [int] -or $kernelPolicyExit -isnot [int])
        {
            throw 'Signature verification returned an invalid exit status.'
        }
        Assert-DemoFileRecords $Directory @($source.files)
        Publish-DemoSignedDriver $staged $driver $backup
        $ready = $source | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        $ready.state = 'Ready'
        $ready.unsigned = $false
        $ready.files = @(Get-DemoFileRecords $Directory)
        $ready | Add-Member -NotePropertyName signing -NotePropertyValue ([ordered]@{
            certificateThumbprint = $Thumbprint.ToUpperInvariant()
            applied = $true
            authenticodeVerifyExit = $authenticodeExit
            hostKernelPolicyVerifyExit = $kernelPolicyExit
            guestLoadTested = $false
        }) -Force
        Write-DemoJsonAtomic $manifestPath $ready
        $committed = $true
        if ($authenticodeExit -ne 0 -or $kernelPolicyExit -ne 0)
        {
            throw 'Signing succeeded, but host policy verification failed. The manifest records both exit codes.'
        }
        return $ready
    }
    catch
    {
        $failure = $_
        if ($null -ne $source -and -not $committed)
        {
            try
            {
                if ([IO.File]::Exists($backup))
                {
                    if ([IO.File]::Exists($driver))
                    {
                        [IO.File]::Replace($backup, $driver, [System.Management.Automation.Language.NullString]::Value)
                    }
                    else
                    {
                        [IO.File]::Move($backup, $driver)
                    }
                }
                $source | Add-Member -NotePropertyName lastSigningAttempt -NotePropertyValue ([ordered]@{
                    status = 'Failed'
                    signExit = $signExit
                    guestLoadTested = $false
                }) -Force
                try
                {
                    Assert-DemoFileRecords $Directory @($source.files)
                }
                catch
                {
                    $source.state = 'Failed'
                    $source.unsigned = $null
                    $source.files = @()
                }
                Write-DemoJsonAtomic $manifestPath $source
            }
            catch
            {
                Write-Warning 'Signing recovery could not publish the original manifest. Rebuild this output before use.'
            }
        }
        throw $failure
    }
    finally
    {
        try
        {
            if ([IO.File]::Exists($staged))
            {
                [IO.File]::Delete($staged)
            }
            if ([IO.File]::Exists($backup) -and $committed)
            {
                [IO.File]::Delete($backup)
            }
        }
        finally
        {
            $lock.Dispose()
        }
    }
}
