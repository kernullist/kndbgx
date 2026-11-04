Set-StrictMode -Version Latest

function Get-KnMSBuild
{
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere))
    {
        throw 'vswhere.exe not found. Install Visual Studio 2022 C++ Build Tools (v143).'
    }
    $vsPath = & $vswhere -latest -version '[17.0,18.0)' -products * `
        -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsPath)
    {
        throw 'No Visual Studio 2022 installation with MSBuild and the v143 C++ toolset found.'
    }
    $msbuild = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path -LiteralPath $msbuild))
    {
        throw "MSBuild executable missing: $msbuild"
    }
    return $msbuild
}
