param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$SdkVersion = '10.0.26100.0'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Artifacts.ps1')
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
$codeSigning = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
    ForEach-Object { $_.EnhancedKeyUsages } | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count -ne 0
if (-not $certificate.HasPrivateKey -or -not $codeSigning -or $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -lt (Get-Date))
{
    throw 'The explicitly selected certificate must be valid, have a private key and have the Code Signing EKU.'
}
$kitRoot = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10
$signtool = Join-Path $kitRoot "bin\$SdkVersion\x64\signtool.exe"
if (-not (Test-Path -LiteralPath $signtool))
{
    throw "signtool.exe is unavailable for SDK $SdkVersion."
}
$output = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\artifacts\snapshot-demo\$Configuration"))
$signAction = {
    param([string]$path)
    $PSNativeCommandUseErrorActionPreference = $false
    & $signtool sign /fd SHA256 /s My /sha1 $CertificateThumbprint $path | ForEach-Object {
        Write-Information -MessageData $_ -InformationAction Continue
    }
    $signExit = [int]$LASTEXITCODE
    if ($signExit -eq 0)
    {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ine $CertificateThumbprint)
        {
            throw 'The staged signature does not belong to the explicitly selected certificate.'
        }
    }
    return $signExit
}.GetNewClosure()
$verifyAction = {
    param([string]$path, [string]$policy)
    $PSNativeCommandUseErrorActionPreference = $false
    & $signtool verify "/$policy" /v $path | ForEach-Object {
        Write-Information -MessageData $_ -InformationAction Continue
    }
    return [int]$LASTEXITCODE
}.GetNewClosure()
$result = Invoke-DemoSignTransaction $output $CertificateThumbprint $signAction $verifyAction
Write-Host "Signature applied. Authenticode exit=$($result.signing.authenticodeVerifyExit); host kernel-policy exit=$($result.signing.hostKernelPolicyVerifyExit)."
Write-Host 'Certificate trust, boot settings and guest load policy were not changed. Guest loading remains untested.'
