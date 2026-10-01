param([string[]]$IpAddress)
$ErrorActionPreference = 'Stop'
if (-not $IpAddress) {
    $IpAddress = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' -and $_.AddressState -eq 'Preferred' } | Select-Object -ExpandProperty IPAddress -Unique)
}
if (-not $IpAddress) { throw 'No LAN IPv4 address found. Supply -IpAddress with your PC LAN address.' }
$parsedAddresses = @($IpAddress | ForEach-Object {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($_, [ref]$parsed)) { throw "Invalid IP address: $_" }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'ShareHub supports IPv4 only.' }
    if ($parsed.ToString() -notmatch '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { throw 'Use a private LAN or loopback IPv4 address.' }
    $parsed.ToString()
})
$san = '2.5.29.17={text}DNS=localhost&' + (($parsedAddresses | ForEach-Object { 'IPAddress=' + $_ }) -join '&')
# If setup fails midway, remove only certificates created by this invocation.
$authority = $null
$certificate = $null
try {
$authority = New-SelfSignedCertificate -Type Custom -Subject ('CN=ShareHub Local CA ' + [Guid]::NewGuid().ToString('N')) -FriendlyName 'ShareHub Local CA' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeyUsage CertSign,CRLSign -NotAfter (Get-Date).AddDays(365) -TextExtension @('2.5.29.19={critical}{text}CA=true&pathlength=0')
$certificate = New-SelfSignedCertificate -Type Custom -Subject 'CN=ShareHub Local HTTPS' -FriendlyName 'ShareHub Local HTTPS' -Signer $authority -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature,KeyEncipherment -NotAfter (Get-Date).AddDays(90) -TextExtension @($san, '2.5.29.37={text}1.3.6.1.5.5.7.3.1', '2.5.29.19={critical}{text}CA=false')
Export-Certificate -Cert $authority -FilePath (Join-Path $PSScriptRoot 'root-cert.cer') -Type CERT | Out-Null
[System.IO.File]::WriteAllText((Join-Path $PSScriptRoot 'tls-cert.txt'), $certificate.Thumbprint, [System.Text.Encoding]::ASCII)
Write-Host ('HTTPS certificate created for: ' + ($parsedAddresses -join ', '))
Write-Host 'The server and local CA private keys remain nonexportable in your Windows user certificate store.'
Write-Host 'Transfer root-cert.cer to your iPhone using a trusted channel. Verify the certificate fingerprint before installing it.'
Write-Host 'Explicitly install the CA certificate on the iPhone and enable full trust in Settings > General > About > Certificate Trust Settings before using HTTPS. Do not bypass certificate warnings.'
Write-Host ('SHA-1 store identifier: ' + $certificate.Thumbprint)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try { Write-Host ('SHA-256 public CA fingerprint: ' + ([BitConverter]::ToString($sha256.ComputeHash($authority.RawData))).Replace('-', ':')) } finally { $sha256.Dispose() }
} catch {
    if ($certificate) { Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $certificate.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue }
    if ($authority) { Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $authority.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue }
    throw
}
