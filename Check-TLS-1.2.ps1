<#
.SYNOPSIS
    Audits the configuration state of all SSL/TLS protocol versions in
    SChannel, and verifies the .NET Framework TLS configuration values
    on the local server.

.DESCRIPTION
    This is a read-only diagnostic script. It distinguishes between three
    possible states for each SChannel protocol:

        - Explicitly Enabled   : Registry key exists with Enabled = 1
                                 and DisabledByDefault != 1
        - Explicitly Disabled  : Registry key exists with Enabled = 0 or
                                 DisabledByDefault = 1
        - Not configured       : Registry key does not exist; the operating
                                 system applies its built-in defaults

    Important: On modern Windows versions (Windows Server 2022 and 2025,
    Windows 11), the absence of an explicit registry override does not
    mean the protocol is disabled at runtime. The operating system applies
    secure defaults: TLS 1.2 and TLS 1.3 are enabled, while SSL 2.0/3.0
    and TLS 1.0/1.1 are disabled. This script reports the registry state
    only; it does not perform live protocol negotiation.

    The script also checks the .NET Framework 4.x registry values
    (SystemDefaultTlsVersions and SchUseStrongCrypto) under both the
    64-bit and 32-bit (WOW6432Node) hives. On .NET Framework 4.7 and
    later, the absence of these values is harmless because the runtime
    already defers to the operating system by default.

    This script complements Set-TLS-1.2.ps1 and is intended primarily
    for hardened or legacy servers (Windows Server 2016/2019, or Entra
    Connect servers) where explicit registry overrides are expected.

    Reference:
    https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-tls-enforcement
    https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

.NOTES
    Author: Firat Boyan
    The script requires read access to HKLM. Administrative rights are
    recommended but not strictly required for read-only registry access.
#>

# --- SChannel protocol check ---

$tlsProtocols = @(
    'SSL 2.0',
    'SSL 3.0',
    'TLS 1.0',
    'TLS 1.1',
    'TLS 1.2',
    'TLS 1.3'
)

Write-Host ""
Write-Host "Checking SChannel TLS/SSL protocol configuration...`n" -ForegroundColor Cyan

foreach ($protocol in $tlsProtocols) {

    foreach ($side in @('Server','Client')) {

        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$side"

        $status = 'Not configured (OS default)'
        $color  = 'Yellow'

        if (Test-Path $path) {
            $key           = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $enabled       = $key.Enabled
            $disabledByDef = $key.DisabledByDefault

            if ($enabled -eq 1 -and $disabledByDef -ne 1) {
                $status = 'Explicitly Enabled'
                $color  = 'Green'
            }
            elseif ($enabled -eq 0 -or $disabledByDef -eq 1) {
                $status = 'Explicitly Disabled'
                $color  = 'Red'
            }
        }

        Write-Host ("{0,-8} - {1,-6} : {2}" -f $protocol, $side, $status) -ForegroundColor $color
    }
    Write-Host "---------------------------" -ForegroundColor Gray
}

# --- .NET Framework TLS configuration check ---

Write-Host "`nChecking .NET Framework TLS settings...`n" -ForegroundColor Cyan

$dotnetPaths = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
)
$dotnetValues = @('SystemDefaultTlsVersions','SchUseStrongCrypto')

foreach ($path in $dotnetPaths) {
    Write-Host $path -ForegroundColor Gray
    foreach ($name in $dotnetValues) {
        $item = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        if ($item -and $item.$name -eq 1) {
            Write-Host ("  {0,-26} : 1 (Explicitly Enabled)" -f $name) -ForegroundColor Green
        }
        else {
            Write-Host ("  {0,-26} : Not configured (.NET 4.7+ uses OS default)" -f $name) -ForegroundColor Yellow
        }
    }
    Write-Host "---------------------------" -ForegroundColor Gray
}

Write-Host "`nAudit complete." -ForegroundColor Cyan
