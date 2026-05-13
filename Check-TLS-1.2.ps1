<#
.SYNOPSIS
    Audits the enabled/disabled state of all SSL and TLS protocol versions
    in the Windows SChannel registry, and verifies the .NET Framework
    TLS configuration values on the local server.

.DESCRIPTION
    This is a read-only diagnostic script. It performs two checks:

    1. SChannel Protocols
       Enumerates the following protocols under
       HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
       and reports the state of each one in both Server and Client modes:

           - SSL 2.0
           - SSL 3.0
           - TLS 1.0
           - TLS 1.1
           - TLS 1.2
           - TLS 1.3

       A protocol whose 'Enabled' value is 1 is reported as Enabled (green);
       any other state is reported as Disabled (red).

    2. .NET Framework TLS Settings
       Verifies that the following values are set to 1 under both the
       64-bit and the 32-bit (WOW6432Node) .NET Framework registry hives:

           - SystemDefaultTlsVersions
           - SchUseStrongCrypto

       These settings instruct .NET Framework 4.x to defer protocol
       selection to SChannel and to use strong cryptographic primitives.

    This script complements Set-TLS-1.2.ps1 by allowing administrators
    to verify the current SChannel and .NET Framework configuration.
    It does not modify any registry settings.

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

Write-Host " "
Write-Host "Checking SChannel TLS/SSL protocol statuses...`n" -ForegroundColor Cyan

foreach ($protocol in $tlsProtocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

    $serverEnabled = "Disabled"
    $clientEnabled = "Disabled"
    $serverColor   = "Red"
    $clientColor   = "Red"

    if (Test-Path $serverPath) {
        $serverEnabledKey = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
        if ($serverEnabledKey -and $serverEnabledKey.Enabled -eq 1) {
            $serverEnabled = "Enabled"
            $serverColor   = "Green"
        }
    }

    if (Test-Path $clientPath) {
        $clientEnabledKey = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
        if ($clientEnabledKey -and $clientEnabledKey.Enabled -eq 1) {
            $clientEnabled = "Enabled"
            $clientColor   = "Green"
        }
    }

    Write-Host "$protocol - Server: $serverEnabled" -ForegroundColor $serverColor
    Write-Host "$protocol - Client: $clientEnabled" -ForegroundColor $clientColor
    Write-Host "---------------------------" -ForegroundColor Gray
}

# --- .NET Framework TLS configuration check ---

Write-Host "`nChecking .NET Framework TLS settings...`n" -ForegroundColor Cyan

$dotnetPaths = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
)
$dotnetValues = @('SystemDefaultTlsVersions', 'SchUseStrongCrypto')

foreach ($path in $dotnetPaths) {
    Write-Host $path -ForegroundColor Gray
    foreach ($name in $dotnetValues) {
        $item = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        if ($item -and $item.$name -eq 1) {
            Write-Host "  $name : 1 (Enabled)" -ForegroundColor Green
        }
        else {
            Write-Host "  $name : Missing or 0" -ForegroundColor Red
        }
    }
    Write-Host "---------------------------" -ForegroundColor Gray
}
