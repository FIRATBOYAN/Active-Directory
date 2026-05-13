<#
.SYNOPSIS
    Enables TLS 1.2 enforcement on Windows Server for .NET Framework 4.x
    and SChannel layers.

.DESCRIPTION
    This script implements the registry configuration recommended by
    Microsoft for Entra Connect (Azure AD Connect) servers. The settings
    enforce TLS 1.2 for both inbound and outbound connections at the
    SChannel and .NET Framework layers.

    Reference:
    https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-tls-enforcement

.NOTES
    Author: Firat Boyan
    A reboot is required after running this script for the changes to
    take effect.
#>
 
 $tlsProtocols = @(
    'SSL 2.0',
    'SSL 3.0',
    'TLS 1.0',
    'TLS 1.1',
    'TLS 1.2',
    'TLS 1.3'
)

Write-Host " "
Write-Host "Checking TLS/SSL protocol statuses...`n" -ForegroundColor Cyan

foreach ($protocol in $tlsProtocols) {
    $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
    $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

    $serverEnabled = "Disabled"
    $clientEnabled = "Disabled"
    $serverColor = "Red"
    $clientColor = "Red"

    if (Test-Path $serverPath) {
        $serverEnabledKey = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
        if ($serverEnabledKey -and $serverEnabledKey.Enabled -eq 1) {
            $serverEnabled = "Enabled"
            $serverColor = "Green"
        }
    }

    if (Test-Path $clientPath) {
        $clientEnabledKey = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
        if ($clientEnabledKey -and $clientEnabledKey.Enabled -eq 1) {
            $clientEnabled = "Enabled"
            $clientColor = "Green"
        }
    }

    Write-Host "$protocol - Server: $serverEnabled" -ForegroundColor $serverColor
    Write-Host "$protocol - Client: $clientEnabled" -ForegroundColor $clientColor
    Write-Host "---------------------------" -ForegroundColor Gray
}

Write-Host "
