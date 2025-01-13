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