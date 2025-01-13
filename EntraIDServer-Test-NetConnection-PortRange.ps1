$DomainControllers = @(
    "SRVDC01.domain.local",
    "SRVDC02.domain.local"
)

foreach ($DC in $DomainControllers) {
    foreach ($Port in 49152..65535) {
        $check = Test-NetConnection -ComputerName $DC -Port $Port -WarningAction SilentlyContinue
        if ($check.TcpTestSucceeded) {
            Write-Host ($DC + " on port " + $Port + ": Connection Successful") -ForegroundColor Green
        } else {
            Write-Host ($DC + " on port " + $Port + ": Connection Failed") -ForegroundColor Red
        }
    }
}


