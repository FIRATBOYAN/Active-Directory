$DomainControllers = @{
    "SRVDC01.firatboyan.local" = @(53,88,464,3268,3269,389,636,135,137,138,139,445,123,49443)
    "SRVDC02.firatboyan.local" = @(53,88,464,3268,3269,389,636,135,137,138,139,445,123,49443)
}

foreach ($DC in $DomainControllers.Keys) {

    foreach ($Port in $DomainControllers[$DC]) {
        $check = Test-NetConnection -ComputerName $DC -Port $Port -WarningAction SilentlyContinue
        if ($check.TcpTestSucceeded) {
            Write-Host ($DC + " on port " + $Port + ": Connection Successful") -ForegroundColor Green
        } else {
            Write-Host ($DC + " on port " + $Port + ": Connection Failed") -ForegroundColor Red
        }
    }
}

