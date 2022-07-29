function Get-LoggedUser
{
    [CmdletBinding()]
    param
    (
        [string[]]$ComputerName 
    )
    foreach ($comp in $ComputerName)
    {
        if ((Test-NetConnection $comp -WarningAction SilentlyContinue).PingSucceeded -eq $true) 
            {  
                $output = @{'Computer' = $comp }
                $output.UserName = (Get-WmiObject -Class win32_computersystem -ComputerName $comp).UserName
            }
            else
            {
                $output = @{'Computer' = $comp }
                         $output.UserName = "offline"
            }
         [PSCustomObject]$output 
    }
}
$computers = (Get-AdComputer -Filter {enabled -eq "true"} -SearchBase 'OU=WKS Computers,OU=Computers,OU=IT,OU=Istanbul,OU=Turkey,OU=Europe,DC=firatboyan,DC=local').Name
Get-LoggedUser $computers |ft -AutoSize