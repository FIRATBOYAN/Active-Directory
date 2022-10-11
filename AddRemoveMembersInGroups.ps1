 # Import AD Module
Import-Module ActiveDirectory

$InOUNotGroupMemberUsers=Get-ADUser -Filter "-not (memberOf -eq 'CN=IST-IT-USR-ON-LEAVE-GRP,OU=User Groups,OU=IT,OU=Istanbul,OU=Turkey,OU=Europe,DC=firatboyan,DC=local')" -SearchBase "OU=Users On Leave,OU=IT,OU=Istanbul,OU=Turkey,OU=Europe,DC=firatboyan,DC=local" -Properties * | 
Select-Object SamAccountName 

$OutOUGroupMemberUsers=Get-ADUser -Filter "(memberOf -eq 'CN=IST-IT-USR-ON-LEAVE-GRP,OU=User Groups,OU=IT,OU=Istanbul,OU=Turkey,OU=Europe,DC=firatboyan,DC=local')" -SearchBase "DC=firatboyan,DC=local" -Properties * | Where-Object {$_.DistinguishedName -notmatch 'Users On Leave'} | 
Select-Object SamAccountName 

$Group = "IST-IT-USR-ON-LEAVE-GRP" 
foreach ($User in $InOUNotGroupMemberUsers) {

            Add-ADGroupMember -Identity $Group -Members $User -Confirm:$false
            Write-Host "Added $User to $Group" -ForeGroundColor Green
    } 
    foreach ($User in $OutOUGroupMemberUsers) {
        Remove-ADGroupMember -Identity $Group -Members $User -Confirm:$false
        Write-Host "Removed $User to $Group" -ForeGroundColor Cyan
    }