Get-ADUser -Filter * -SearchBase "OU=Old Users,OU=IT,OU=Istanbul,OU=Turkey,OU=Europe,DC=firatboyan,DC=local" -Properties * | Select-Object UserPrincipalName | export-csv -path "\\firatboyan.local\SYSVOL\firatboyan.local\scripts\OLD USERS\IST-IT-OLD-USR-GRP-01.csv"


 # Import AD Module
Import-Module ActiveDirectory

# Import the data from CSV file and assign it to variable
$Users = Import-Csv "\\firatboyan.local\SYSVOL\firatboyan.local\scripts\OLD USERS\IST-IT-OLD-USR-GRP-01.csv"

# Specify target group where the users will be added to
# You can add the distinguishedName of the group. For example: CN=Pilot,OU=Groups,OU=Company,DC=exoip,DC=local
$Group = "IST-IT-OLD-USR-GRP-01" 

foreach ($User in $Users) {
    # Retrieve UPN
    $UPN = $User.UserPrincipalName

    # Retrieve UPN related SamAccountName
    $ADUser = Get-ADUser -Filter "UserPrincipalName -eq '$UPN'"

    # User from CSV not in AD
    if (-not $ADUser) {
        Write-Host "$UPN does not exist in AD" -ForegroundColor Red
    }
    else {
        # Retrieve AD user group membership
        $ExistingGroups = Get-ADPrincipalGroupMembership $ADUser.SamAccountName

        # User already member of group
        if ($ExistingGroups.Name -contains $Group) {
            Write-Host "$UPN already exists in $Group" -ForeGroundColor Yellow
        }
        else {
            # Add user to group
            Add-ADGroupMember -Identity $Group -Members $ADUser.SamAccountName
            Write-Host "Added $UPN to $Group" -ForeGroundColor Green
        }
    }
    } 