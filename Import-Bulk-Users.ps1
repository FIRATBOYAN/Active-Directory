# Import the Active Directory module for running AD cmdlets
Import-Module ActiveDirectory

# Store the data from ADUsers.csv in the $Users variable
$Users = Import-Csv "C:\PS\BULK USERS\Import-Bulk-Users.csv"

# Loop through each row containing user details in the CSV file 
foreach ($User in $Users) {
    # Read user data from each field in each row
    # The username is used more often, so to prevent typing, save that in a variable
    $Username = $User.SamAccountName

    # Check to see if the user already exists in AD
    if (Get-ADUser -Filter "SamAccountName -eq '$Username'") {
        # If user does exist, give a warning
        Write-Warning "A user account with username $Username already exists in Active Directory."
    }
    else {
        # User does not exist then proceed to create the new user account

        # Create a hashtable for splatting the parameters
        $userProps = @{
            Name                 = $User.Name
            SamAccountName       = $User.SamAccountName
            GivenName            = $User.GivenName
            Surname              = $User.Surname
            Initials             = $User.Initials
            DisplayName          = $User.DisplayName
            UserPrincipalName    = $User.UserPrincipalName
            Department           = $User.Department
            Description          = $User.Description
            Office               = $User.Office
            OfficePhone          = $User.OfficePhone
            EmailAddress         = $User.EmailAddress
            StreetAddress        = $User.StreetAddress
            POBox                = $User.POBox
            City                 = $User.City
            State                = $User.State
            Country              = $User.Country
            PostalCode           = $User.PostalCode
            Title                = $User.Title
            Company              = $User.Company
            AccountPassword      = (ConvertTo-SecureString $User.password -AsPlainText -Force)
            Path                 = $User.path
            Enabled              = $true
            ChangePasswordAtLogon = $true
        } # end userProps

        New-ADUser @userProps
        Write-Host "The user account $Username is created." -ForegroundColor Cyan
    } # end else
} # end foreach
