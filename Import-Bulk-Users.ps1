#Import active directory module for running AD cmdlets
Import-Module activedirectory

#Store the data from ADUsers.csv in the $ADUsers variable
$Users = Import-csv c:\ps\bulk_import.csv

#Loop through each row containing user details in the CSV file 
foreach ($User in $Users) {
    # Read user data from each field in each row
    # the username is used more often, so to prevent typing, save that in a variable
   $Username       = $User.SamAccountName

    # Check to see if the user already exists in AD
    if (Get-ADUser -F {SamAccountName -eq $Username}) {
         #If user does exist, give a warning
         Write-Warning "A user account with username $Username already exist in Active Directory."
    }
    else {
        # User does not exist then proceed to create the new user account

        # create a hashtable for splatting the parameters
        $userProps = @{
            SamAccountName             = $User.SamAccountName                   
            Path                       = $User.path      
            GivenName                  = $User.GivenName 
            Surname                    = $User.Surname
            Initials                   = $User.Initials
            Name                       = $User.Name
            DisplayName                = $User.DisplayName
            UserPrincipalName          = $user.UserPrincipalName 
            Department                 = $User.Department
            Description                = $User.Description
            Office                     = $User.Office
            OfficePhone                = $User.OfficePhone
            EmailAddress               = $User.EmailAddress
            StreetAddress              = $User.StreetAddress
            POBox                      = $User.POBox
            City                       = $User.City
            State                      = $User.State
	    Country		       = $User.Country
            PostalCode                 = $User.PostalCode
            Title                      = $User.Title
            Company                    = $User.Company
            AccountPassword            = (ConvertTo-SecureString $User.password -AsPlainText -Force) 
            Enabled                    = $true
            ChangePasswordAtLogon      = $true
        }   #end userprops   

         New-ADUser @userProps
       #  Write-Host "The user account $User is created." -ForegroundColor Cyan
   

    } #end else
   
}