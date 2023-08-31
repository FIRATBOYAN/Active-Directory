$path="C:\ADSecurityCheckList"
Write-Host "Checking C:\ADSecurityCheckList Folder Exist" -ForegroundColor Blue

if(Test-Path -Path $path){
Write-Host "Path exist" -ForegroundColor Green


}
else{

write-host "Path not exist" -ForegroundColor Red
write-host "Path is creating" -ForegroundColoR Blue
md $path
}

$date = Get-Date -UFormat %d%m%Y
if(Test-Path -Path $path\$date){
Write-Host "Path exist" -ForegroundColor Green


}
else{

write-host "Path not exist" -ForegroundColor Red
write-host "Path is creating" -ForegroundColoR Blue
md $path\$date
}

$finalpath="$path\$date"
Write-Host "$finalpath created" -ForegroundColor Blue

"---All Object In Active Directory---"  > $finalpath\1-AllObject.csv 
(Get-ADObject -filter * -Properties *).count >> $finalpath\1-AllObject.csv 

"---All User In Active Directory---" >$finalpath\2-AllUser.csv
(Get-Aduser -Filter * -Properties *).count >>$finalpath\2-AllUser.csv 

"---Disable Users In Active Directory---" >$finalpath\3-DisableUser.csv 
$disableuser=Get-ADUser -Filter {enabled -eq $false} | select Name,SamaccountName,SID >>$finalpath\3-DisableUser.csv 


"---Inactive Users In Active Directory---" >$finalpath\4-InactiveUser.csv 
$inactiveuser=Get-ADUser -Filter {-not ( lastlogontimestamp -like "*") -and (enabled -eq $true)} | select Name,SamaccountName,SID >>$finalpath\4-InactiveUser.csv 

"---Admin Count 1 Users In Active Directory---" >$finalpath\5-admincount.csv 
$admincount=Get-ADUser -Filter {admincount -eq 1} | select Name,SamaccountName,SID >>$finalpath\5-admincount.csv 

"---Password Never Expire Users In Active Directory---" >$finalpath\6-PasswordNeverExpireUser.csv
$passwordneverexpire=Get-ADUser -Filter {PasswordNeverExpires -eq $true} | select Name,SamaccountName,SID >>$finalpath\6-PasswordNeverExpireUser.csv 

"---Password Not Require Users In Active Directory---" >$finalpath\7-PasswordNotRequiredUser.csv 
$passwordnotrequired= Get-ADUser -Filter {passwordnotrequired -eq $true} | select Name,SamaccountName,SID >>$finalpath\7-PasswordNotRequiredUser.csv 

"---Kerberos DES Encryption Enabled Users In Active Directory---" >$finalpath\8-DesEnabledUser.csv
$desenabled=Get-ADUser -Filter {UserAccountControl -band 0x200000} >>$finalpath\8-DesEnabledUser.csv 


 "---Admin Count 1(Privilige Users) and AccountNotDelegated Users In Active Directory---" >$finalpath\9-SensitiveNotDelegatedUser.csv 
$sensitiveandnotdelegated=Get-ADUser -Filter {(AdminCount -eq 1) -and (AccountNotDelegated -eq $false)} | Select-Object Samaccountname >>$finalpath\9-SensitiveNotDelegatedUser.csv 

"---Users Dont Require Kerberos Pre Auth In Active Directory---" >$finalpath\10-DontPreKreAuthUser.csv 
$notkrepreauthent=Get-ADUser -Filter {UserAccountControl -band 4194304}| Select-Object SamaccountName >>$finalpath\10-DontPreKreAuthUser.csv 


$sid = (Get-ADDomain).domainsid 
$sid500 = $sid.ToString() + "-500" 

"---RID 500 Account (Administrator) In Active Directory---" >$finalpath\11-AdministratorAccount.csv 
$administrator=Get-ADUser -Identity $sid500 -Properties * |select name,samaccountname,PasswordLastSet >>$finalpath\11-AdministratorAccount.csv 


$sid501=$sid.ToString() + "-501"
"---RID 501 Account (Guest) In Active Directory---" >$finalpath\12-GuestAccount.csv 
$guest= Get-ADUser -Identity $sid501 |select name,samaccountname,PasswordLastSet >>$finalpath\12-GuestAccount.csv 



"---All Computers In Active Directory---" >$finalpath\13-Allcomputer.csv 
(Get-Adcomputer -Filter * -Properties *).count >>$finalpath\13-Allcomputer.csv 

"---Disable Computers In Active Directory---" >$finalpath\14-DisableComputers.csv 
$disablecomputer=Get-ADcomputer -Filter {enabled -eq $false} | select Name,SamaccountName,SID >>$finalpath\14-DisableComputers.csv 

"---Password Not Required Computers In Active Directory---" >$finalpath\15-PasswordNotrequiredComputers.csv 
$passwordnotrequired= Get-ADcomputer -Filter {passwordnotrequired -eq $true} | select Name,SamaccountName,SID >>$finalpath\15-PasswordNotrequiredComputers.csv 



"---Domain Admins Group Members ---" >$finalpath\16-domainadmins.csv 
$domainadmins=Get-ADGroupMember -Identity "Domain Admins" -Recursive |select name,samaccountname,objectClass >>$finalpath\16-domainadmins.csv 

"---Enterprise Admins Group Members ---" > $finalpath\17-enterpriseadmins.csv 
$enterpriseadmins=Get-ADGroupMember -Identity "Enterprise Admins" -Recursive |select name,samaccountname,objectClass >> $finalpath\17-enterpriseadmins.csv 

"---Schema Admins Group Members ---" >$finalpath\18-schemaadmins.csv
$schemaadmins=Get-ADGroupMember -Identity "Schema Admins" -Recursive |select name,samaccountname,objectClass >> $finalpath\18-schemaadmins.csv

"---Administrators Group Members ---" >$finalpath\19-administrators.csv
$administrators=Get-ADGroupMember -Identity "Administrators" -Recursive |select name,samaccountname,objectClass >> $finalpath\19-administrators.csv

"---Backup Operators Group Members ---" >$finalpath\20-backupoperators.csv
$backupoperators=Get-ADGroupMember -Identity "Backup Operators" -Recursive |select name,samaccountname,objectClass >> $finalpath\20-backupoperators.csv

"---Print Operators Group Members ---" >$finalpath\21-printoperators.csv
$printoperators=Get-ADGroupMember -Identity "Print Operators" -Recursive |select name,samaccountname,objectClass >> $finalpath\21-printoperators.csv

"---Server Operators Group Members ---" >$finalpath\22-serveroperators.csv
$serveroperators=Get-ADGroupMember -Identity "Server Operators" -Recursive |select name,samaccountname,objectClass >> $finalpath\22-serveroperators.csv

"---Group Policy Creator Owners Group Members ---" >$finalpath\23-gpocreator.csv
$gpocreator=Get-ADGroupMember -Identity "Group Policy Creator Owners" -Recursive |select name,samaccountname,objectClass >> $finalpath\23-gpocreator.csv

"---Protected Users Group Members ---" >$finalpath\24-protectedusers.csv
$protectedusers=Get-ADGroupMember -Identity "Protected Users" -Recursive |select name,samaccountname,objectClass >> $finalpath\24-protectedusers.csv
"No NTLM , DES or RC4 not Using , TGT 4 hours" >>$finalpath\24-protectedusers.csv

"---Empty Group  ---" >$finalpath\25-emptygroup.csv
$emptygroup=Get-ADGroup -LDAPFilter "(!(member=*))" | select Name  >> $finalpath\25-emptygroup.csv



"---KRBTGT Account Details ---" >$finalpath\26-krbtgt.csv
$krbtgt=Get-ADUser -Identity "krbtgt" -Properties * | select name,samaccountname,passwordlastset >> $finalpath\26-krbtgt.csv

"---SMB V1  ---" > $finalpath\27-smbv1.csv
$smb1control=Get-SmbServerConfiguration |select EnableSMB1Protocol >> $finalpath\27-smbv1.csv
"False Meaning: SMBV1 Not Installed" >> $finalpath\27-smbv1.csv


"---Latest Update Date  ---" >$finalpath\28-update.csv
$updatedate=Get-HotFix  | Sort-Object InstalledOn -Descending |  select Description,HotFixID,InstalledOn -First 1  >> $finalpath\28-update.csv


"---Last Boot Time  ---" >$finalpath\29-lastboottime.csv
$lastboottime=Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime >> $finalpath\29-lastboottime.csv





$protectedusersdisting=(Get-ADGroup "Protected Users").distinguishedname

"---Admin Count 1 User in Protected Users Groups  ---" >$finalpath\30-AdminUserinProtectedUser.csv
$adminusersforprotected=Get-ADUser -LDAPFilter '(adminCount=1)' -Properties samaccountname,memberof |Where-Object {($_.MemberOf -contains $protectedusersdisting)} | Select-Object Samaccountname >>$finalpath\30-AdminUserinProtectedUser.csv
"No NTLM , DES or RC4 not Using , TGT 4 hours" >>$finalpath\30-AdminUserinProtectedUser.csv

$admincount1user=(Get-ADUser -LDAPFilter '(adminCount=1)').count

"---Admin Count 1 User Not in Protected Users Groups  ---" >$finalpath\31-AdminUsernotinProtectedUser.csv
$adminusersfornotprotected=Get-ADUser -LDAPFilter '(adminCount=1)' -Properties samaccountname,memberof |Where-Object {($_.MemberOf -notcontains $protectedusersdisting)} | Select-Object Samaccountname >>$finalpath\31-AdminUsernotinProtectedUser.csv
"No NTLM , DES or RC4 not Using , TGT 4 hours" >>$finalpath\31-AdminUsernotinProtectedUser.csv

"---Public Firewall Status---" >$finalpath\32-firewallpublic.csv
$publicfirewall=Get-NetFirewallProfile |where {$_.Name -like "Public" }|select name,Enabled,DefaultInboundAction,DefaultOutboundAction >> $finalpath\32-firewallpublic.csv
"Enabled, Inbound Block , Outbound Allow MS Baseline suggesstion">> $finalpath\32-firewallpublic.csv

"---Private Firewall Status---" >$finalpath\33-firewallprivate.csv
$privatefirewall=Get-NetFirewallProfile |where {$_.Name -like "Private" }|select name,Enabled,DefaultInboundAction,DefaultOutboundAction >> $finalpath\33-firewallprivate.csv
"Enabled, Inbound Block , Outbound Allow MS Baseline suggesstion" >> $finalpath\33-firewallprivate.csv

"---Domain Firewall Status---" >$finalpath\34-firewalldomain.csv
$Domainfirewall=Get-NetFirewallProfile |where {$_.Name -like "Domain" }|select name,Enabled,DefaultInboundAction,DefaultOutboundAction >> $finalpath\34-firewalldomain.csv
"Enabled, Inbound Block , Outbound Allow MS Baseline suggesstion" >> $finalpath\34-firewalldomain.csv


$domains = (Get-ADForest).Domains 

"---All Domain Controllers Count  ---" >$finalpath\35-domaincontrollers.csv
$domainControllers = (($domains | foreach { Get-ADDomainController -Server $_ -Filter * }).HostName).count >> $finalpath\35-domaincontrollers.csv

"---Recyle Bin Status ---" >$finalpath\36-recylebin.csv
$recyclebin=(Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' -Properties *).EnabledScopes >> $finalpath\36-recylebin.csv

"---Domain Mode  ---" >$finalpath\37-DomainMode.csv
$domainmode=Get-ADDomain | Select-Object DomainMode  >> $finalpath\37-DomainMode.csv

"---Forest Mode  ---" >$finalpath\38-ForestMode.csv
$forestmode=get-adforest | Select-Object ForestMode >> $finalpath\38-ForestMode.csv

"---Spooler Service Status  ---" >$finalpath\39-SpoolerService.csv
$spoolerservice=Get-Service -Name Spooler | select Status >> $finalpath\39-SpoolerService.csv

"---All Gpo Count  ---" >$finalpath\40-AllGpo.csv
$allgpo=(Get-GPO -All).count >> $finalpath\40-AllGpo.csv

"---UnLinked Gpo's ---" >$finalpath\41-UnlinkedGpo.csv
$unlinkedgpo=Get-GPO -All |Where-Object { $_ | Get-GPOReport -ReportType XML| Select-String -NotMatch "<LinksTo>>"} | select DisplayName  >> $finalpath\41-UnlinkedGpo.csv


"---Fine Grained Password Policy ---" >$finalpath\42-FineGrainedPolicy.csv
$finegrainedpolicy=Get-ADFineGrainedPasswordPolicy -Filter * | select Name >> $finalpath\42-FineGrainedPolicy.csv


"---Audit Policy Config ---" > $finalpath\43-AuditPolicyConfig.csv
$auditpolicyconfig=auditpol /get /category:* >> $finalpath\43-AuditPolicyConfig.csv


"MS Baseline Suggestion Audit Policy"> $finalpath\43-BaselineAuditPolicyConfigSuggestion.csv
"Account Logon	Audit Credential Validation	Success and Failure
Account Management	Audit Computer Account Management	Success
Account Management	Audit Other Account Management Events	Success
Account Management	Audit Security Group Management	Success
Account Management	Audit User Account Management	Success and Failure
Detailed Tracking	Audit PNP Activity	Success
Detailed Tracking	Audit Process Creation	Success
DS Access	Audit Directory Service Access	Success and Failure
DS Access	Audit Directory Service Changes	Success and Failure
Logon/Logoff	Audit Account Lockout	Failure
Logon/Logoff	Audit Group Membership	Success
Logon/Logoff	Audit Logon	Success and Failure
Logon/Logoff	Audit Other Logon/Logoff Events	Success and Failure
Logon/Logoff	Audit Special Logon	Success
Object Access	Audit Detailed File Share	Failure
Object Access	Audit File Share	Success and Failure
Object Access	Audit Other Object Access Events	Success and Failure
Object Access	Audit Removable Storage	Success and Failure
Policy Change	Audit Audit Policy Change	Success
Policy Change	Audit Authentication Policy Change	Success
Policy Change	Audit MPSSVC Rule-Level Policy Change	Success and Failure
Policy Change	Audit Other Policy Change Events	Failure
Privilege Use	Audit Sensitive Privilege Use	Success and Failure
System	Audit Other System Events	Success and Failure
System	Audit Security State Change	Success
System	Audit Security System Extension	Success
System	Audit System Integrity	Success and Failure" >> $finalpath\43-BaselineAuditPolicyConfigSuggestion.csv










"Duplicate SPN Checking"> $finalpath\44-DuplicateSPN.csv
$dublicatespn=Setspn -x -f >> $finalpath\44-DuplicateSPN.csv



"SMB Share on Domain Controller">$finalpath\45-SMBShare.csv
$smbshare=get-smbshare | select name,path >> $finalpath\45-SMBShare.csv

"Default Domain Password Policy"> $finalpath\46-DefaultDomainPasswordPolicy.csv
$defaultpwdpolicy=Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled >> $finalpath\46-DefaultDomainPasswordPolicy.csv



"MS Baseline Default Domain Password Policy "> $finalpath\46-BaselineDefaultDomainPasswordPolicy.csv
"Enforce password history	24
Maximum password age	60
Minimum password age	1
Minimum password length	14
Password must meet complexity requirements	Enabled
Store passwords using reversible encryption	Disabled" >>$finalpath\46-BaselineDefaultDomainPasswordPolicy.csv





"Default Domain Locked Policy">$finalpath\47-LockedPolicy.csv
$defaultlockedpolicy=Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutDuration,LockoutThreshold,LockoutObservationWindow >> $finalpath\47-LockedPolicy.csv

"MS BaselineDefault Domain Locked Policy">$finalpath\47-BaselineLockedPolicy.csv
"Account lockout duration	15
Account lockout threshold	10
Reset account lockout counter after	15" >>$finalpath\47-BaselineLockedPolicy.csv



"Site Assigned Servers">$finalpath\48-ServerSignSite.csv
$serverassignsite=(Get-ADForest).Domains | ForEach { Get-ADDomainController -Discover -DomainName $_ } | ForEach { Get-ADDomainController -Server $_.Name -filter * } | Select Site, Name, Domain  >> $finalpath\48-ServerSignSite.csv

"All Subnet">$finalpath\49-AllSubnet.csv
$allsubnet=Get-ADReplicationSubnet -filter * -Properties * | Select Name, Site >> $finalpath\49-AllSubnet.csv

"All Site"> $finalpath\50-AllSite.csv
$allsite=Get-ADReplicationSite -Filter * | select name >> $finalpath\50-AllSite.csv

"FSMO Roles">$finalpath\51-FsmoRoles.csv
$fsmoroles=netdom query fsmo >> $finalpath\51-FsmoRoles.csv

"AD Backup Status">$finalpath\52-ADbackups.csv
$backups=repadmin /showbackup * >> $finalpath\52-ADbackups.csv


"All Operating System">$finalpath\53-OperatingSystemAll.csv
$operatingsystem=Get-ADComputer -Filter * -Properties * | Select-Object Name,OperatingSystem,OperatingSystemVersion >> $finalpath\53-OperatingSystemAll.csv

"OS Summary">$finalpath\54-OSSummary.csv
$os2=Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count   >> $finalpath\54-OSSummary.csv

$7days= (Get-Date).AddDays(-7)

"Last 7 Days Created Users">$finalpath\55-last7dayscreateduser.csv
$last7dayscreateduser=Get-ADUser -Filter {whencreated -ge $7days} | select Name,SamaccountName,SID >> $finalpath\55-last7dayscreateduser.csv

"Last 7 Days Changed Users">$finalpath\56-last7dayschangeduser.csv
$last7dayschangeduser=Get-ADUser -Filter {whenchanged -ge $7days} | select Name,SamaccountName,SID >> $finalpath\56-last7dayschangeduser.csv

"Top 5 Logon Count For User">$finalpath\57-Top5logoncount.csv
$logoncount=get-aduser -Filter * -Properties Logoncount,Name,SamaccountName | Select-Object Name,SamaccountName,LogonCount | Sort-Object logoncount -Descending |select -First 5 >> $finalpath\57-Top5logoncount.csv


"Last 7 Days Created Computers">$finalpath\58-last7dayscreatedcomputer.csv
$last7dayscreatedcomputer=Get-ADcomputer -Filter {created -ge $7days} | select Name,SamaccountName,SID >> $finalpath\58-last7dayscreatedcomputer.csv

"Computer Logon Count Top 5">$finalpath\59-logoncountcomputer.csv
$logoncountcomp=Get-ADComputer -Filter * -Properties Name,LogonCount| Select-Object Name,LogonCount | Sort-Object logoncount -Descending |select -First 5 >> $finalpath\59-logoncountcomputer.csv

"Different  Computer Account(User Account Control not 4096)">$finalpath\60-differentcomputeraccount.csv
$differentcomputeraccount=Get-ADComputer -Filter "useraccountcontrol -ne 4096" -Properties useraccountcontrol |select name,useraccountcontrol >> $finalpath\60-differentcomputeraccount.csv


"Domain Controllers Info">$finalpath\61-Alldomaincontrollersinfo.csv
$Alldomaincontrollersinfo=Get-ADDomainController -Filter * | Select Domain,Name,IPv4Address,IsGlobalCatalog,Site,OperatingSystem >> $finalpath\61-Alldomaincontrollersinfo.csv

"All Ethernet Interfaces">$finalpath\62-allethernetinterfaces.csv
$allethernetinterfaces=netsh interface ipv4 show interfaces >> $finalpath\62-allethernetinterfaces.csv

"Service Accounts running on Services">$finalpath\63-serviceaccountservices.csv
$serviceaccountservices=Get-WmiObject win32_service | where {($_.startname -ne "LocalSystem") -and ($_.startname -ne "NT AUTHORITY\NetworkService") -and ($_.startname -ne "NT AUTHORITY\NETWORK SERVICE") -and ($_.startname -ne "NT AUTHORITY\LocalService") } | FT name, startname, startmode >> $finalpath\63-serviceaccountservices.csv

"Installed Roles">$finalpath\64-installedroles.csv
$installedroles=Get-WindowsFeature | Where {$_.installed -eq "True"} >> $finalpath\64-installedroles.csv

"Installed Applications"> $finalpath\65-installedapplication.csv
$installedapplication=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName,Publisher,InstallDate  >> $finalpath\65-installedapplication.csv


"--NTP Configuration Registry">$finalpath\66-ntpserver.csv
$ntpserver=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\ | select Type, NtpServer  >> $finalpath\66-ntpserver.csv

"--NTP Configuration">>$finalpath\66-ntpserver.csv
$ntpstatus=w32tm /query /configuration >> $finalpath\66-ntpserver.csv
"--NTP Status">>$finalpath\66-ntpserver.csv
$ntpstatus2=w32tm /query /status >> $finalpath\66-ntpserver.csv


"Replication Queue">$finalpath\67-replicationqueue.csv
$replicationhealth=repadmin /queue >> $finalpath\67-replicationqueue.csv

"Replication Summary">$finalpath\68-replicationsummary.csv
$replicationhealth2=repadmin /replsummary >> $finalpath\68-replicationsummary.csv

"DC Diag Checking">$finalpath\69-dcdiag.csv
$dcdiag=dcdiag /v /c /d /e >> $finalpath\69-dcdiag.csv

"All AD Service Account">$finalpath\70-serviceaccount.csv
$serviceaccount= Get-ADServiceAccount -Filter * -Properties * |select name,samaccountname,Enabled >> $finalpath\70-serviceaccount.csv



$forest=(Get-ADDomain).forest
$msdcs="_msdcs." + $forest

"Forest SERVICE LOCATION INFO">$finalpath\71-forestsrv.csv
$forestsrv=Get-DnsServerResourceRecord -RRType SRV -ZoneName $forest >> $finalpath\71-forestsrv.csv

"MSDCS SERVICE LOCATION INFO">$finalpath\72-msdcsrv.csv
$msdcsrv=Get-DnsServerResourceRecord -RRType SRV -ZoneName $msdcs >> $finalpath\72-msdcsrv.csv

"FOREST NAME SERVER INFO">$finalpath\73-forestns.csv
$forestns=Get-DnsServerResourceRecord -RRType NS -ZoneName $forest >> $finalpath\73-forestns.csv

"MSDCS NAME SERVER INFO">$finalpath\74-msdcns.csv
$msdcns=Get-DnsServerResourceRecord -RRType NS -ZoneName $msdcs  >> $finalpath\74-msdcns.csv


$forest=(Get-ADDomain).forest

$eD = Get-ADDomain -Identity $forest
$DC = $eD.DNSRoot

$Root = Get-ADObject -Server $DC -SearchBase (Get-ADDomain -Identity $DC -Server $DC).DistinguishedName -LDAPFilter '(objectClass=domain)'


"ROOT Domain ACL Report"> $finalpath\75-rootacl.csv
$rootaccess=(Get-Acl -Path "AD:$root").Access | select ActiveDirectoryRights,AccessControlType,IdentityReference  >> $finalpath\75-rootacl.csv


"ADMIN SD HOLDER ACL Report">$finalpath\76-adminsdholderacl.csv
$adminsdholderaccess=(Get-Acl -Path "AD:CN=AdminSDHolder,CN=System,$root").Access | select ActiveDirectoryRights,AccessControlType,IdentityReference >> $finalpath\76-adminsdholderacl.csv

"Under C: Users Info">$finalpath\77-usersfolder.csv
$usersfolder=Get-ChildItem -Path C:\Users | select Name,LastWriteTime >> $finalpath\77-usersfolder.csv


"Administrator Account Last LogonDate">$finalpath\78-AdministratorAccountLastLogon.csv 
$administratoraccountlastlogon=Get-ADUser -Identity $sid500 -Properties * |select name,samaccountname,LastLogonDate >>$finalpath\78-AdministratorAccountLastLogon.csv 



$privilegegroups=Get-ADgroup -Filter * -Properties * | where {$_.Admincount -eq 1} | select samaccountname

$priviligeincomputers=foreach($groupsname in $privilegegroups){
$computeraccountfind=Get-ADGroupMember -Identity $groupsname.samaccountname | where {($_.objectclass -eq "computer")} | select Name
[PSCustomObject]@{
"Group Name"=$groupsname.samaccountname
"Computers Name"=$computeraccountfind.name
}

}

"Computers In Privilige Groups (Admin Count 1 Groups)">$finalpath\79-ComputerAccountinPriviligeGroup.csv 
$priviligeincomputers | Out-File -FilePath  $finalpath\79-ComputerAccountinPriviligeGroup.csv 

"User In Privilige Groups but User is disable (Admin Count 1 Groups)">$finalpath\80-priviligeuserdisable.csv 
$priviligeuserdisable=Get-ADUser -Filter * -Properties * | where {($_.Admincount -eq 1)-and ($_.Enabled -eq $false) -and ($_.samaccountname -ne "krbtgt")} | select samaccountname >>$finalpath\80-priviligeuserdisable.csv 


$InactiveDays = 90
$Days = (Get-Date).Adddays(-($InactiveDays))
"Admin Accounts Not Login 90 Days">$finalpath\81-enabledadminaccountinactive.csv 
$enabledadminaccountinactive=Get-ADUser -Filter {LastLogonTimeStamp -lt $Days -and enabled -eq $true -and admincount -eq 1 }  -Properties LastLogonTimeStamp | select Name,SamaccountName >>$finalpath\81-enabledadminaccountinactive.csv 


$Recentlydays = 7
$Days = (Get-Date).Adddays(-($Recentlydays))
"Admin Accounts Created in 7 Days">$finalpath\82-recentlycreatedpriviligeaccount.csv 
$recentlycreatedpriviligeaccount=Get-ADUser -Filter {WhenCreated -gt $Days -and enabled -eq $true -and admincount -eq 1 } -Properties *| Select-Object Samaccountname,WhenCreated >>$finalpath\82-recentlycreatedpriviligeaccount.csv 



  $UsersInAdminGroups = (Get-ADGroup -LDAPFilter '(adminCount=1)') | 
    ForEach-Object {
        # Get all users from all admin groups recursively
        Get-ADGroupMember $_ -Recursive | Where-Object {$_.ObjectClass -eq 'User'}
    }  | Sort-Object distinguishedname | Select-Object -Unique

    $admincountuser=Get-ADUser -LDAPFilter '(adminCount=1)' |select Samaccountname
    ForEach($admincountuser in $admincountuser.samaccountname){
    
    if(($admincountuser -notin $UsersInAdminGroups.samaccountname)-and ($admincountuser -ne "krbtgt")){
    Write-Output  $admincountuser | Out-File -FilePath $finalpath\83-nomoreadmin.csv -Append
    } 
    
    

    }  


    "User Not In Primary Group Domain Users">$finalpath\84-userprimaryid.csv 
$userprimaryid=Get-ADUser -Filter '(primaryGroupID -ne 513)' -Properties * |Where-Object {$_.samaccountname -ne "Guest"} |select Samaccountname >>$finalpath\84-userprimaryid.csv 

"Computers Not In Primary Group Domain Computers">$finalpath\85-computerprimaryid.csv 
$computerprimaryid=Get-ADcomputer -Filter '(primaryGroupID -ne 515 -and primaryGroupID -ne 516)' -Properties * |select Samaccountname,primaryGroupID >>$finalpath\85-computerprimaryid.csv 





$eD = Get-ADDomain -Identity $forest
$DC = $eD.DNSRoot
$Root = Get-ADObject -Server $DC -SearchBase (Get-ADDomain -Identity $DC -Server $DC).DistinguishedName -LDAPFilter '(objectClass=domain)'

$dcdist=$root.DistinguishedName

$domaincontrollerlist=Get-ADComputer -Filter * -SearchBase "OU=Domain Controllers,$dcdist" | select DistinguishedName

$domaincontrollerdistinguished= $domaincontrollerlist.DistinguishedName

$dcownerlists=foreach($dcownerdist in $domaincontrollerdistinguished){
$finddcowner=(Get-Acl -Path "AD:$dcownerdist").Owner
[PSCustomObject]@{
"Distinguished Name"=$dcownerdist
"Owner"=$finddcowner
}
}


$dcownerlists| Out-File -FilePath $finalpath\86-dcownerlist.csv 




"MSDS Machine Account Quota Info">$finalpath\87-msdsmachineaccountQuota.csv 
$msdsmachineaccountQuota=Get-ADObject -Identity ((Get-ADDomain).distinguishedname) `
             -Properties ms-DS-MachineAccountQuota  >>$finalpath\87-msdsmachineaccountQuota.csv 

"GPO settings (User Right: Add workstations to domain configured with only high-privileged group(s)/account(s)) linked to Domain Controllers" >>$finalpath\87-msdsmachineaccountQuota.csv 






"Prevent Enabling Lock Screen Camera Checking">$finalpath\88-NolockScreenCamera.csv
$NolockScreenCamera=Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Personalization\' | select NoLockScreenCamera >>$finalpath\88-NolockScreenCamera.csv
"
If Result 1 Enabled
How To Enable= Computer Configuration\Administrative Templates\Control Panel\ Prevent enabling lock screen camera" >>$finalpath\88-NolockScreenCamera.csv



"Prevent Enabling Lock Screen Slide Showing">$finalpath\89-NoLockScreenSlideshow.csv
$NolockScreenSlideShow=Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Personalization\' | select NoLockScreenSlideshow >>$finalpath\89-NoLockScreenSlideshow.csv
"

If Result 1 Enabled
How To Enable= Computer Configuration\Administrative Templates\Control Panel\ Prevent enabling lock screen slide show">>$finalpath\89-NoLockScreenSlideshow.csv



"WDigest Authentication">$finalpath\90-wdigest.csv
$wdigest=Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\" | select UseLogonCredential >>$finalpath\90-wdigest.csv

"If Result 0 Disabled

Windows XP was the first operating system to introduce the WDigest protocol.
This protocol is enabled by default on Windows systems and helps clients authenticate to Hypertext Transfer Protocol (HTTP)
and Simple Authentication Security Layer (SASL) applications by sending cleartext credentials. Not Store in LSASS
  
How To Disable =Computer Configuration\Preferences\Registry
HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\  UseLogonCredential REG_DWORD = 0" >>$finalpath\90-wdigest.csv



"Insecure Logon Checking">$finalpath\91-AllowInsecureGuestAuth.csv
$AllowInsecureGuestAuth=Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\" | Select AllowInsecureGuestAuth >>$finalpath\91-AllowInsecureGuestAuth.csv
"
If Result 0 Disabled

This policy setting determines if the SMB client will allow insecure guest logons to an SMB server. Not Enable to guest logon to SMB Share

This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.

Insecure guest logons are used by file servers to allow unauthenticated access to shared folders.

Since insecure guest logons are unauthenticated, important security features such as SMB Signing and SMB Encryption are disabled.

How to Disabled =Computer Configuration\Administrative Templates\Network\LanManWorkstation Enable insecure guest logons

">>$finalpath\91-AllowInsecureGuestAuth.csv




"Autorun  Checking">$finalpath\92-NoAutorun.csv
$NoAutorun=Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" | select NoAutorun >>$finalpath\92-NoAutorun.csv
"

If Result 1 Do not execute any autorun commands

When media containing an autorun command is inserted, the system will automatically execute the program without user intervention
Maybe It has vulneratibility things thats why do not execute autorun commands.

How To Disable= Computer Configuration\Administrative Templates\Windows Components\AutoPlay Policies 
Set the default behavior for AutoRun Do not execute any autorun commands 

 


">>$finalpath\92-NoAutorun.csv


"Autorun Drive Type  Checking">$finalpath\93-NoDriveTypeAutoRun.csv
$NoDriveTypeAutoRun=Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ | select NoDriveTypeAutoRun >>$finalpath\93-NoDriveTypeAutoRun.csv

"

If Result 255 All Drivers

Turn Off Autorun policy to All Drivers

How To Configure = Computer Configuration\Administrative Templates\Windows Components\AutoPlay Policies 
Turn off Autoplay All Drivers


">>$finalpath\93-NoDriveTypeAutoRun.csv



"Hardened UNC Checking">$finalpath\94-hardenUNC.csv
$hardenUNC=Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths >>$finalpath\94-hardenUNC.csv


"
If Result has 
\\*\NETLOGON : RequireMutualAuthentication=1, RequireIntegrity=1
\\*\SYSVOL   : RequireMutualAuthentication=1, RequireIntegrity=1

SYSVOL and NETLOGON Share has secure UNC path 

This policy setting configures secure access to UNC paths.

How to Active Policy =Computer Configuration\Administrative Templates\Network\Network Provider

Hardened UNC Paths 

\\*\NETLOGON : RequireMutualAuthentication=1, RequireIntegrity=1
\\*\SYSVOL   : RequireMutualAuthentication=1, RequireIntegrity=1 


">>$finalpath\94-hardenUNC.csv



"LDAP Require Signing Checking">$finalpath\95-requiresigning.csv
$requiresigning=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" | Select ldapserverintegrity >>$finalpath\95-requiresigning.csv

"

If Result is 2 Require Signing

This policy setting determines whether the Lightweight Directory Access Protocol (LDAP) server requires 
LDAP clients to negotiate data signing.
Unsigned network traffic is susceptible to man-in-the-middle attacks,
where an intruder captures packets between the server and the client device and modifies them before forwarding them to the client device. 


How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
Domain controller: LDAP server signing requirements  Require Signing

Be careful if you enable this policy 
Client devices that don't support LDAP signing can't run LDAP queries against the domain controllers.

You should Enable Policy Computer Configuration\Windows Settings \Local Policy \ Security Options \
Network Security: LDAP client signing requirements  Require Signing to client


" >>$finalpath\95-requiresigning.csv


"Lan Manager Authentication Level Checking">$finalpath\96-lanmanagerlevel.csv

$lanmanagerlevel=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" |select lmcompatibilitylevel >>$finalpath\96-lanmanagerlevel.csv
"

If Result 5 response only NTLMV2

 
Send LM & NTLM responses: Clients use LM and NTLM authentication and never use NTLMv2 session security; domain controllers accept LM, NTLM, and NTLMv2 authentication.
Send LM & NTLM - use NTLMv2 session security if negotiated: Clients use LM and NTLM authentication and use NTLMv2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLMv2 authentication.
Send NTLM response only: Clients use NTLM authentication only and use NTLMv2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLMv2 authentication.
Send NTLMv2 response only: Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLMv2 authentication.
Send NTLMv2 response only\\refuse LM: Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it; domain controllers refuse LM (accept only NTLM and NTLMv2 authentication).
Send NTLMv2 response only\\refuse LM & NTLM: Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it; domain controllers refuse LM and NTLM (accept only NTLMv2 authentication).



How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \

Network security: LAN Manager authentication level Send NTLMv2 response only\\refuse LM & NTLM

Be careful If you have NTLM,LM traffic , which will be down

Event Id: 4624 Source Port 49194

">>$finalpath\96-lanmanagerlevel.csv



"Admin Approval Mode">$finalpath\97-adminapprovalmode.csv
$adminapprovalmode=Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" | SELECT filteradministratortoken >>$finalpath\97-adminapprovalmode.csv
##Must 1 Enable Admin Approval Mode
"
If Result 1 Enable

This policy setting determines the behavior of Admin Approval Mode for the built-in administrator account.
 When the Admin Approval Mode is enabled, the local administrator account functions like a standard user account,
  but it has the ability to elevate privileges without logging on by using a different account. 
In this mode, any operation that requires elevation of privilege displays a prompt that allows the administrator to permit or deny the elevation of privilege


How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \

User Account Control: Admin Approval Mode for the Built-in Administrator account Enabled




" >>$finalpath\97-adminapprovalmode.csv



"Admin Approval Mode Admin User">$finalpath\98-adminapprovalforadmin.csv
$adminapprovalforadmin=Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" | SELECT ConsentPromptBehaviorAdmin >>$finalpath\98-adminapprovalforadmin.csv
##Admin Approval Mode for Admin 2 Consenst for secure desktop
"

If Result 2 Prompt for consent on the secure desktop

When an operation requires elevation of privilege, 
the user is prompted on the secure desktop to select Permit or Deny. 
If the user selects Permit, the operation continues with the user's highest available privilege.*


How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
Prompt for consent on the secure desktop


">>$finalpath\98-adminapprovalforadmin.csv







"Admin Approval Mode Normal User">$finalpath\99-adminapprovalforuser.csv
$adminapprovalforuser=Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" | SELECT ConsentPromptBehaviorUser >>$finalpath\99-adminapprovalforuser.csv
##Admin Approval Mode for User 0 Automativally DeNY

"

If Result 0 Automatically deny elevation requests


This option returns an Access denied error message to standard users 
when they try to perform an operation that requires elevation of privilege.

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
User Account Control: Behavior of the elevation prompt for standard users -Automatically deny elevation requests


">>$finalpath\99-adminapprovalforuser.csv


"Time Inactivity Checking">$finalpath\100-timeinactivitymachine.csv
$timeinactivitymachine=Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" | select inactivitytimeoutsecs >>$finalpath\100-timeinactivitymachine.csv
##TimeOutSec 900 
"
If Result 900 15 minutes

When user is inactivite 15 minutes automatically lock computers

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \

Interactive logon: Machine inactivity limit  900

">>$finalpath\100-timeinactivitymachine.csv



"LM Hash Next Password">$finalpath\103-Lmhashnextpassword.csv
$Lmhashnextpassword=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" |select NoLmHash >>$finalpath\103-Lmhashnextpassword.csv


"If result 1 Enabled


This security setting determines if, at the next password change, the LAN Manager (LM) hash value for the new password is stored.
 The LM hash is relatively weak and prone to attack, as compared with the cryptographically stronger Windows NT hash.
 Since the LM hash is stored on the local computer in the security database the passwords can be compromised if the security database is attacked.


 
How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \

Network security: Do not store LAN Manager hash value on next password change--Enabled


">>$finalpath\103-Lmhashnextpassword.csv



"Plain Text Password for 3 Party SMB Servers">$finalpath\101-unencrtyptedpassword3party.csv
$unencrtyptedpassword3party=Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters |select EnablePlainTextPassword >>$finalpath\101-unencrtyptedpassword3party.csv
##Default Disable but must 0 dont sent unencrypted password to 3.party SMB Servers

"
If Result 0 Disable

If this security setting is enabled, the Server Message Block (SMB) redirector is allowed to send plaintext passwords to non-Microsoft SMB servers that do not support password encryption during authentication.

Sending unencrypted passwords is a security risk.

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \

Microsoft network client: Send unencrypted password to third-party SMB servers --- Disable


">>$finalpath\101-unencrtyptedpassword3party.csv


"Digital Sign Client">$finalpath\102-digitalsignclient.csv
$digitalsignclient=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" |select RequireSecuritySignature >>$finalpath\102-digitalsignclient.csv

"


If Result 1 Enabled Always



All Windows operating systems support both a client-side SMB component and a server-side SMB component.
 To take advantage of SMB packet signing, both the client-side SMB component and server-side SMB component that are involved in a communication must have SMB packet signing either enabled or required. On Windows 2000 and later operating systems, enabling or requiring packet signing for client and server-side SMB components is controlled by the following four policy settings:
Microsoft network client: Digitally sign communications (always) - Controls whether or not the client-side SMB component requires packet signing.
Microsoft network client: Digitally sign communications (if server agrees) - Controls whether or not the client-side SMB component has packet signing enabled.
Microsoft network server: Digitally sign communications (always) - Controls whether or not the server-side SMB component requires packet signing.
Microsoft network server: Digitally sign communications (if client agrees) - Controls whether or not the server-side SMB component has packet signing enabled.
If server-side SMB signing is required, a client will not be able to establish a session with that server, unless it has client-side SMB signing enabled.
 By default, client-side SMB signing is enabled on workstations, servers, and domain controllers.
  Similarly, if client-side SMB signing is required, that client will not be able to establish a session with servers that do not have packet signing enabled. By default, server-side SMB signing is enabled only on domain controllers.


  First Off all open If client agree after than always

  careful do it with if client agress Client server and Domain control must be

  
How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
  Microsoft network client: Digitally sign communications (always)-Enabled
  (if server agrees)-enabled


">>$finalpath\102-digitalsignclient.csv

"Digital Sign Server">$finalpath\103-digitalsigncserver.csv
$digitalsigncserver=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" |select requiresecuritysignature >>$finalpath\103-digitalsigncserver.csv


"

If Result 1 Enabled Always



All Windows operating systems support both a client-side SMB component and a server-side SMB component.
 To take advantage of SMB packet signing, both the client-side SMB component and server-side SMB component that are involved in a communication must have SMB packet signing either enabled or required. On Windows 2000 and later operating systems, enabling or requiring packet signing for client and server-side SMB components is controlled by the following four policy settings:
Microsoft network client: Digitally sign communications (always) - Controls whether or not the client-side SMB component requires packet signing.
Microsoft network client: Digitally sign communications (if server agrees) - Controls whether or not the client-side SMB component has packet signing enabled.
Microsoft network server: Digitally sign communications (always) - Controls whether or not the server-side SMB component requires packet signing.
Microsoft network server: Digitally sign communications (if client agrees) - Controls whether or not the server-side SMB component has packet signing enabled.
If server-side SMB signing is required, a client will not be able to establish a session with that server, unless it has client-side SMB signing enabled.
 By default, client-side SMB signing is enabled on workstations, servers, and domain controllers.
  Similarly, if client-side SMB signing is required, that client will not be able to establish a session with servers that do not have packet signing enabled. By default, server-side SMB signing is enabled only on domain controllers.


  --First Off all open If client agree after than always!!!!!!!!!!!!!!!!



  
How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
  Microsoft network server: Digitally sign communications (always)-Enabled
  (if server agrees)-enabled
">>$finalpath\103-digitalsigncserver.csv



"Anonymous Account and Share">$finalpath\104-restrictanonymoussamaccountsandshares.csv
$restrictanonymoussamaccountsandshares=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" | select restrictanonymous >>$finalpath\104-restrictanonymoussamaccountsandshares.csv
#Must Be 1 

"
If Result 1 Restricted

Windows allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares. This is convenient, for example, when an administrator wants to grant access to users in a trusted domain that does not maintain a reciprocal trust. 
If you do not want to allow anonymous enumeration of SAM accounts and shares, then enable this policy.

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
Network access: Do not allow anonymous enumeration of SAM accounts and shares-Enabled


">>$finalpath\104-restrictanonymoussamaccountsandshares.csv


"Anonymous Sam Accounts">$finalpath\105-restrictanonymoussamaccounts.csv
$restrictanonymoussamaccounts=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" | select restrictanonymoussam >>$finalpath\105-restrictanonymoussamaccounts.csv
#Must Be 1 
"
If Result 1 Restricted


Windows allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares.
 This is convenient, for example, when an administrator wants to grant access to users in a trusted domain that does not maintain a reciprocal trust.



How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
Network access: Do not allow anonymous enumeration of SAM accounts -Enabled

">>$finalpath\105-restrictanonymoussamaccounts.csv



"Secure RPC Checking">$finalpath\106-securerpc.csv
$securerpc=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |select fEncryptRPCTraffic >>$finalpath\106-securerpc.csv
##MUSTBE 1 Enabled

"

If Result 1 Enabled

Specifies whether a Remote Desktop Session Host server requires secure RPC communication with all clients or allows unsecured communication.
You can use this setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.

How To Enable= Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security
Require secure RPC communication Enabled

">>$finalpath\106-securerpc.csv


"Secure RPC Encryption Level Checking">$finalpath\107-securerpcencryptionlevel.csv
$securerpcencryptionlevel=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |select MinEncryptionLevel >>$finalpath\107-securerpcencryptionlevel.csv
##MUSTBE 3 High Level
"
If Result 3 High Level


Specifies whether a Remote Desktop Session Host server requires secure RPC communication with all clients or allows unsecured communication.
You can use this setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.

How To Enable= Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security
Set client connection encryption level--High Level


">>$finalpath\107-securerpcencryptionlevel.csv



"Always Ask Password Upon Connection">$finalpath\108-PromptForPassword.csv
$PromptForPassword=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |select fPromptForPassword >>$finalpath\108-PromptForPassword.csv

"

If Result 1 Prompt Password

This policy setting specifies whether Remote Desktop Services always prompts the client for a password upon connection.
You can use this setting to enforce a password prompt for users logging on to Remote Desktop Services, even if they already provided the password in the Remote Desktop Connection client.
By default, Remote Desktop Services allows users to automatically log on by entering a password in the Remote Desktop Connection client.
If you enable this policy setting, users cannot automatically log on to Remote Desktop Services by supplying their passwords in the Remote Desktop Connection client. They are prompted for a password to log on.

How To Enable= Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security
Always prompt for password upon connection---Enabled

">>$finalpath\108-PromptForPassword.csv


"Dont Allow Password to be Saved">$finalpath\109-Notallowpasswordsave.csv
$Notallowpasswordsave=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" |select DisablePasswordSaving >>$finalpath\109-Notallowpasswordsave.csv
##Must Be 1 Enabled

"
If Result 1 Dont Allow Password to be Saved




Controls whether passwords can be saved on this computer from Remote Desktop Connection.
If you enable this setting the password saving checkbox in Remote Desktop Connection will be disabled and users will no longer be able to save passwords. 

You should apply this also to client which will make RDP connection to Domain Controller


How To Enable= Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security
Do not allow passwords to be saved-Enabled



">>$finalpath\109-Notallowpasswordsave.csv





"Windows Smart Screen Checking">$finalpath\110-windowssmartscreen.csv
$windowssmartscreen=Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\" | select EnableSmartScreen,ShellSmartScreenLevel >>$finalpath\110-windowssmartscreen.csv


"
If Result 1 Enabled and Warn must be

This policy allows you to turn Windows Defender SmartScreen on or off. 
 SmartScreen helps protect PCs by warning users before running potentially malicious programs downloaded from the Internet.  
 This warning is presented as an interstitial dialog shown before running an app that has been downloaded from the Internet and is unrecognized or known to be malicious.  No dialog is shown for apps that do not appear to be suspicious.
Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.

How To Enable= Computer Configuration\Administrative Templates\Windows Components\File Explorer
Configure Windows Defender SmartScreen-Enabled

">>$finalpath\110-windowssmartscreen.csv




"Powershell Logging Checking">$finalpath\111-powershellogging.csv
$powershellogging=Get-ChildItem -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" >>$finalpath\111-powershellogging.csv
"

If Result 
ModuleLogging                  EnableModuleLogging : 1                                                                                                                                                                                                           
ScriptBlockLogging             EnableScriptBlockLogging : 1                                                                                                                                                                                                      
Transcription                  EnableTranscripting    : 1                                                                                                                                                                                                        
                               OutputDirectory        : c:\pslogs                                                                                                                                                                                                
                               EnableInvocationHeader : 1  

Logging enable and OutputDirectory C:\Pslogs

This will give to log powershell commands


How To Enable= Computer Configuration\Administrative Templates\Windows Components\Windows Powershell


Turn On Module Logging = Module Names *
Turn on Powershell Script Block Logging = Enabled
Turn on Powershell Transcription= Enabled
Output Directory = Where log will stay



">>$finalpath\111-powershellogging.csv

"Registry Policies Updating">$finalpath\112-registrypolicyprocess.csv
$registrypolicyprocess=Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" >>$finalpath\112-registrypolicyprocess.csv

"
If Result 
NoBackgroundPolicy : 0
NoGPOListChanges   : 0


This policy setting determines when registry policies are updated.
This policy setting affects all policies in the Administrative Templates folder and any other policies that store values in the registry.
 It overrides customized settings that the program implementing a registry policy set when it was installed.


 How To Enable= Computer Configuration\Administrative Templates\System\Group Policy
 Configure registry policy processing

Process even if the Group Policy objects have not changed = True
Do not apply during periodic background processing = False



">>$finalpath\112-registrypolicyprocess.csv



"WinRM Client Traffic and Authentication">$finalpath\113-winrmclient.csv
$winrmclient=Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" |select AllowBasic,AllowUnencryptedTraffic,AllowDigest >>$finalpath\113-winrmclient.csv
"

If Result 

AllowBasic=0
 AllowUnencryptedTraffic=0
  AllowDigest=0

  Basic and Digest Authentication is Disable
  UnencryptedTraffic is Disable

  How To Enable= Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client
  Allow Basic authentication---Disabled
Allow unencrypted traffic---Disabled
Disallow Digest authentication--Enabled



">>$finalpath\113-winrmclient.csv



"WinRM Service Traffic and Authentication">$finalpath\114-winrmservice.csv
$winrmservice=Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" |select AllowBasic,AllowUnencryptedTraffic,DisableRunAs >>$finalpath\114-winrmservice.csv
"
If Result

AllowBasic              : 0
AllowUnencryptedTraffic : 0
DisableRunAs            : 1

Basic and Digest Authentication is Disable
RunAs Service Disable = Enable


  How To Enable= Computer Configuration\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service

   Allow Basic authentication---Disabled
Allow unencrypted traffic---Disabled
Disallow WinRM from storing RunAs credentials---Enabled


">>$finalpath\114-winrmservice.csv


"Event Log Size">$finalpath\115-eventlogmaxsize.csv
$eventlogmaxsize=Get-ChildItem -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\" >>$finalpath\115-eventlogmaxsize.csv
"

How To Configure= Computer Configuration\Administrative Templates\Windows Components\Event Log Service
Application
Security 
System


">>$finalpath\115-eventlogmaxsize.csv

"NTLM Session Security">$finalpath\116-ntlmsessionsecurity.csv
$ntlmsessionsecurity=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\" |Select NtlmMinClientSec,NtlmMinServerSec >>$finalpath\116-ntlmsessionsecurity.csv
"

If Result 537395200 Require NTLMv2 session security, Require 128bit encryption


It Depends on LAN Manager authentication level NTLMV2,
Issued on NTLMV2 security

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \

Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
Network security: Minimum session security for NTLM SSP based (including secure RPC) servers


Require NTLMv2 session security, Require 128bit encryption


">>$finalpath\116-ntlmsessionsecurity.csv


"Null Session Fall Back">$finalpath\117-ntlmsessionsecurity.csv
$nullsessionfallback=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\" | SELECT allownullsessionfallback >>$finalpath\117-ntlmsessionsecurity.csv

"
If Result 0 Disabled


This policy affects session security during the authentication process between devices running Windows Server 2008 R2 and Windows 7 and later
 and those devices running earlier versions of the Windows operating system. 
 For computers running Windows Server 2008 R2 and Windows 7 and later,
  services running as Local System require a service principal name (SPN) to generate the session key.
   However, if Network security: Allow Local System to use computer identity for NTLM is set to disabled,
    services running as Local System will fall back to using NULL session authentication when they transmit data to servers running versions of Windows earlier than Windows Vista or
     Windows Server 2008. NULL session doesn't establish a unique session key for each authentication; 
and thus, it can't provide integrity or confidentiality protection.

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \
Network security: Allow LocalSystem NULL session fallback---Disabled


">>$finalpath\117-ntlmsessionsecurity.csv


"Advanced Audit Policy">$finalpath\118-auditsubcategory.csv
$auditsubcategory=Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\" | select scenoapplylegacyauditpolicy >>$finalpath\118-auditsubcategory.csv
"

If Result 1 Enabled

For Advanced Audit Policy it is required , override audit policy category settings

How To Active Policy = Computer Configuration\Windows Settings \Local Policy \ Security Options \


Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings -- -Enabled

">>$finalpath\118-auditsubcategory.csv



$domaincontrollerou=(Get-ADDomain).DomainControllersContainer
$allgpoenabled=(Get-GPInheritance -Target $domaincontrollerou).InheritedGpoLinks 

$allgpoenabled >>$finalpath\119-DomainControllerOUGpos.csv


Gpresult /H $finalpath\120-DomainControllerGpresult.html

Write-Host "End--------------------------------%100" -ForegroundColor Green