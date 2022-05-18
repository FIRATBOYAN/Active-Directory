$currentDomain =(Get-ADDomainController).hostname

        $defaultNamingContext = (([ADSI]"LDAP://$currentDomain/rootDSE").defaultNamingContext)
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=computer)(dNSHostName=$currentDomain))"
        $searcher.SearchRoot = "LDAP://" + $currentDomain + "/OU=Domain Controllers," + $defaultNamingContext
        $dcObjectPath = $searcher.FindAll() | %{$_.Path}

        # DFSR
        $searchDFSR = New-Object DirectoryServices.DirectorySearcher
        $searchDFSR.Filter = "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))"
        $searchDFSR.SearchRoot = $dcObjectPath
        $dfsrSubObject = $searchDFSR.FindAll()

        if ($dfsrSubObject -ne $null){

            [pscustomobject]@{
                "SYSVOL Replication Mechanism"= "DFSR"
                "Path:"= $dfsrSubObject|%{$_.Properties."msdfsr-rootpath"}
            }

        }

        # FRS
        $searchFRS = New-Object DirectoryServices.DirectorySearcher
        $searchFRS.Filter = "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))"
        $searchFRS.SearchRoot = $dcObjectPath
        $frsSubObject = $searchFRS.FindAll()

        if($frsSubObject -ne $null){

            [pscustomobject]@{
                "SYSVOL Replication Mechanism" = "FRS"
                "Path" = $frsSubObject|%{$_.Properties.frsrootpath}
            }

        }