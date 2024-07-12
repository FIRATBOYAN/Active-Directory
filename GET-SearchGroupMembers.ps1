$TelifHaklariMetni = @"
##############################################
#
# Bu Script'in yazarı, Fırat Boyan'dır ve sadece amacına uygun olarak kullanılabilir.
# Bu Script, Fırat Boyan'ın izni olmadan hiçbir makalede referans gösterilmeden yayınlanamaz.
#
# www.firatboyan.com
#
##############################################
"@

Write-Output $TelifHaklariMetni

do {
    Write-Host "Onaylıyor musunuz? (Evet/Hayır): " -ForegroundColor Cyan -NoNewline
    $Onay = Read-Host
    if ($Onay -eq "Evet") {

        Write-Output ""
        
        Write-Host "Script çalıştırılıyor..." -ForegroundColor Yellow
        
        Start-Sleep -Seconds 3
        
    } elseif ($Onay -eq "Hayır") {

        Write-Output ""
        
        Write-Host "Onay verilmedi. Script'ten çıkış yapılıyor..." -ForegroundColor Yellow
        
        Start-Sleep -Seconds 3
        
        exit
    } else {
        Write-Output "Geçersiz giriş. Lütfen 'Evet' veya 'Hayır' yazınız."
    }
} until ($Onay -eq "Evet" -or $Onay -eq "Hayır")

function SearchGroup {
    while ($true) {

        Write-Host ""
        Write-Host ""

        Write-Host -NoNewline "Lütfen grup anahtar kelimesini girin: " -ForegroundColor Cyan
        $keyword = Read-Host

        $groups = @(Get-ADGroup -Filter "Name -like '*$keyword*'")

        if ($groups.Count -eq 0) {
            Write-Host "Anahtar kelimeye uygun grup bulunamadı. Lütfen doğru anahtar kelimeyi girdiğinizden emin olun." -ForegroundColor Red
            continue
        }

        Write-Host ""
        Write-Host "Anahtar kelimeye uygun gruplar:" -ForegroundColor Yellow
        $index = 1
        $groups | ForEach-Object { 
            Write-Host "$index. $($_.Name)"
            $index++
        }

        $validSelection = $false
        $groupNumber = 0
        while (-not $validSelection) {

            Write-Host -NoNewline "Hangi grubu seçmek istiyorsunuz? (numara girin): " -ForegroundColor Cyan
            $input = Read-Host
            if ([int]::TryParse($input, [ref]$groupNumber) -and $groupNumber -ge 1 -and $groupNumber -le $groups.Count) {
                $validSelection = $true
            } else {
                Write-Host "Geçersiz numara. Lütfen listeden geçerli bir numara girin." -ForegroundColor Red
            }
        }

        $selectedGroup = $groups[$groupNumber - 1]
        $groupDN = $selectedGroup.DistinguishedName

        $groupMembers = Get-ADGroupMember -Identity $groupDN
        $memberCount = @($groupMembers).Count

        Write-Host ""
        Write-Host "Members of $($selectedGroup.Name):" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Name                DistinguishedName"
        Write-Host "----                -----------------"

        if ($memberCount -eq 0) {
            Write-Host "Bu grubun üyesi yok." -ForegroundColor Yellow
        } else {
            foreach ($member in $groupMembers) {
                $adObject = Get-ADObject -Identity $member.DistinguishedName -Properties DistinguishedName
                $name = $adObject.Name
                $distinguishedName = $adObject.DistinguishedName
                Write-Host ("{0,-20} {1}" -f $name, $distinguishedName)
            }
        }

        Write-Host ""
        Write-Host ("Grup üyeleri listesi tamamlandı. Grup üye sayısı: {0}" -f $memberCount) -ForegroundColor Green

        $responseValid = $false
        while (-not $responseValid) {
            Write-Host -NoNewline "Başka bir grup için arama yapmak ister misiniz? (Evet/Hayır): " -ForegroundColor Cyan
            $response = Read-Host
            switch ($response.ToLower()) {
                "e" { 
                    $responseValid = $true 
                    break
                }
                "evet" { 
                    $responseValid = $true 
                    break
                }
                "h" { 
                    Write-Host "İşlem tamamlandı." -ForegroundColor Green 
                    return
                }
                "hayır" { 
                    Write-Host "İşlem tamamlandı." -ForegroundColor Green 
                    return
                }
                default { 
                    Write-Host "Geçersiz seçenek. Lütfen 'Evet' veya 'Hayır' girin." -ForegroundColor Red 
                }
            }
        }
    }
}

SearchGroup
