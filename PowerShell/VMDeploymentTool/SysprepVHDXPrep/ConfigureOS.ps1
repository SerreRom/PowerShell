[xml]$XML = Get-Content C:\Windows\Panther\Unattend\ConfigureOS.xml

## STEP 1: RENAME NET ADAPTER ##
Foreach ($NetAdapter in Get-NetAdapter){
Write-Host "Renaming network adapters ..." -ForegroundColor Green -BackgroundColor Black
$NetAdapterDisplayValue = (get-netAdapterAdvancedProperty |
                          ?{($_.DisplayName -eq "Hyper-V Network Adapter Name") -and ($_.Name -eq $NetAdapter.Name)}).DisplayValue
                            Rename-NetAdapter -Name $NetAdapter.Name -NewName $NetAdapterDisplayValue
                          }


## STEP 2: SET IP ADDRESSES ##
Foreach ($NetAdapter in $XML.Configuration.NetAdapters.NetAdapter){
    Write-Host "Set IP Address on $($NetAdapter.Name)" -ForegroundColor Green -BackgroundColor Black
    if ($NetAdapter.Gw -notlike $Null){
        New-NetIPAddress -InterfaceAlias $($NetAdapter.Name) `
                         -IPAddress $($NetAdapter.IP) `
                         -PrefixLength $($NetAdapter.Netmask) `
                         -DefaultGateway $($NetAdapter.GW) `
                         -Type Unicast | Out-Null
    }
    Else {
        New-NetIPAddress -InterfaceAlias $($NetAdapter.Name) `
                         -IPAddress $($NetAdapter.IP) `
                         -PrefixLength $($NetAdapter.Netmask) `
                         -Type Unicast | Out-Null
    }

    if ($NetAdapter.DNS -notlike $Null){
        Set-DnsClientServerAddress -InterfaceAlias $($NetAdapter.Name) `
                                   -ServerAddresses $($NetAdapter.DNS) | Out-Null
    }

    if (!($NetAdapter.RegisterDNS)){
        Set-DNSClient -InterfaceAlias $($NetAdapter.Name) -RegisterThisConnectionsAddress $False
    }
}
## STEP 3: JOIN DOMAIN ##
Write-Host "Joining $($Xml.Configuration.Domain.Name) domain..." -ForegroundColor Green -BackgroundColor Black
$Account      = $XML.Configuration.Domain.Account
$Password     = ConvertTo-SecureString $XML.Configuration.Domain.Password -AsPlainText -Force
$credential   = New-Object -typename System.Management.Automation.PSCredential -argumentlist $Account, $Password
Sleep 5
Add-Computer -DomainName $XML.Configuration.Domain.Name `
             -OUPath $XML.Configuration.Domain.OUPath `
             -NewName $XML.Configuration.ComputerName `
             -Credential $Credential

## STEP 4: Remove Unattend file and XML file ##
Write-Host "Removing sensitive files ..." -ForegroundColor Green -BackgroundColor Black
Remove-Item C:\Windows\Panther\Unattend\Unattend.xml -Confirm:$False
Remove-Item C:\Windows\Panther\Unattend\ConfigureOS.xml -Confirm:$False

## STEP 5: REBOOT ##
Write-Host "Rebooting." -ForegroundColor Green -BackgroundColor Black
Sleep 5
Restart-Computer -Force
