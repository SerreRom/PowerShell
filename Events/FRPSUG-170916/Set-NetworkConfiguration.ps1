<#
.Synopsis
   This script configures a Hyper-V host automatically
.DESCRIPTION
   This script install drivers, configure network adapters, vMSwitch, join the domain.
.AUTHOR
    Romain Serre
    rserre@seromIT.com
    Twitter: @RomSerre
.REQUIREMENTS
    PowerShell v5
    Windows Server 2016
#>

#################
### Functions ###
#################

Function Write-Log {
    Param([string]$LogPath,
          [string]$Message,
          [int]$Level,
          [Bool]$Verbose)

    $OKLogs = $LogPath + "\OK_NetworkConfiguration.log"
    $KOLogs = $LogPath + "\KO_NetworkConfiguration.log"
    $Date   = get-date -format 'yyyyMMdd - hh:mm:ss'

    # Get the level to define the log file and the level of error
    Switch ($Level){

        0 {
            $Color    = "Green"
            $TxtLevel = "INFO"
            $LogFile  = $OKLogs
        }
        1 { 
            $Color    = "Yellow"
            $TxtLevel = "WARN"
            $LogFile  = $KOLogs
        }
        2 { 
            $Color    = "Red"
            $TxtLevel = "ERRO"
            $LogFile  = $KOLogs
        }
    }
    # Prepare the log string
    [String]$Logline = "$Date - $TXTLevel - $Message"

    # If $verbose is true, write log in powershell console
    if ($Verbose){
       Write-Host $LogLine -ForegroundColor $Color -BackgroundColor Black 
    }
    
    # Add-content to log file      
    Add-Content $LogFile -Value $Logline
}

#################
### Variables ###
#################

# Get script path
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

# Location of copied data. Scripts will be run from here
$DeployPkg     = "C:\temp\Deploy"

# Path to the NodeConfiguration.xml which containers the network configuration
$XMLPath       = $DeployPkg + "\NodeConfiguration.xml"

# Show logs in console (No = 0 | Yes = 1)
$Verbose = 1


#################
### Main Code ###
#################

# Test if XML file exists. If not: exit
Try {
    Resolve-Path -Path $XMLPath -ErrorAction Stop | Out-Null
}
Catch {
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 -Message "Can't find the XML file located to $XMLPath. Exiting"
    Exit
}
# Get XML content
[xml]$XML = Get-Content $XMLPath

# Rename network adapters
Try {
    Rename-NetAdapter -Name "Ethernet 2" -NewName CNA02 -ErrorAction Stop
}
Catch {
      Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 `
                -Message "Rename network adapter error: $($Error[0].Exception.Message)"
}
Try {
    Rename-NetAdapter -Name "Ethernet" -NewName CNA01 -ErrorAction Stop
}
Catch {
      Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 `
                -Message "Rename network adapter error: $($Error[0].Exception.Message)"
}

Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Starting Step $($Step): Network configuration"
$ComputerName = Get-Content Env:ComputerName

# Disabling disconnected network adapters
Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Disabling unuse network adapters"
Try {
    Get-NetAdapter |? Status -like "Disconnected" | Disable-NetAdapter -ErrorAction Stop | Out-Null
}
Catch {
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 -Message "Can't disable network adapter"
}

    Try {
    # Enable Jumbo Frame on all NICs
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
              -Message "Set MTU on physical network adapters"
    Get-NetAdapterAdvancedProperty -Name CNA* -RegistryKeyword "*jumbopacket" -ErrorAction Stop | 
    Set-NetAdapterAdvancedProperty -RegistryValue 9014 -ErrorAction Stop | Out-Null
}
Catch {
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 `
              -Message "Can't set MTU $($Error[0].Exception.Message)"
}
$Node = $XML.NodeConfiguration.Node |? Name -like $ComputerName
Foreach ($Switch in $Node.VMSwitch){
    # Creating vSwitch (SET)
    Try {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                  -Message "Creating Switch Embedded Teaming (name: $($Switch.Name)) vSwitch with $($Switch.NICs)"
        $NICs = $($Switch.NICs) -split ","
        New-VMSwitch -Name $($Switch.Name) `
                     -NetAdapterName $NICs `
                     -EnableEmbeddedTeaming $True `
                     -AllowManagementOS $False `
                     -ErrorAction Stop | Out-Null
        
    }
    Catch {
            Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 `
                    -Message "Can't deploy vSwitch: $($Error[0].Exception.Message). Exiting"
                    Exit
    }

        # Creating vNICs
        Foreach ($vNIC in $Switch.vNIC){
            Try {
                Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Deploying vNIC called $($vNIC.Name)"
                Add-VMNetworkAdapter -SwitchName $Switch.Name `
                                     -ManagementOS `
                                     -Name $vNIC.Name `
                                     -ErrorAction Stop | Out-Null

                # If untagged
                If ($vNIC.Type -like "Untagged"){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Configure $($vNIC.Name) to untagged"
                    Set-VMNetworkAdapterVlan -ManagementOS `
                                             -VMNetworkAdapterName $vNIC.Name `
                                             -Untagged `
                                             -ErrorAction Stop | Out-Null
                }

                # if Access mode
                Elseif ($vNIC.Type -like "Access"){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Configure $($vNIC.Name) to Access (VID: $($vNIC.VlanID))"
                    Set-VMNetworkAdapterVlan -ManagementOS `
                                             -VMNetworkAdapterName $vNIC.Name `
                                             -Access `
                                             -VlanId $vNIC.VlanID `
                                             -ErrorAction Stop | Out-Null
                }

                # Set vNIC Team Mapping
                if ($vNIC.TeamMapping){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Setting up the team mapping on $($vNIC.Name)"

                    Sleep 8
                    Set-VMNetworkAdapterTeamMapping -ManagementOS `
                                                    -VMNetworkAdapterName $vNIC.Name `
                                                    -SwitchName $Switch.Name `
                                                    -PhysicalNetAdapterName $vNIC.TeamMapping `
                                                    -ErrorAction Stop | Out-Null
                        
                }

                # Set RDMA
                If ($VNIC.RDMA -Like "True"){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Enabling RDMA on $($vNIC.Name)"
                    Enable-NetAdapterRDMA -Name "*$($vNIC.Name)*" -ErrorAction Stop | Out-Null
                }
                Else {
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Disabling RDMA on $($vNIC.Name)"
                    Disable-NetAdapterRDMA -Name "*$($vNIC.Name)*" -ErrorAction Stop | Out-Null
                }

                #Set RSS
                Set-NetAdapterRSS -Name "*$($vNIC.Name)*" `
                                  -BaseProcessorNumber $vNIC.RSS.MinimumProcessorNumber `
                                  -MaxProcessorNumber $vNIC.RSS.MaximumProcessorNumber `
                                  -MaxProcessors $vNIC.RSS.MaximumProcessor `
                                  -ErrorAction Stop | Out-Null


                # Set MTU on vNICs
                Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                          -Message "Set MTU on $($vNIC.Name)"
                Get-NetAdapterAdvancedProperty -Name NIC* -RegistryKeyword "*jumbopacket" -ErrorAction Stop | 
                Set-NetAdapterAdvancedProperty -RegistryValue $vNIC.MTU -ErrorAction Stop | Out-Null

                # Set IP address for not routed network adapter
                If ($vNIC.Gateway -like $Null){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Set IP configuration on $($vNIC.Name): IP: $($vNIC.IPaddr)/$($vNIC.Netmask)"
                    New-NetIPAddress -InterfaceAlias "vEthernet ($($vNIC.Name))" `
                                     -IPAddress $vNIC.IPaddr `
                                     -PrefixLength $vNIC.Netmask `
                                     -Type Unicast `
                                     -ErrorAction Stop | Out-Null
                }
                # Set IP address for routed network adapter
                Else {     
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Set IP configuration on $($vNIC.Name): IP: $($vNIC.IPaddr)/$($vNIC.Netmask) - GW: $($vNIC.Gateway)"
                    New-NetIPAddress -InterfaceAlias "vEthernet ($($vNIC.Name))" `
                                     -IPAddress $vNIC.IPaddr `
                                     -PrefixLength $vNIC.Netmask `
                                     -Type Unicast `
                                     -DefaultGateway $vNIC.Gateway `
                                     -ErrorAction Stop | Out-Null
            }

                # Set DNS information
                If ($vNIC.DNS -notlike $Null){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Set DNS on $($vNIC.Name) (DNS: $($vNIC.DNS))"
                    $DNS = $vNIC.DNS -split ","
                    Set-DnsClientServerAddress -InterfaceAlias "vEthernet ($($vNIC.Name))" `
                                               -ServerAddresses $DNS `
                                               -ErrorAction Stop | Out-Null
                }

                #Disable DNS registration of Storage and Cluster network adapter
                If ($vNIC.Management -like "False"){
                    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                              -Message "Disable DNS registration on $($vNIC.Name)"
                    
                    Set-DNSClient -InterfaceAlias "vEthernet ($($vNIC.Name))" `
                                  -RegisterThisConnectionsAddress $False `
                                  -ErrorAction Stop | Out-Null
                }
                    
            }
            Catch {
                Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 `
                          -Message "Can't deploy or configure vNIC $($vNIC.Name): $($Error[0].Exception.Message)"
            }
        }
    }
#### ADD TO DOMAIN ####

Try {
    # Add computer to domain
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
              -Message "Add computer to the domain $($XML.NodeConfiguration.ActiveDirectory.name)"

    $strUser     = "SeromIT\SA-ADS-JOIN"
    $StrPass     = ConvertTo-SecureString "qd?INI58" -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential $strUser, $strPass
   
    Add-Computer -DomainName $($XML.NodeConfiguration.ActiveDirectory.Domain) `
                 -Credential $Credentials `
                 -OUPath $($XML.NodeConfiguration.ActiveDirectory.NodeOU) `
                 -ErrorAction Stop | Out-Null
}
Catch {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 `
                  -Message "Can't add machine to the domain: $($Error[0].Exception.Message)"
        Exit
}

