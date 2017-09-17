<#
.Synopsis
   This script creates and adds nodes to cluster
.DESCRIPTION
   If the node is the master, the cluster is created. If the node is not a master,
   the node join the cluster. If the cluster already exists, the node is added.
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

    $OKLogs = $LogPath + "\OK_ClusterDeployment.log"
    $KOLogs = $LogPath + "\KO_ClusterDeployment.log"
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

# Location of copied data. Scripts will be run from here
$DeployPkg     = "C:\temp\Deploy"

# Path to the ClusterConfiguration.xml which containers the network configuration
$XMLPath       = $DeployPkg + "\ClusterConfiguration.xml"

# Show logs in console (No = 0 | Yes = 1)
$Verbose = 1


#################
### Main Code ###
#################

# Get script path
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

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

$ClusterName  = $XML.ClusterConfiguration.Settings.ClusterName
$Nodes        = $XML.ClusterConfiguration.Settings.Nodes
$Nodes        = $Nodes -Split ","

    
Try {
     Get-ADComputer $ClusterName -ErrorAction Stop
}
Catch {
    Try {  
            
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Testing the cluster ..."
        # Test cluster       
        Test-Cluster -Node $Nodes -Include "Storage Spaces Direct", Inventory,Network,"System Configuration" -ErrorAction Stop | Out-Null
            
        # Create the Cluster
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                    -Message "Creating the cluster"
           
        New-Cluster -Node $Nodes `
                    -StaticAddress $XML.ClusterConfiguration.Settings.ClusterIPAddress `
                    -Name $ClusterName `
                    -NoStorage `
                    -ErrorAction Stop | Out-Null
        Sleep 60
        # Set block cache size
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Changing the block cache size to $($XML.ClusterConfiguration.Settings.ClusterBlockCacheSize)"

        (Get-Cluster -Name $ClusterName -ErrorAction Stop).blockCacheSize=$($XML.ClusterConfiguration.Settings.ClusterBlockCacheSize)

        # Set Cloud Witness
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Setting up the Cloud Witness..."
            
        Set-ClusterQuorum -CloudWitness `
                            -Cluster $ClusterName `
                            -AccountName $XML.ClusterConfiguration.Settings.WitnessAccountName `
                            -AccessKey $XML.ClusterConfiguration.Settings.WitnessAccessKey `
                            -ErrorAction Stop | Out-Null

        # Set the cluster network Name
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Renaming Cluster Networks"
        (Get-Cluster -Name $ClusterName | Get-ClusterNetwork |? Role -like ClusterAndClient).Name=$($XML.ClusterConfiguration.Settings.MGMTNetworkName)
        (Get-Cluster -Name $ClusterName | Get-ClusterNetwork |? Role -like Cluster).Name=$($XML.ClusterConfiguration.Settings.ClusterNetworkName)

        # Set the Live-Migration Network
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Set the Live-Migration network to the cluster network"

        Get-ClusterResourceType -Name "Virtual Machine" | 
        Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(“;”,(Get-ClusterNetwork | Where-Object {$_.Name -ne "$($XML.ClusterConfiguration.Settings.MGMTNetworkName)"}).ID)) -ErrorAction Stop | Out-Null
                         
    }
    Catch {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 -Message "Error when configuring cluster: $($Error[0].Exception.Message)"
        Exit
        
    }
    ##Change CNO OU
    Try {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Moving Cluster CNO to $($XML.ClusterConfiguration.ActiveDirectory.CNOOU)"
        Get-ADComputer $CLusterName -ErrorAction Stop | 
        Move-ADObject -TargetPath $($XML.ClusterConfiguration.ActiveDirectory.CNOOU) -ErrorAction Stop
    }
    Catch {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 -Message "Can't move CNO computer object in Active Directory: $($Error[0].Exception.Message)"

    }
    ## Configure Kerberos SMB for nodes
    Try {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                    -Message "Setting up the kerberos delefation ..."
        Get-ADComputer $Nodes[0] | Set-ADObject -Add @{"msDS-AllowedToDelegateTo"="Microsoft Virtual System Migration Service/$($Nodes[1]).$($XML.ClusterConfiguration.ActiveDirectory.Domain)", "cifs/$($Nodes[1]).$($XML.ClusterConfiguration.ActiveDirectory.Domain)","Microsoft Virtual System Migration Service/$($Nodes[1])", "cifs/$($Nodes[1])"}
        Get-ADComputer $Nodes[1] | Set-ADObject -Add @{"msDS-AllowedToDelegateTo"="Microsoft Virtual System Migration Service/$($Nodes[0]).$($XML.ClusterConfiguration.ActiveDirectory.Domain)", "cifs/$($Nodes[0]).$($XML.ClusterConfiguration.ActiveDirectory.Domain)","Microsoft Virtual System Migration Service/$($Nodes[0])", "cifs/$($Nodes[0])"}
    }
    Catch {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 `
                    -Message "Can't set kerberos delegation: $($Error[0].Exception.Message)"
    }
    ## Set Live-Migration and Storage Migration settings
    Try {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                    -Message "Change Live-Migration and Storage Migration settings (Kerberos authentication, SMB protocol etc.)"

        Enable-VMMigration –Computername $Nodes -ErrorAction Stop| Out-Null
        Set-VMHost         –Computername $Nodes `
                            –VirtualMachineMigrationAuthenticationType Kerberos `
                            -VirtualMachineMigrationPerformanceOption SMB `
                            -MaximumVirtualMachineMigrations 8 `
                            -MaximumStorageMigrations 8 `
                            -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 `
                    -Message "Can't set the Live-Migration and Storage Migration settings: $($Error[0].Exception.Message)"
    }
    ## Clean Disk for S2D
    icm (Get-Cluster -Name $ClusterName | Get-ClusterNode) {  

    Update-StorageProviderCache  

    Get-StoragePool |? IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue  

    Get-StoragePool |? IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue 
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue  

    Get-Disk |? Number -ne $null |? IsBoot -ne $true |? IsSystem -ne $true |? PartitionStyle -ne RAW |% {  

        $_ | Set-Disk -isoffline:$false  

        $_ | Set-Disk -isreadonly:$false  

        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false  

        $_ | Set-Disk -isreadonly:$true  

        $_ | Set-Disk -isoffline:$true  

    }  

    Get-Disk |? Number -ne $null |? IsBoot -ne $true |? IsSystem -ne $true |? PartitionStyle -eq RAW | Group -NoElement -Property FriendlyName  

    } | Sort -Property PsComputerName,Count

    ## Enable S2D
    Try {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 -Message "Enabling S2D ..."
        Enable-ClusterS2D  -PoolFriendlyName $XML.ClusterConfiguration.Settings.PoolName `
                           -ErrorAction Stop `
                           -Confirm:$False | Out-Null
    }
    Catch {
        Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 2 -Message "Can't enable S2D on the cluster: $($Error[0].Exception.Message). Exiting script"
        Exit
    }

    ## Create volume & rename folder
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 `
                -Message "Creating volume ..."
    Foreach ($Volume in $XML.ClusterConfiguration.Volumes.Volume){
        Try {
            Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Create volume called $($Volume.Name) (Size: $($Volume.Size))"
            New-Volume -StoragePoolFriendlyName $XML.ClusterConfiguration.Settings.PoolName `
                       -FriendlyName $Volume.Name `
                       -FileSystem CSVFS_ReFS `
                       -Size $VOlume.Size `
                       -ErrorAction Stop | Out-Null
                
            Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 0 -Message "Renaming c:\ClusterStorage\Volume1 by $($VOlume.Name)"
            Rename-Item c:\ClusterStorage\Volume1 $VOlume.Name -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 -Message "Can't create volume $($Volume.Name): $($Error[0].Exception.Message)"
        }
    }

    ## Cluster Ready
    Write-Log -Verbose $Verbose -LogPath $ScriptDir -Level 1 -Message "Your S2D hyperconverged cluster is ready. Have fun." 
}




                
