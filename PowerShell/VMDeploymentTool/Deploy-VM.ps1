#requires -module Hyper-V, FailoverClusters, ActiveDirectory

clear

#### FUNCTIONS ####

Function Show-ScriptInformation{
    Write-Host "Welcome to Hyper-V VM deployment tool v0.1" -ForegroundColor Green -BackgroundColor Black
    Write-Host "This script has been written by Romain Serre" -ForegroundColor Green -BackgroundColor Black
    Write-Host "Twitter: @RomSerre" -ForegroundColor Green -BackgroundColor Black
    Write-Host "Blog: http://www.tech-coffee.net" -ForegroundColor Green -BackgroundColor Black
    Write-Host "Enjoy :)" -ForegroundColor Green -BackgroundColor Black
    Write-Host
    Write-Host
}

Function Validate-XMLFile {
    Param ([XML]$XMLFile,
           [String]$Password)
   
    $SecDescriptor = $Null

    Write-Host "Beginning of XML file validation." -ForegroundColor Green -BackgroundColor Black
    Write-Host "Check 1: validate resolution of $($XMLFile.VirtualMachines.Domain.Name)" -ForegroundColor Yellow -BackgroundColor Black
    # Check Domain resolution
    Try {
        $IPAD = (Resolve-DnsName $XMLFile.VirtualMachines.Domain.Name -ErrorAction Stop | Random).IPAddress
        $DC   = (Resolve-DnsName $IPAD -ErrorAction Stop).NameHost
    }
    Catch {

        Write-Host "$($Error[0].Exception.Message). Exiting script" -ForegroundColor Red -BackgroundColor Black
        Exit

    }
    Write-Host "Check passed. The next check will use the following domain controller: $DC" -ForegroundColor Green -BackgroundColor Black
    Write-Host "Check 2: validate $($XMLFile.VirtualMachines.Domain.Account) permissions on $($XMLFile.VirtualMachines.Domain.OUPath)" -ForegroundColor Yellow -BackgroundColor Black
    # Check account permission
    
    $secpasswd = ConvertTo-SecureString $Password -AsPlainText -Force
    $Cred      = New-Object System.Management.Automation.PSCredential ($XMLFile.VirtualMachines.Domain.Account, $secpasswd)

    Try {
        $SecDescriptor =  (Get-ADObject $($XMLFile.VirtualMachines.Domain.OUPath) -Properties * -Credential $Cred -Server $DC -ErrorAction Stop).nTSecurityDescriptor |
                          Select -Expand Access |
                          ? IdentityReference -like "*$($XMLFile.VirtualMachines.Domain.Account)*" |
                          ? AccessControlType -like "Allow" |
                          ? ActiveDirectoryRights -like "*CreateChild*" |
                          ? ObjectType -like "bf967a86-0de6-11d0-a285-00aa003049e2"     
    }
    Catch {
        Write-Host "$($Error[0].Exception.Message). Exiting script" -ForegroundColor Red -BackgroundColor Black
        Exit
    }
    if ($SecDescriptor.IdentityReference -like $Null){
        Write-Host "$($XMLFile.VirtualMachines.Domain.Account) can't create computer object in $($XMLFile.VirtualMachines.Domain.OUPath)" -ForegroundColor Red -BackgroundColor Black
        Exit
    }
    Write-Host "Check passed. $($XMLFile.VirtualMachines.Domain.Account) can create computer object in $($XMLFile.VirtualMachines.Domain.OUPath)" -ForegroundColor Green -BackgroundColor Black
    
    # Validate cluster communication
    Write-Host "Check 3: validate cluster communication" -ForegroundColor Yellow -BackgroundColor Black
    Try {
        Get-Cluster -Name $XMLFile.VirtualMachines.Hosts.Cluster.Name -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-Host "Check failed. Can't get information about cluster. Exiting" -ForegroundColor Red -BackgroundColor Black
        Exit
    }
    Write-Host "Check passed." -ForegroundColor Green -BackgroundColor Black    
    Write-Host "Check 4: validate VM(s) configuration" -ForegroundColor Yellow -BackgroundColor Black
    # Foreach VM, check settings
    Foreach ($VM in $XMLFile.VirtualMachines.VM){
        Write-Host " Check VM called $($VM.Information.Name)" -Foreground Yellow -BackgroundColor Black
        Write-Host "   Validating VM name..." -ForegroundColor Yellow -BackgroundColor Black
        if ((($VM.Information.Name).Length -eq 0) -or (($VM.Information.Name).Length -gt 15)){
            Write-Host "    Check failed. VMName length: $(($VM.Information.Name).Length). Maybe length superior to 15? Exiting script" -foregroundColor Red -BackgroundColor Black
            Exit
        }
        Else {
            Write-Host "   Check passed." -ForegroundColor Green -BackgroundColor Black
        }
        Write-Host "   Validating VM gen version (1 or 2)..." -ForegroundColor Yellow -BackgroundColor Black
        if (($VM.Hardware.Gen -lt 1) -or ($VM.Hardware.Gen -gt 2)){
            Write-Host "   Check failed. VM Gen should be 1 or 2. Exiting." -ForegroundColor Red -BackgroundColor Black
            Exit
        }
        Else {
            Write-Host "   Check passed." -ForegroundColor Green -BackgroundColor Black
        }
        Write-Host "   Check startup memory configuration..." -ForegroundColor Yellow -BackgroundColor Black
        If (($VM.Hardware.Gen -eq 1) -and (($VM.Hardware.StartupMemory/1TB) -gt 1)){
            Write-Host "   Your VM is Gen 1 and the memory is more than 1TB. Not supported. Exiting" -ForegroundColor Red -BackgroundColor Black
            Exit
        }
            ElseIf (($VM.Hardware.Gen -eq 2) -and (($VM.Hardware.StartupMemory/12TB) -gt 1)){
            Write-Host "   Your VM is Gen 2 and the memory is more than 12TB. Not supported. Exiting" -ForegroundColor Red -BackgroundColor Black
            Exit
        }
        Write-Host "   Check passed." -ForegroundColor Green -BackgroundColor Black
        Write-Host "   Check dynamic memory configuration..." -ForegroundColor Yellow -BackgroundColor Black
        
        if ($VM.Hardware.DynamicMemory -eq 0){
            Write-Host "   Dynamic memory is disabled." -ForegroundColor Green -BackgroundColor Black
            
        }
        Elseif ($VM.Hardware.DynamicMemory -eq 1){
            Write-Host "    Dynamic memory is enabled." -ForegroundColor Green -BackgroundColor Black
            if ($VM.Hardware.MinimumMemory -gt $VM.Hardware.MaximumMemory){
                Write-Host "    Check failed. The minimum memory is greater than maximum memory. Exiting." -ForegroundColor Red -BackgroundColor Black
                Exit
            }
            if ($VM.Hardware.StartupMemory -gt $VM.Hardware.MaximumMemory){
                Write-Host "    Check failed. The startup memory is greater than maximum memory. Exiting." -ForegroundColor Red -BackgroundColor Black
            }
        }
        Else {
            Write-Host "    Check failed. Wrong dynamic memory setting (1 or 0 accepted). Exiting." -ForegroundColor Red -BackgroundColor Green
        }
        Write-Host "    Check passed." -ForegroundColor Green -BackgroundColor Black
        Write-Host "   Check processor count..." -ForegroundColor Yellow -BackgroundColor Black
        If($VM.Hardware.Gen -eq 1){
            if (([int]$VM.Hardware.ProcessorCount -lt 1) -or ([int]$VM.Hardware.ProcessorCount -gt 64)){
                Write-Host "   Check failed. The processor count is incorrect. Maximum processor for Gen 1 is 64. Processor count set: $($VM.Hardware.ProcessorCount). Exiting" -ForegroundColor red -BackgroundColor Black
                Exit
            }
        }
        Elseif ($VM.Hardware.Gen -eq 2){
            if (([int]$VM.Hardware.ProcessorCount -lt 1) -or ([int]$VM.Hardware.ProcessorCount -gt 256)){
                Write-Host "   Check failed. The processor count is incorrect. Maximum processor for Gen 2 is 256. Processor count set: $($VM.Hardware.ProcessorCount). Exiting" -ForegroundColor red -BackgroundColor Black
                Exit
            }
        }
        Write-Host "   Check passed." -ForegroundColor Green -BackgroundColor Black 
        Write-Host "   Check if VMswitch $($VM.Hardware.SwitchName) exists on cluster nodes..." -ForegroundColor Yellow -BackgroundColor Black
        $Nodes = (Get-ClusterNode -Cluster $XMLFile.VirtualMachines.Hosts.Cluster.Name |? State -like "Up").Name
        Foreach ($Node in $Nodes){
            Try {
               $Switch = Get-VMSwitch -Name $($VM.Hardware.SwitchName) -ComputerName $Node -ErrorAction Stop
            }
            Catch {
                Write-Host "   Check failed. The VMSwitch $($VM.Hardware.SwitchName) doesn't exist on $Node. Exiting." -ForegroundColor Red -BackgroundColor Black
            }
        }
        Write-Host "   Check passed." -ForegroundColor Green -BackgroundColor Black
        # Check vhdx file
        Write-Host "Check 5: validate $($VM.Information.OSDisk.Path)" -ForegroundColor Yellow -BackgroundColor Black
        Try {
            Resolve-Path -Path $VM.Information.OSDisk.Path -ErrorAction Stop
        }
        Catch {
             Write-Host "$($Error[0].Exception.Message). Exiting script" -ForegroundColor Red -BackgroundColor Black
             Exit
        }
        Write-Host "Check passed. $($VM.Information.OSDisk.Path) exists" -ForegroundColor Green -BackgroundColor Black
    }
    Write-Host "All VMs passed checks." -ForegroundColor Green -BackgroundColor Black

}

Function Create-VM {
    Param([int]$Gen,
          [String]$VMName,
          [int64]$StartupMemory,
          [int]$ProcessorCount,
          [int64]$MinimumMemory,
          [int64]$MaximumMemory,
          [int]$DynamicMemory,
          [String]$SwitchName,
          [string]$ComputerName,
          [string]$Notes
          )

    $VMPath = (Get-VMHost $ComputerName).VirtualMachinePath

    New-VM -Generation $Gen `
           -NoVHD `
           -MemoryStartupBytes $StartupMemory `
           -Path $VMPath `
           -Name $VMName `
           -SwitchName $SwitchName `
           -ComputerName $ComputerName

    if ($DynamicMemory){
        Set-VM -Name $VMName `
               -ProcessorCount $ProcessorCount `
               -DynamicMemory `
               -MemoryMinimumBytes $MinimumMemory `
               -MemoryMaximumBytes $MaximumMemory `
               -MemoryStartupBytes $StartupMemory `
               -Notes $Notes `
               -ComputerName $ComputerName 
    }
    Else {
        Set-VM -Name $VMName `
               -ProcessorCount $ProcessorCount `
               -StaticMemory `
               -MemoryStartupBytes $StartupMemory `
               -ComputerName $ComputerName
    }

    $VM = Get-VM -Name $VMName -ComputerName $ComputerName
    Return $VM

}

Function Set-FirstNetworkAdapter {
    Param([String]$Name,
          [String]$VMName,
          [String]$DeviceNaming,
          [int]$VID,
          [String]$ComputerName)

    $SetvNic = Get-VMNetworkAdapter -VMName $VMName -ComputerName $ComputerName | Rename-VMNetworkAdapter -NewName $Name
    $SetvNIC = Set-VMNetworkAdapter -VMName $VMName `
                                    -VMNetworkAdapterName $Name `
                                    -DeviceNaming $DeviceNaming `
                                    -ComputerName $ComputerName

    if ($VID -eq 0){
        $SetvNICVlan = Set-VMNetworkAdapterVlan -VMName $VMName `
                                                -VMNetworkAdapterName $Name `
                                                -Untagged `
                                                -ComputerName $ComputerName
    }
    Else{
        $SetvNICVlan = Set-VMNetworkAdapterVlan -VMName $VMName `
                                                -VMNetworkAdapterName $Name `
                                                -VlanId $VID `
                                                -Access `
                                                -ComputerName $ComputerName
    }
    
    Return $SetvNic

}

Function Create-VMNetworkAdapter {
    Param ([String]$Name,
           [String]$SwitchName,
           [String]$DeviceNaming,
           [Int]$VID,
           [String]$VMName,
           [String]$ComputerName
    )

    
    Write-Host "Creating an additional network adapter called $Name" -ForegroundColor Green -BackgroundColor Black
    Add-VMNetworkAdapter -VMName $VMName `
                         -ComputerName $ComputerName `
                         -SwitchName $SwitchName `
                         -Name $Name `
                         -DeviceNaming $DeviceNaming

    if ($vNIC.VID -eq 0){
        $SetvNICVlan = Set-VMNetworkAdapterVlan -VMName $VMName `
                                                -VMNetworkAdapterName $Name `
                                                -Untagged `
                                                -ComputerName $ComputerName
    }
    Else{
        $SetvNICVlan = Set-VMNetworkAdapterVlan -VMName $VMName `
                                                -VMNetworkAdapterName $Name `
                                                -VlanId $VID `
                                                -Access `
                                                -ComputerName $ComputerName
                             
    }
}

Function Set-OSVirtualDisk {
    Param ([string]$MasterPath,
           [string]$VMpath,
           [String]$VMName,
           [string]$ComputerName
          )
          

    $UNCPath      = $VMPath -replace "c:","\\$ComputerName\c$"
    $MasterName   = Split-Path $MasterPath -leaf
    $OSDiskPath   = $($VMpath + "\" + $MasterName)
    
    copy-item $MasterPath $UNCPath 


    $OSDisk = Add-VMHardDiskDrive -VMName $VMName -Path $OSDiskPath -ComputerName $ComputerName
    $OSDisk = Get-VM -Name $VMName -ComputerName $ComputerName | Get-VMHardDiskDrive
    Set-VMFirmware -VMName $VMName -FirstBootDevice $OSDisk -ComputerName $ComputerName
    return $OSDiskPath
    

}

Function Create-DataVirtualDisks {
    Param([String]$VMName,
          [Array]$AdditionalDisks,
          [String]$ComputerName,
          [String]$VMPath
          )
 
    Foreach ($Disk in $AdditionalDisks){
        
        Invoke-Command -ComputerName $ComputerName `
                       -ArgumentList $VMName, $VMPath, $Disk.Name, $Disk.Size, $Disk.Type `
                       -ScriptBlock {

                        $VHDXPath = $Args[1] + "\" + $Args[2]
                        if ($Args[4] -like "Dynamic"){
                            New-VHD -SizeBytes $Args[3] -Path $VHDXPath -Dynamic
                        }
                        Elseif ($Args[4] -like "Fixed"){
                            New-VHD -SizeBytes $Args[3] -Path $VHDXPath -Fixed
                        }

                        $AddDisk = Add-VMHardDiskDrive -VMName $Args[0] -Path $VHDXPath | Out-Null

                       } | Out-Null
    }
 }
    
Function Create-XMLConfigureOS { 
    Param([string]$VMName,
          [string]$DomainName,
          [string]$OUPath,
          [string]$Account,
          [String]$VHDXPath,
          [String]$Password,
          [Array]$NetAdapters,
          [String]$ComputerName
          )

    
    
    Invoke-Command -ComputerName $ComputerName `
                   -ArgumentList $VMName, $DomainName, $OUPath, $Account, $Password, $VHDXPath, $NetAdapters `
                   -ScriptBlock {
                
                $VolumeVHD   = (Mount-VHD –Path $Args[5] –Passthru | Get-Disk | Get-Partition | Get-Volume |? FileSystemLabel -notlike "Recovery").DriveLetter

                $ConfigureOS = $($VolumeVHD + ":\Windows\Panther\Unattend\ConfigureOS.xml")
                [XML]$XML    = Get-Content $ConfigureOS

                $XML.Configuration.ComputerName    = $Args[0]
                $XML.Configuration.Domain.Name     = $Args[1]
                $XML.Configuration.Domain.Account  = $Args[3]
                $XML.Configuration.Domain.OUPath   = $Args[2]
                $XML.Configuration.Domain.Password = $Args[4]
                $XML.Save($ConfigureOS)

                Foreach ($NetAdapter in $Args[6]){
                    #Add XML node for each network adapter
                    $XMLNic = $XML.CreateElement("NetAdapter")
                    $XMLNic.SetAttribute("Name", $NetAdapter.Name)
                    $XMLNic.SetAttribute("IP", $NetAdapter.IPAddress)
                    $XMLNic.SetAttribute("Netmask", $NetAdapter.Netmask)
                    $XMLNic.SetAttribute("GW", $NetAdapter.Gateway)
                    $XMLNic.SetAttribute("DNS", $NetAdapter.DNS)
                    $XMLNic.SetAttribute("RegisterDNS", $NetAdapter.RegisterDNS)
                    $XML.SelectSingleNode("//Configuration/NetAdapters").AppendChild($XMLNic) | Out-Null
                    $XML.Save($ConfigureOS)
                }
                
         Dismount-VHD $Args[5]
         }
            
  } 

Function Set-IntegrationServices {
    Param([Array]$Services,
          [String]$VMName,
          [String]$ComputerName
          )
    Foreach ($Service in $Services){
        If ($Service.State -eq 1){
            Write-Host "Enabling integration service $($Service.Name) ($($Service.Description))" -Foreground Green -BackgroundColor Black
            try {
                Get-VMIntegrationService -VMName $VMName -ComputerName $ComputerName -Name $Service.Name -ErrorAction Stop | Enable-VMIntegrationService -ErrorAction Stop | Out-Null
            }
            Catch {
                Write-Host "Can't enable the integration servie $($Service.Name) on $VMName. $($Error[0].Exception.Message)" -ForegroundColor Red -BackgroundColor black
            }
        }
        Else {
            Write-Host "Disabling integration service $($Service.Name) ($($Service.Description))" -Foreground Green -BackgroundColor Black
            try {
                Get-VMIntegrationService -VMName $VMName -ComputerName $ComputerName -Name $Service.Name -ErrorAction Stop | Disable-VMIntegrationService -ErrorAction Stop | Out-Null
            }
            Catch {
                Write-Host "Can't disable the integration servie $($Service.Name) on $VMName. $($Error[0].Exception.Message)" -ForegroundColor Red -BackgroundColor black
            }
        }
    }

}

#### VARIABLES ####

# Template repository
$TemplatePath = "\\VMLIB01\Template"

#### MAIN CODE ####

$Templates = Get-ChildItem $TemplatePath
$TPArray   = @()
$i         = 1

#Show intitle
Show-ScriptInformation

# Show a multichoice menu with all templates
Foreach ($Template in $Templates){
    Write-Host "[ $i ] $(SPlit-Path $Template.FullName -leaf)" -ForegroundColor Green -BackgroundColor Black
    $TPObj = New-Object System.Object
    $TPObj | Add-Member -Type NoteProperty -Name id -Value $i
    $TPObj | Add-Member -Type NoteProperty -Name Name -Value $(SPlit-Path $Template.FullName -leaf)
    $TPObj | Add-Member -Type NoteProperty -Name FullName -Value $Template.FullName
    $TPArray += $TPObj
    $i++ 
}
Write-Host "[ 0 ] Exit" -ForegroundColor Yellow -BackgroundColor Black
Write-Host
Write-Host "On which master your VM is based: " -NoNewline -ForegroundColor Cyan -BackgroundColor Black
[int]$Choice = Read-Host

# If user selects exit, exit script :)
If ($Choice -eq 0){
    Write-Host "Bye bye. See you next time" -ForegroundColor Green -BackgroundColor Black
    Exit
}

# If user typed a number not listed, exit the script.
$TP = $TPArray |? id -like $Choice
if ($TP.Name -like $Null){
    Write-Host "You have selected a template that doesn't exist. Sorry." -ForegroundColor Red -BackgroundColor Black
    exit
}
Write-Host "You have selected the following template: $($TP.Name) ($($TP.FullName))" -ForegroundColor Green -BackgroundColor Black

# Load the XML in memory and show the number of VM to deploy
[xml]$Template = Get-Content $TP.FullName

# Get the password to join the domain
Write-Host "Please provide the password for the account $($Template.VirtualMachines.Domain.Account +"@" + $Template.VirtualMachines.Domain.Name): " -NoNewline -ForegroundColor Yellow -BackgroundColor Black
$Password = Read-Host -AsSecureString
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

$XMLValidation = Validate-XMLFile -XMLFile $Template -Password $Password
# Exit

# Get the number of VM to deploy
$NbrVM    = ($Template.VirtualMachines.VM | Measure-Object).Count
Write-Host "Number of VM to deploy: $NbrVM" -ForegroundColor Green -BackgroundColor Black

# Get cluster nodes
$ClusterNodes = Get-Cluster $Template.VirtualMachines.Hosts.Cluster.Name | Get-ClusterNode |? state -like "Up"

Foreach ($VM in $Template.VirtualMachines.VM){

    $OSTemplate = $VM.Information.OSDisk.Path
    $TimeStart = Get-Date
    Write-Host "Detecting the Hyper-V node with the less number of vm..." -ForegroundColor Green -BackgroundColor Black
    
    # Get a host in the cluster with the less number of vm
    $HostVM   = @()
    Foreach ($Node in $ClusterNodes){
        $HVObj   = New-Object System.Object
        $CountVM = (Get-VM -ComputerName $Node.Name).Count
        $HVObj | Add-Member -Type NoteProperty -Name Host -Value $Node.Name
        $HVObj | Add-Member -Type NoteProperty -Name CountVM -Value $CountVM
        $HostVM += $HVObj
    }
    $HVHost = ($HostVM | Sort-Object CountVM -Descending | Select -Last 1).Host

    Write-Host "The VM will be deployed on $HVHost" -ForegroundColor Green -BackgroundColor Black

    ## CREATE VIRTUAL MACHINES ##

    Write-Host "Creation of $($VM.Information.Name) on $($HVHost)" -ForegroundColor Green -BackgroundColor Black
    Write-Host "VM Hardware:" -ForegroundColor Green -BackgroundColor Black
    Write-Host "    - Notes: $($VM.Information.Notes)" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    - vCPU: $($VM.Hardware.ProcessorCount)" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    - Gen: $($VM.Hardware.Gen)" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    - Startup Memory: $($VM.Hardware.StartupMemory / 1MB)MB" -ForegroundColor Cyan -BackgroundColor Black
    
    if ($VM.Hardware.DynamicMemory -eq 1){
        Write-Host "    - Dynamic Memory: Enabled" -ForegroundColor Cyan -BackgroundColor Black
        Write-Host "    - Minimum Memory: $($VM.Hardware.MinimumMemory / 1MB)MB" -ForegroundColor Cyan -BackgroundColor Black
        Write-Host "    - Maximum Memory: $($VM.Hardware.MaximumMemory /1MB)MB" -ForegroundColor Cyan -BackgroundColor Black
    }
    Else {
        Write-Host "    - Dynamic Memory: Disabled" -ForegroundColor Cyan -BackgroundColor Black
    }
    Write-Host "    - Switch Name: $($VM.Hardware.SwitchName)" -ForegroundColor Cyan -BackgroundColor Black

    
    $GetVM = Create-VM -Gen $VM.Hardware.Gen `
                    -VMName $VM.Information.Name `
                    -ProcessorCount $VM.Hardware.ProcessorCount `
                    -DynamicMemory $VM.Hardware.DynamicMemory `
                    -StartupMemory $VM.Hardware.StartupMemory `
                    -MinimumMemory $VM.Hardware.MinimumMemory / 1MB `
                    -MaximumMemory $VM.Hardware.MaximumMemory / 1MB `
                    -SwitchName $VM.Hardware.SwitchName `
                    -Notes $VM.Information.Notes `
                    -ComputerName $HVHost
    Try {
        $GetVM = Get-VM -Name $VM.Information.Name -ComputerName $HVHost -ErrorAction Stop
    }
    Catch {
        Write-Host "The VM ($($VM.Information.Name)) doesn't exist on $($HVHost). Stop VM creation" -ForegroundColor Red -BackgroundColor Black
        Break
    }
    Write-Host "    - VM path (on $($HVHost): $($GetVM.Path))" -ForegroundColor Cyan -BackgroundColor Black

    ## CONFIGURE FIRST NETWORK ADAPTER ##
    

    if ($VM.NetworkAdapter.VID -eq 0){$VID = "Untagged"}
    Else {$VID = "Access ($($VM.NetworkAdapter.VID))"}
    Write-Host "Configuration of the first network adapter" -ForegroundColor Green -BackgroundColor Black
    Write-Host "    - vNIC name: $($VM.NetworkAdapter.Name)" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    - Device Naming: $($VM.NetworkAdapter.DeviceNaming)" -ForegroundColor Cyan -BackgroundColor Black
    Write-Host "    - VLAN: $VID" -ForegroundColor Cyan -BackgroundColor Black
    
    Set-FirstNetworkAdapter -Name $VM.NetworkAdapter.Name `
                            -DeviceNaming $VM.NetworkAdapter.DeviceNaming `
                            -VMName $GetVM.Name `
                            -VID $VM.NetworkAdapter.VID `
                            -ComputerName $HVHost
    $NetAdapters = @()

    $NicObj = New-Object System.Object
    $NicObj | Add-Member -Type NoteProperty -Name Name -Value $VM.NetworkAdapter.Name
    $NicObj | Add-Member -Type NoteProperty -Name IPAddress -Value $VM.NetworkAdapter.IPAddress
    $NicObj | Add-Member -Type NoteProperty -Name Netmask -Value $VM.NetworkAdapter.Netmask
    $NicObj | Add-Member -Type NoteProperty -Name Gateway -Value $VM.NetworkAdapter.Gateway
    $NicObj | Add-Member -Type NoteProperty -Name DNS -Value $VM.NetworkAdapter.DNS
    $NicObj | Add-Member -Type NoteProperty -Name RegisterDNS -Value $VM.NetworkAdapter.RegisterDNS
    $NicObj | Add-Member -Type NoteProperty -Name VID -Value $VM.NetworkAdapter.VID
    $NetAdapters += $NicObj
    
    ## MANAGE ADDITIONAL NETWORK ADAPTERS ##
    
    ## If additional adapters, add to array
    Foreach ($NIC in $VM.AdditionalAdapters){

        $NicObj = New-Object System.Object
        $NicObj | Add-Member -Type NoteProperty -Name Name -Value $NIC.Name
        $NicObj | Add-Member -Type NoteProperty -Name IPAddress -Value $NIC.IPAddress
        $NicObj | Add-Member -Type NoteProperty -Name Netmask -Value $NIC.Netmask
        $NicObj | Add-Member -Type NoteProperty -Name Gateway -Value $NIC.Gateway
        $NicObj | Add-Member -Type NoteProperty -Name DNS -Value $NIC.DNS
        $NicObj | Add-Member -Type NoteProperty -Name RegisterDNS -Value $VM.NetworkAdapter.RegisterDNS
        $NicObj | Add-Member -Type NoteProperty -Name VID -Value $VM.NetworkAdapter.VID
        $NetAdapters += $NicObj

        Create-VMNetworkAdapter -Name $NIC.Name `
                                -SwitchName $NIC.SwitchName `
                                -VID $NIC.VID `
                                -DeviceNaming $NIC.DeviceNaming `
                                -VMName $GetVM.Name `
                                -ComputerName $HVHost
    }
    Write-Host "Starting for 3 seconds the $($GetVM.Name) VM to get static MAC addresses..." -ForegroundColor Green -BackgroundColor Black
    Start-VM -ComputerName $HVhost -Name $GetVM.Name
    Sleep 5
    Write-Host "Stopping the $($GetVM.Name) VM..." -ForegroundColor Green -BackgroundColor Black
    Stop-VM -ComputerName $HvHost -Name $GetVM.Name -TurnOff
    Sleep 5
    Foreach ($NIC in $NetAdapters){
        Write-Host "Set static MAC address on $($NIC.Name)" -ForegroundColor Green -BackgroundColor Black
        $MACAddress = Get-VMNetworkAdapter -VMName $GetVM.Name -ComputerName $HVHost -Name $Nic.Name | Select MACAddress -ExpandProperty MACAddress
        $MACAddress = ($MACAddress -replace '(..)','$1-').trim('-')
        Set-VMNetworkAdapter -VMName $GetVM.Name -ComputerName $HVHost -Name $Nic.Name -StaticMacAddress $MacAddress
    }

    ## SET OS DISK ##

    $TemplateFile = Get-Item $OSTemplate
    Write-Host "Copy of VHDX $($TemplateFile.FullName) ($([Math]::Round($TemplateFile.Length / 1GB,2))GB). Please be patient" -ForegroundColor Green -BackgroundColor Black
    Write-Host "    - Copy to: $($GetVM.Path) ($HVHost)" -ForegroundColor Cyan -BackgroundColor Black
    
    $OSDisk = Set-OSVirtualDisk -MasterPath $TemplateFile.Fullname -VMpath $GetVM.Path -VMName $GetVM.Name -ComputerName $HVHost

    ## CONFIGURE THE XML INSIDE THE VHDX ##
    Write-Host "Configuration of VHDX located to $OSDisk" -ForegroundColor Green -BackgroundColor Black
    Create-XMLConfigureOS -VMName $GetVM.Name `
                          -DomainName $Template.VirtualMachines.Domain.Name `
                          -OUPath $Template.VirtualMachines.Domain.OUPath `
                          -Account $Template.VirtualMachines.Domain.Account `
                          -Password $Password `
                          -NetAdapters $NetAdapters `
                          -VHDXPath $OSDisk `
                          -ComputerName $HVHost

    ## ADD ADDITIONAL VHDX ##
    $AdditionalDisks = @()

    Foreach ($Disk in $VM.AdditionalDisk){
        $DiskObj = New-Object System.Object
        Write-Host "Adding additional disk called $($Disk.Name) - Size: $([Math]::Round($Disk.Size / 1GB, 2))GB - $($Disk.Type)" -Foreground Green -BackgroundColor Black
        $DiskObj | Add-Member -Type NoteProperty -Name Name -Value $Disk.Name
        $DiskObj | Add-Member -Type NoteProperty -Name Size -Value $Disk.Size
        $DiskObj | Add-Member -Type NoteProperty -Name Type -Value $Disk.Type
        $AdditionalDisks += $DiskObj

    }

    Create-DataVirtualDisks -VMName $GetVM.Name `
                            -ComputerName $HVHost `
                            -AdditionalDisks $AdditionalDisks `
                            -VMPath $GetVM.Path

    ## MANAGE INTEGRATION SERVICES ##
    
    $IntServicesArray = @()
    Foreach ($Service in $VM.IntegrationServices.Service){
        $IntServicesObj = New-Object System.Object
        $IntServicesObj | Add-Member -Type NoteProperty -Name Name -Value $Service.Name
        $IntServicesObj | Add-Member -Type NoteProperty -Name State -Value $Service.State
        $IntServicesObj | Add-Member -Type NoteProperty -Name Description -Value $Service.Description
        $IntServicesArray += $IntServicesObj
    }
    Set-IntegrationServices -Services $IntServicesArray -VMName $GetVM.Name -ComputerName $HVHost
    
    ## ADD THE VM TO CLUSTER AND START IT ##
    Write-Host "Adding $($GetVM.Name) to the cluster $($Template.VirtualMachines.Hosts.Cluster.Name)" -ForegroundColor Green -BackgroundColor Black
    $AddVMCluster = Get-VM -Name $GetVM.Name -ComputerName $HVHost | Add-ClusterVirtualMachineRole -Cluster $Template.VirtualMachines.Hosts.Cluster.Name
    
    if ($VM.Information.Autostart -eq 1){
        Write-Host "Starting $($GetVM.Name) ..." -ForegroundColor Green -BackgroundColor Black
        Start-VM -Name $GetVM.Name -ComputerName $HVHost
    }

    $TimeEnd  = Get-Date
    $Duration =  $TimeEnd - $TimeStart
    Write-Host "Total duration to deploy $($GetVM.Name): $($Duration.TotalSeconds) seconds" -Foreground Green -BackgroundColor Black
}

