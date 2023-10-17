#ACTIVE DIRECTORY PORTS
https://garvis.ca/2018/09/07/domain-controller-ports/

#list win32 wmi classes

Get-WMIObject -List| Where{$_.name -match "^Win32_"} | Sort Name | Format-Table Name


#Get all wmi classes
Get-WmiObject -list * -NameSpace root -Recurse -EA 0


#MOVE CLUSTER GROUP TO ANOTHER NODE
Move-ClusterGroup -Name "Cluster Group" -Cluster CLUSTER_NAME -Node AUTOMITESRV01


#get windows disk serial number
Get-WmiObject -ComputerName COMPUTERNAME -Class win32_physicalmedia | Select-Object -Property Tag,SerialNumber

Get-WmiObject -ComputerName COMPUTERNAME -Class win32_diskdrive | Select-Object -Property Name,SerialNumber,Size


#GetInfo RDM Disks 
Get-WmiObject -Class Win32_DiskDrive -Namespace 'root\CIMV2' -ComputerName "ServerName" | 
Select-Object -Property PSComputerName,
                        DeviceID,
                        Status,
                        Index,
                        @{label='Size(GB)';expression={'{0:N2}' -f ($PSItem.Size / 1GB)}},
                        SCSIBus,
                        SCSILogicalUnit,
                        SCSIPort,
                        SCSITargetId,
                        Caption,
                        Name,
                        SerialNumber,
                        Signature | Out-File SERVER-VMM0120disks.txt -Append


#get machines that run on node in a cluster
Get-Cluster -Name CLUSTER_NAME | Get-ClusterGroup | Where-Object -FilterScript {$_.OwnerNode -eq "ServerName"}


Get-Cluster -Name CLUSTER_NAME | Get-ClusterGroup | FT  Cluster,OwnerNode,State,Name -AutoSize 


Get-Cluster -Name CLUSTER_NAME.br.automite.net | 
Get-ClusterGroup | 
Select-Object -Property Cluster,OwnerNode,State,Name,GroupType | 
Sort-Object -Property OwnerNode | Format-Table -AutoSize | Out-File "$env:systemdrive\Tmp\EvidenceChangeNumber9454.txt" -Append



Get-Cluster -Name CL_SCVMM.br.automite.net | Get-ClusterGroup | 
Select-Object -Property Cluster,OwnerNode,State,Name,GroupType | 
Sort-Object -Property OwnerNode | Format-Table -AutoSize | Out-File "$env:systemdrive\Tmp\EvidenceChangeNumber9454.txt" -Append

#lista computadores inativos
Invoke-Command -ScriptBlock {dsquery computer domainroot -name *SERVER-00* -inactive 90} 


Suspend-ClusterNode -Name "ServerName" -Cluster "ClusterName" -Drain
Suspend-ClusterNode -Name "ServerName" -Cluster "ClusterName" -Drain



#get installed updates after given date 


Set-Location "C:\SCRIPTS\HYPER-V\HealthCheck"

$allHYPerVHost = (Get-Content -Path "C:\SCRIPTS\HYPER-V\HealthCheck\AllHYPerV.txt")

foreach ($HYPerVHost in $allHYPerVHost){
    Get-HotFix -ComputerName $HYPerVHost | Where-Object -FilterScript {$_.InstalledOn -ge "01/01/2018"} | Format-Table -AutoSize | Out-File .\Updates2018HyperV.txt -Append
} 


#get hotfix or get hotfix by ID
Get-WmiObject -ComputerName "ServerName" -Class win32_QuickFixEngineering

Get-WmiObject -ComputerName "ServerName" -Class win32_QuickFixEngineering -Filter "HotFixID='KB982132'"

####################################

#Get Last WSUS Report Machines
Get-WsusComputer -FromLastReportedStatusTime 01/01/2017 -ToLastReportedStatusTime 12/31/2017 | 
Select-Object -Property FullDomainName,IPAddress,OSFamily,OSDescription,ClientVersion,ComputerRole,LastSyncTime,LastReportedStatusTime | Export-Csv -Path .\WSUS-SYNC-2017.csv



#View where a VM is running
Get-Cluster -Name CLUSTER_NAME | Get-ClusterGroup | Where-Object -FilterScript {$_.Name -eq "ServerName"}

Get-Cluster -Name CLUSTER_NAME | Get-ClusterGroup | Where-Object -FilterScript {$_.Name -eq "ServerName"}


#get smb sessions
Get-SmbSession | Select-Object -Property ClientUserName,ClientComputerName,ScopeName,NumOpens,SessionID,SecondsIdle | Format-Table -AutoSize


#get team nic info for troubleshooting


$path = c:\temp\

[string]$dataAtual = (Get-Date -Format dd-MM-yyyy_HHmmss)

[string]$PCname = $env:COMPUTERNAME

Get-Netadapter | Format-Table -AutoSize | Out-File "$path\TeamNic-Info-$PCName-$dataAtual.txt" -Append 

Get-NetLbfoTeam | Format-Table -AutoSize | Out-File "$path\TeamNic-Info-$PCName-$dataAtual.txt" -Append 

Get-NetLbfoTeamMember | Format-List | Out-File "$path\TeamNic-Info-$PCName-$dataAtual.txt" -Append 

Get-NetLbfoTeamNic | Select-Object -Property Name,InterfaceDescription,Team,Default,Primary,VlanID,"TransmitLinkSpeed(Gbps)" | Format-Table -AutoSize |  Out-File "$path\TeamNic-Info-$PCName-$dataAtual.txt" -Append

Write-Output "Fim do Script de Coleta TEAM NIC INFO"


#view rdp session
Get-RDUserSession |ft Username,Idletime
Get-RDUserSession |select-object UserName,Servername,IdleTime,CreateTime



#View Folder with specific period and move it
Get-ChildItem | Where-Object -FilterScript {$_.LastWriteTime -gt "1/01/2018" -and $_.LastWriteTime -lt "02/01/2018"} | Move-Item -Destination .\2018\January



#Now how you can check that (check if $variablename has $null as value):

if (!$variablename) { Write-Host "variable is null" }

#And here if you wanna check if $variablename has any value except $null:

if ($variablename) { Write-Host "variable is NOT null" }


#view where you are connected
Get-PSDrive

#connect to registry
Set-Location HKLM:\SOFTWARE\BROADCOM

Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters



######################################################################
#Get events between two dates
Get-VIEvent -entity "ServerName" -MaxSamples([int]::MaxValue) | 
Where-Object -FilterScript {$_.CreatedTime -gt (Get-Date).AddDays(-11) -and $_.CreatedTime -lt (Get-Date).AddDays(-9)}

#####################################################################

Get-ADUser -SearchBase “OU=Buenos Aires,OU=Argentina,dc=argentina,dc=local” -Filter * -ResultSetSize 5000 | Select Name,SamAccountName

######################################################################
#Get Files in Directory sorted by last access time
#parameter width do not truncate

Get-ChildItem -Recurse | Select-Object -Property Name,@{label='LengthMB';expression={[math]::Round($PSItem.Length / 1MB,2)}},DirectoryName,LastWriteTime,LastAccessTime | 
Sort-Object -Property LastAccessTime | Format-Table -AutoSize| Out-File -Width 1024 -FilePath D:\ServerName.txt -Append


#View Share of Remove Computer
Get-WmiObject -Class Win32_Share

#Get windows Install Date
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Caption, Version, InstallDate, OSArchitecture




#VMWARE Disconnect CDROM DRIVES ISO DRIVES
Get-VM | Get-CDDrive | Where {$_.ISOPath -ne $null} | Set-CDDrive -NoMedia -Confirm:$false

$VMS = Get-VM $CDConnected | Get-CDDrive $VMS | where { ($_.ConnectionState.Connected -eq "true") -and ($_.ISOPath -notlike "*.ISO*")} 

$VMS = Get-VM $CDConnected | Get-CDDrive $VMS | where { ($_.ConnectionState.Connected -eq "true") -and ($_.ISOPath -notlike "*.ISO*")} 

If ($CDConnected -ne $null) {Set-CDDrive -connected 0 -StartConnected 0 $CDConnected -Confirm:$false }

Get-VM | Get-CDDrive | Where-Object -FilterScript {$_.ConnectionState.Connected -eq "true"} | Select-Object -Property Parent,Name,IsoPath


Get-VM | Where-Object {$_.PowerState -eq "PoweredOn"} | Get-CDDrive | Where-object -FilterScript {$_.IsoPath -like "*ISO*"} | Format-Table Parent, Name,IsoPath

Get-VM | Where-Object {$_.PowerState -eq "PoweredOn"} | Get-CDDrive | Where-object -FilterScript {$_.IsoPath -like "*ISO*"} | FT -AutoSize Parent,Name,IsoPath | Out-File -Width 2048 -FilePath "C:\temp\VMS-com-iso.txt" -Append

Get-VM | Where-Object {$_.PowerState -eq "PoweredOn"} | Get-CDDrive | Where-Object -FilterScript {$_.ConnectionState.Connected -eq "True"}

######################################
# Disk Space

$allVolumes = Get-Volume 

foreach ($volume in $allVolumes){
    $percentFree = [math]::Round(($volume.SizeRemaining / $volume.Size),4)*100
    $labelV = $volume.FileSystemLabel
    $driveLetter = $volume.DriveLetter
    $typeV = $volume.DriveType
    Write-Output "The volume Named: $labelV - Drive Letter: $driveLetter - Type $typeV has $percentFree % free"

}


########################################
#Control Panel Itens

Get-ControlPanelItem | Where-Object -FilterScript {$_.Name -like "c*"}

#Get Serial Physical Disk NAA
$computerName = Read-Host "Digite o nome da máquina ao qual deseja conectar"
New-PSSession -ComputerName $computername
Enter-PSSession -Id 1
Get-PhysicalDisk |
Where-Object -FilterScript {$PSITEM.BusType -like 'Fibre Channel'} |
Select-Object -Property FriendlyName,UniqueID,SerialNumber,BusType,Manufacturer,Model,LogicalSectorSize,@{label='Size(GB)';expression={'{0:N2}' -f ($PSItem.Size / 1GB)}} | Sort-Object -Property FriendlyName | Format-Table -AutoSize -Wrap | Out-File -Width 1024 -FilePath .\LUN-INFO.txt -Append

Get-PhysicalDisk | 
Where-Object -FilterScript {$PSITEM.BusType -like 'Fibre Channel'} | 
Select-Object -First 1 | Format-List *


#get sql installed
Get-WmiObject -ClassName win32_softwarefeature | Where-Object -FilterScript {$_.ProductName -like "SQL Server*"} | 
Select-Object -Property ProductName,Vendor,Caption,Version | 
format-table -AutoSize

#last boot time, boot, uptime
Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime

#UPTIME
$today = (get-date)

$today = (get-date -Format ddMMyyyy).ToString()

$lastBoot = Get-cimInstance -className Win32_operatingsystem | Select-Object -ExpandProperty lastbootuptime

$diff = New-TimeSpan -Start $lastBoot -End $today

$tDays = $diff.Days.ToString()

$tHours = $diff.Hours.ToString()

$tUptime = $tDays + 'd' + $tHours + 'h'


Get-CimInstance -ComputerName "ServerName" -ClassName win32_operatingsystem | select csname, lastbootuptime

Get-CimInstance -ComputerName "ServerName" -ClassName win32_operatingsystem | Select-Object -Property CSName,CurrentTimezone,LocalDateTime,LastBootUpTime

Get-WmiObject -ComputerName "ServerName" -Class win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}

Get-WmiObject -Class win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}

#boot reboot uptime
Get-WmiObject -ComputerName (Read-Host "Enter Computername") -Class Win32_OperatingSystem | 
Select-Object -Property @{label = 'Computername';Expression={$_.CSName}},
                        @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}},
                        Status,
                        @{LABEL='LocalDateTime';EXPRESSION={$_.ConverttoDateTime($_.LocalDateTime)}},
                        @{LABEL='InstallDate';EXPRESSION={$_.ConverttoDateTime($_.InstallDate)}}




#system center get info about vm
get-vm | Where-Object -FilterScript {$_.CreationTime -gt "05/05/2018"} | Select-Object -Property ComputerName,VirtualMachineState,CPUCount,CPUType,MemoryAssignedMB,OperatingSystem,Location,Hostname,Owner,ObjectType,CreationTime,AddedTime,ModifiedTime |Export-Csv -NoTypeInformation -Path C:\tmp\teste.csv

#system center get job
Get-Job | Where-Object -FilterScript {$_.ResultName -eq "AUTOMITE0048"} | EXPORT-CSV -NoTypeInformation -Path c:\TMP\AUTOMITE0048LOG.csv


#number of logical processors number of processors cpu 
Get-WmiObject –class Win32_processor | ft systemname,Name,DeviceID,NumberOfCores,NumberOfLogicalProcessors, Addresswidth

Get-WmiObject -ComputerName SERVER-VMM0262 -Class Win32_processor | Select-Object -Property SystemName,Name,Caption,DeviceID,NumberofCores,NumberOfLogicalProcessors | Format-Table -AutoSize 

Get-CimInstance -computername SERVER-VMM0262 -ClassName 'Win32_Processor' | Measure-Object -Property 'NumberOfCores' -Sum;

#validate services automatic and stopped
Get-CimInstance win32_service -Filter "startmode = 'auto' AND state != 'running' AND Exitcode !=0 " -ComputerName sql1 | select name, startname, exitcode

Get-wmiobject win32_service -Filter "startmode = 'auto' AND state != 'running' AND Exitcode !=0 " -ComputerName sql1 | select name, startname, exitcode

Get-wmiobject win32_service -Filter "state != 'running' AND Exitcode !=0 " -ComputerName sql1 | select name, startname, exitcode

Get-WmiObject -Class Win32_Service -Filter "state != 'running' AND ExitCode !=0" -ComputerName TESTE | Select-Object -Property Name,StartName,ExitCode | Sort-Object -Property Name  


Get-Service | Where-Object -FilterScript {$_.status -like "*pending"} | Format-Table -AutoSize

Get-Service -ComputerName (Get-Content C:\Scripts\Box\Input\HYPerV\AllHYPerVHosts.txt) -Name windows_exporter | Select-Object -Property MachineName,ServiceName,Status,StartType

Get-Service | Where-Object -FilterScript {$_.status -ne "Running"} | Format-Table -AutoSize

Get-WmiObject -Class Win32_Service -Filter "state != 'running' AND ExitCode !=0" | Select-Object -Property Name,DisplayName,StartName,ExitCode | Format-Table -AutoSize -Wrap

#GET SERVICE NOT RUNNING EXIT CODE DIFERENTE DE 0, SERVIÇOS COM ERRO ERROR CODE - CODIGOS DE ERRO DE SERVIÇO
#https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-
Get-WmiObject -Class win32_service | 
Where-Object -FilterScript {$_.State -ne "Running" -and $_.StartMode -ne "Disabled" -and $_.ExitCode -ne 0} | 
Select-Object -Property Caption, StartMode,ExitCode | 
Sort-Object -Property Caption | Format-Table -AutoSize -Wrap


# Rodar comando DOS direto do powershell
cmd /c "sc.exe queryex aelookupsvc"


#GET NTFS BLOCK SIZE 
#GET NTFS ALLOCATION UNIT SIZE
#https://www.bytesizedalex.com/get-windows-ntfs-block-size/

Get-WmiObject -Class Win32_Volume | Select-Object Label, BlockSize | Format-Table -AutoSize

Get-CimInstance -ClassName Win32_Volume | Select-Object Label, BlockSize | Format-Table -AutoSize

Get-CimInstance -ClassName Win32_Volume | Select-Object Name, FileSystem, Label, BlockSize | Sort-Object Name | Format-Table -AutoSize


#Get all clusters in a domain
Get-Cluster -Domain br.automite.net

FailoverClusters\get-cluster -Domain br.automite.net

#Add Blank Line to a text file
Write-Output "`n" | Out-File $file -Append



#GET WWN WINDOWS 2012 MACHINE HBA
#https://support.purestorage.com/Solutions/Microsoft_Platform_Guide/FlashArray_Connectivity/Retrieve_World_Wide_Names_(WWNs)_on_Windows_Server
Get-WmiObject -class MSFC_FCAdapterHBAAttributes -namespace "root\WMI" | ForEach-Object {(($_.NodeWWN) | ForEach-Object {"{0:x}" -f $_}) -join ":"}

#20:0:0:25:b5:51:0:d
#20:0:0:25:b5:51:0:d

Get-InitiatorPort | Select-Object -Property NodeAddress,PortAddress,ConnectionType


#on WINDOWS 2003
#https://www.yourcomputer.in/how-to-check-wwn-on-windows-server/

#ACTIVE DIRECTORY PASSWORD LAST SET
Get-ADUser -Identity Domain_User -Properties * | Select-Object -Property PasswordLastSet



#GET ALL IP CONFIG HOSTS ESXi
Get-VMHost | Select Name,@{n="ManagementIP"; e={Get-VMHostNetworkAdapter -VMHost $_ -VMKernel | ?{$_.ManagementTrafficEnabled} | %{$_.Ip}}}, PowerState, Manufacturer, Model



Get-VMHost | Select Name,
                    @{n="DeviceNameMGMT"; e={Get-VMHostNetworkAdapter -VMHost $_ -VMKernel | Where-Object {$_.ManagementTrafficEnabled} | ForEach-Object {$_.DeviceName}}},
                    @{n="ManagementIP"; e={Get-VMHostNetworkAdapter -VMHost $_ -VMKernel | Where-Object {$_.ManagementTrafficEnabled} | ForEach-Object {$_.Ip}}},
                    @{n="SubnetMaskMGMT"; e={Get-VMHostNetworkAdapter -VMHost $_ -VMKernel | Where-Object {$_.ManagementTrafficEnabled} | ForEach-Object {$_.SubnetMask}}},
                    @{n="DeviceNameVmotion";e={Get-VMHostNetworkAdapter -VmHost $_ -Vmkernel | Where-Object {$_.VMotionEnabled} | ForEach-Object {$_.DeviceName}}},
                    @{n="VmotionIP";e={Get-VMHostNetworkAdapter -VmHost $_ -Vmkernel | Where-Object {$_.VMotionEnabled} | ForEach-Object {$_.Ip}}},
                    @{n="SubnetMaskVmotion";e={Get-VMHostNetworkAdapter -VmHost $_ -Vmkernel | Where-Object {$_.VMotionEnabled} | ForEach-Object {$_.SubnetMask}}},
                    PowerState, Manufacturer, Model




#Inventário SCVMM - VMS - Hyper-V
Get-SCVMHost | Get-VM | FT HostName,Name,Owner,CreationTime,OperatingSystem,VirtualMachineState,VMAddition,CPUCount,CPUType,Memory,DiskResources,Location,HasPassthroughDisk,VirtualFibreChannelAdapters -AutoSize -Wrap > InventarioVMSHYPerV.txt 


Get-SCVirtualMachine | Select-Object -Property VMCPath, 
                                               VirtualMachineState, 
                                               @{label='TotalSize(GB)';expression={[math]::Round($PSItem.TotalSize / 1GB,2)}},
                                               MemoryAssignedMB,
                                               Status,
                                               StartAction,
                                               StopAction,
                                               BiosGuid,
                                               ComputerNameString,
                                               OperatingSystemShutdownEnabled,
                                               TimeSynchronizationEnabled,
                                               DataExchangeEnabled,
                                               HeartbeatEnabled,
                                               BackupEnabled,
                                               CheckpointLocation,
                                               Location,
                                               CreationTime,
                                               OperatingSystem,
                                               HasVMAdditions,
                                               VMAddition,
                                               CPUCount,
                                               CPUType,
                                               IsHighlyAvailable,
                                               DynamicMemoryEnabled,
                                               UseHardwareAssistedVirtualization,
                                               HostName,
                                               Owner,
                                               NumLockEnabled



#data de criação, created date, when create
Get-ADComputer AUTOMITE0001 -Properties * | Select name,description,whenCreated,whenChanged

Get-ADComputer AUTOMITE002 -Properties * | Select name,description,whenCreated,whenChanged

#users
Get-ADUser UserName -Properties * | Select SamAccountName,givenName,sn,description,whenCreated,whenChanged

#groups
Get-ADGroup GroupName -Properties * | Select SamAccountName,description,whenCreated,whenChanged

#computers
Get-ADComputer ComputerName -Properties * | Select name,description,whenCreated,whenChanged


#Get Windows Version, Versão do Windows,Service Pack, Nome do SO

(Get-WmiObject -Class win32_operatingsystem).Version
(Get-WmiObject -Class Win32_OperatingSystem).Caption
(Get-WmiObject -Class Win32_OperatingSystem).CSDVersion
(Get-WmiObject -ComputerName automitedc4 -Class win32_operatingsystem).Name.Split("|")[0]

Get-WmiObject -ComputerName automitedc4 -Class Win32_OperatingSystem | Select-Object -Property CSName,Version,Caption,CSDVersion,OSArchitecture

[System.Environment]::OSVersion.Version

[System.Environment]::OSVersion.Version.ToString()


$message = 'there is an error with your file'
$message -match 'error'

'123-45-6789' -match '\d\d\d-\d\d-\d\d\d\d'



#Now how you can check that (check if $variablename has $null as value):

if (!$variablename) { Write-Host "variable is null" }

#And here if you wanna check if $variablename has any value except $null:

if ($variablename) { Write-Host "variable is NOT null" }



#comandos para manipular variáveis
Get-Command -Noun Variable | Format-Table -Property Name,Definition -AutoSize -Wrap

#find type accelerators
#https://blogs.technet.microsoft.com/heyscriptingguy/2014/05/28/powertip-find-a-list-of-powershell-type-accelerators/
#https://blogs.technet.microsoft.com/heyscriptingguy/2013/07/08/use-powershell-to-find-powershell-type-accelerators/
#https://www.jaapbrasser.com/working-with-type-accelerators-in-powershell/
#https://renenyffenegger.ch/notes/Windows/PowerShell/language/object/type/accelerators
#https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/understanding-type-accelerators-part-2
#https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/understanding-type-accelerators-part-1
[PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Get 

$accelerators = [PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Get 

$accelerators.Count

$accels = [psObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::Get
$names  = $accels.keys | sort-object

foreach ($name in $names) {
  '{0, -30} {1}' -f $name, $accels[$name].FullName
}


([adsisearcher]'samaccountname=julianoabr').FindOne()

[bool]([adsisearcher]"samaccountname=automiteusr001").FindOne()
[bool](Get-ADUser -filter 'samaccountname -eq "automiteusr001"')

#type literals
[System.Net.NetworkInformation.IPStatus]

[System.Net.NetworkInformation.Ping]

[System.Environment]::OSVersion

[System.Environment]::CommandLine


#View Secure Channel Domain
Test-ComputerSecureChannel -Verbose

#Test-ComputerSecureChannel -Repair -Verbose


#cluster disk corruption settings
#Checks all logical disks on a node for the dirty bit using PowerShell
Get-WMIObject Win32_LogicalDisk | ft DeviceID, VolumeDirty


# Check the parameter on a disk
Get-ClusterResource "<Cluster Disk Name>" | Get-Parameter | fl DiskRunChkDsk

 
# Example
Get-ClusterResource "Witness Disk" | Get-Parameter | fl DiskRunChkDsk


# Set the parameter on a disk ( is the x is the number we want to set)
Get-ClusterResource "<Cluster Disk Name>" | Set-Parameter DiskRunChkDsk = x

# Example
Get-ClusterResource "Witness Disk" | Set-Parameter DiskRunChkDsk = 4


#You can check if the dirty bit has been set on all CSV volumes using the command
Get-WMIObject Win32_Volume | ft Caption, DirtyBitSet -autosize


# Check the values of the parameters
Get-ClusterSharedVolume | Get-ClusterParameter

 

#Set the value of the DiskRunChkDsk parameter
Get-ClusterSharedVolume | Set-ClusterParameter DiskRunChkDsk 4

#CLUSTER COMMANDS
#https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ee619744(v=ws.10)#BKMK_basic


#change powershell console
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.buffersize
$newsize.height = 3000
$newsize.width = 150
$pswindow.buffersize = $newsize
$newsize = $pswindow.windowsize
$newsize.height = 60
$newsize.width = 150
$pswindow.windowsize = $newsize
$pswindow.windowtitle = "My PowerShell Session"
$pswindow.foregroundcolor = "Yellow"
$pswindow.backgroundcolor = "Black"


#PAUSE POWERSHELL
function Pause
{

   Read-Host 'Press Enter to continue…' | Out-Null
}


#Get computers that name starts with File Server
Get-ADComputer -Filter 'Name -like "FileServer*"' -Properties IPv4Address | FT Name,DNSHostName,IPv4Address -A


#GET COMPUTERS WITH HYP IN THE NAME
Get-ADComputer -Filter 'Name -like "*HYP*"'| Select-Object -Property DNSHostName | Sort-Object -Property DNSHostname



#MUDA LINGUAGEM PADRÃO DO TECLADO
Get-WinUserLanguageList

Set-WinUserLanguageList -LanguageList pt-BR

Set-WinUserLanguageList -LanguageList pt-BR,en-US -Force -Verbose


#disabel firewall
#Turning Off Firewall Using PowerShell
#On the PowerShell, execute the following command. This will turn off your firewall.
#https://www.faqforge.com/windows/turn-off-firewall-using-powershell-command-prompt/

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

#add default route
#https://blogs.technet.microsoft.com/bruce_adamczak/2013/01/23/windows-2012-core-survival-guide-default-gateway-settings/
New-NetRoute -interfaceindex 15 -NextHop "192.168.0.1" -destinationprefix "0.0.0.0/0"


#add ip address to APIPA INTERFACE
New-NetIPAddress -InterfaceIndex 7 -AddressFamily IPv4 -IPAddress 172.16.0.1

#change ip address
Set-NetIPAddress -InterfaceIndex 7 -AddressFamily IPv4 -IPAddress 172.16.0.2


#FQDN
[System.Net.Dns]::GetHostByName($env:computerName)

[System.Net.Dns]::GetHostByName($env:computerName).HostName

#To get FQDN of Remote computer:

[System.Net.Dns]::GetHostByName('mytestpc1')

#or
#For better formatted value use:

[System.Net.Dns]::GetHostByName('automitecomputer01').HostName

$Domain=[System.Net.Dns]::GetHostByName($VM).Hostname.split('.')
$Domain=$Domain[1]+'.'+$Domain[2]

$server = Get-ADComputer serverName -Server domainName -Properties * | select Name, DistinguishedName
$domain = $server.DistinguishedName -split ","
$domain = $domain | ? {$_ -like 'DC=*'}
$domain = $domain -join "."
$domain = $domain -replace "DC="
$FQDN = $server.Name + "." + $domain


$allDVSwitch = Get-VDSwitch


#Get all Events of specific VM. 
Get-VIEvent -MaxSamples([int]::MaxValue) | Where-Object {$_.FullFormattedMessage -like "*AUTNN9*"} | Select-Object -Property CreatedTime,Username,FullFormattedMessage



#EVITAR RESULTADOS TRUNCADOS COM ... TRES PONTOS
#How to Prevent Truncation of Long Output in Exchange Management Shell
#https://practical365.com/exchange-server/how-to-prevent-truncation-of-long-output-in-exchange-management-shell/
#https://social.technet.microsoft.com/Forums/exchange/en-US/25f8da05-88ec-443d-9412-ea79baa5c619/powershell-results-are-truncated-how-can-i-expand-to-show-fully?forum=exchangesvradminlegacy
$FormatEnumerationLimit #padrão é 4

$FormatEnumerationLimit = -1 # unlimited


# ------------------------------------------------------------------------------
# Migrate Storage Wizard Script
# ------------------------------------------------------------------------------
# Script generated on Tuesday, September 18, 2018 12:14:33 PM by Virtual Machine Manager
# 
# For additional help on cmdlet usage, type get-help <cmdlet name>
# ------------------------------------------------------------------------------


$vm = Get-SCVirtualMachine -ID "20873a75-717e-42f5-acf4-3d84423fb839" -Name "AUTOMITE0015"

$vmHost = Get-SCVMHost | where { $_.Name -eq "AUTOMITESRV003.server.local" }

Move-SCVirtualMachine -VM $vm -VMHost $vmHost -Path "C:\ClusterStorage\Volume2" -UseLAN -RunAsynchronously -UseDiffDiskOptimization -JobGroup "cf26c507-3466-4b33-bcc1-b65cdea663a4"


#Ver aplicações instaladas, software instalados
#https://sid-500.com/2018/04/02/powershell-how-to-get-a-list-of-all-installed-software-on-remote-computers/

$computer = read-host "digite o nome da vm"

Write-Output "Aplicações Instaladas"

Get-WmiObject -ComputerName $computer -ClassName win32_softwarefeature | Select-Object -Property ProductName,Vendor,Caption,Version | Format-List 

Get-WmiObject -ComputerName $computer -ClassName win32_softwarefeature | Select-Object -Property PSComputerName,ProductName,Vendor,Caption,Version | Export-Csv -Path C:\temp\soft.csv -NoTypeInformation

Get-CimInstance win32_product | Select-Object Name, PackageName, InstallDate | Out-GridView

(Get-ADComputer -Filter * -Searchbase "OU=Test,DC=sid-500,DC=com").Name | Out-File "C:\Temp\Computer.txt" | notepad "C:\Temp\Computer.txt"

Get-CimInstance -ComputerName (Get-Content "C:\Temp\Computer.txt") -ClassName win32_product -ErrorAction SilentlyContinue| Select-Object PSComputerName, Name, PackageName, InstallDate | Out-GridView


#GET SO REMOTE SISTEMA OPERACIONAL
Get-WmiObject -ComputerName (Get-Content C:\Temp\listaFindSO.txt) -Class win32_operatingsystem -ErrorAction SilentlyContinue | Select-Object -Property CSName,Version,Caption | Export-Csv -NoTypeInformation -Path C:\temp\outputso.csv -Append

#https://blogs.technet.microsoft.com/jonjor/2010/10/05/scvmm-powershell-commands-cheat-sheet/
#SCVMM Comandos - Commands


#body as HTML corpo do e-mail como HTML 
$body = Get-Content C:\Scripts\Reports\DiskReport.htm -Raw
Send-MailMessage -Body $body -BodyAsHtml # other parameters

$body = [System.IO.File]::ReadAllText('C:\Scripts\Reports\DiskReport.hml')
Send-MailMessage -Body $body -BodyAsHtml # other parameters


#Métodos Matemática 
[math].GetMethods() | Select-Object -Property Name

#VER ERRO SEM TRUNCAR NO POWERSHELL
$error[0] | fl * -force


#view process of a user
Get-process  | where {$_.cpu -gt 100} | select cpu,pm,vm,processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}} | ft -AutoSize

Get-Process -IncludeUserName | Where-Object -FilterScript {$_.Username -like "*srv_sql*"}

Invoke-Command -ComputerName AUTOMITE756 -ScriptBlock{Get-Process -IncludeUserName | Sort-Object -Property UserName}

Invoke-Command -ComputerName AUTOMITE756 -ScriptBlock{Get-Process -IncludeUserName | 
Select-Object -Property Handles,ID, ProcessName,Username,@{label='WorkingSet';Expression={[math]::Round(($_.WorkingSet/1MB),2)}} | Sort-Object -Property WorkingSet | Format-Table -AutoSize}



#before PS4
Get-WmiObject Win32_Process -Filter "name='calculator.exe'" | 
Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | 
Sort-Object UserName, Name

#COLOCAR A DATA NA SAIDA DO NOME DO ARQUIVO
out-file -filepath "C:\temp\mybackup $(get-date -f yyyy-MM-dd).zip"


#time out 
#https://social.technet.microsoft.com/Forums/en-US/dd0c3072-670e-4f8b-9c4e-089049fc6b95/powershell-function-time-out?forum=winserverpowershell
# Start Job
$job = Start-Job -ScriptBlock {
    Start-Sleep -Seconds 5000
}
# Wait for job to complete with timeout (in sec)
$job | Wait-Job -Timeout 2

# Check to see if any jobs are still running and stop them
$job | Where-Object {$_.State -ne "Completed"} | Stop-Job


#Alternativas do comando Get-WindowsFeature

Get-WindowsFeature #(Consulta)
Remove-WindowsFeature #(Remove a feature sem desinstalar os binários)
Install-WindowsFeature #(Instala)
Uninstall-WindowsFeature #(Desinstala a feature removendo os binários do Windows. Instalação posterior só com a ISO do Windows.)

#Exemplos do comando Get-WindowsFeature

Get-WindowsFeature –ComputerName "Server01" | Where InstallState -Eq Installed
Get-WindowsFeature –ComputerName "Server01" | Where InstallState -Eq Removed
Get-WindowsFeature –ComputerName "Server01" | Where InstallState -Eq Available
Get-WindowsFeature -Name "AD*, Web*"
Get-WindowsFeature -Vhd "D:\ps-test\vhd1.vhd"
Get-WindowsFeature -ComputerName "Server1" -Credential "contoso.com\user1"

#Adicionando e Removendo o Modo Gráfico “GUI” no Windows Server 2012 R2

#A tabela abaixo exemplifica quais os parâmetros devem ser instalados ou desinstalados a fim de obter um determinado tipo de instalação.

#Tipo de instalação	Commando Uninstall/Install-WindowsFeature
#Server Core	Nenhum
#Minimal Server Interface	Server-Gui-Mgmt-Infra, Server-Gui-Shell
#Interface gráfica completa	Server-Gui-Mgmt-Infra, Server-Gui-Shell, Desktop-Experience

Dism /online /enable-feature /featurename:Server-Gui-Mgmt /featurename:Server-Gui-Shell /featurename:ServerCore-FullServer

Get-WindowsFeature | Where Installed
Remove-WindowsFeature Server-Gui-Shell, Server-Gui-Mgmt-Infra -Restart #(Converte GUI em Core e ainda permite fazer rollback)
Install-WindowsFeature Server-Gui-Mgmt-Infra,Server-Gui-Shell -Restart #(Converte Core em GUI. ISO será necessário dependendo de como foi removido a GUi anteriormente, ou seja, Uninstall ou Remove?)
Uninstall-WindowsFeature Server-Gui-Mgmt-Infra,server-gui-shell -Restart #(Converte GUI em Core. Rollback só com a ISO do S.O e executando o procedimento abaixo

#To convert from a Server Core installation to a Server with a GUI installation, determine the index number for a Server with a GUI image

#Example: Get-WindowsImage -ImagePath <path to wim>\install.wim.

Install-WindowsFeature Server-Gui-Mgmt-Infra,Server-Gui-Shell –Restart –Source c:\mountdir\windows\winsxs #(VIA ISO)
Install-WindowsFeature Server-Gui-Mgmt-Infra,Server-Gui-Shell –Restart #(Via Windows Update)

#Convertendo o servidor de GUI para Minimal Grafical Mode

Get-WindowsFeature -Name *gui*

Install-WindowsFeature Server-Gui-Mgmt-Infra -Restart #(Torna Minimal Server Interface)


#GET WINDOWS VERSION E SERIAL
Get-WmiObject -Class Win32_OperatingSystem -EnableAllPrivileges 


Get-WmiObject -Class Win32_OperatingSystem -EnableAllPrivileges | Get-Member


#REBOOT WINDOWS MACHINE
(Get-WmiObject -Class Win32_OperatingSystem -EnableAllPrivileges).Reboot()

$OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName 'ServerName' -Credential (Get-Credential)
$OS.Reboot()


#CONVERTER STRING EM NÚMERO READ-HOST
#https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/11/use-powershell-to-easily-convert-decimal-to-binary-and-back/
$num1 = read-host -Prompt "Enter Ist number"
$num2 = Read-Host -Prompt "Enter Second number" 

[int]$Num3 = [convert]::ToInt32($num1, 10)
[int]$Num2 = [convert]::ToInt32($num2, 10)

$sum = $num1 + $num2

Write-Host "Result: $sum"

$num1 = [convert]::ToDouble($num1)

$teste2 = [convert]::ToInt32($teste)


$teste2 = $teste.ToInt32($null)

#CONFIGURAÇÃO INICIAL POWERCLI
Import-Module -Name Vmware.VimAutomation.Core -Verbose
Set-PowerCLIConfiguration -InvalidCertificateAction Warn -Scope AllUsers
Set-PowerCliConfiguration -InvalidCertificateAction Ignore -Scope AllUsers
Set-PowerCLIConfiguration -ParticipateInCeip:$false -Scope AllUsers

#ÍCONE DO POWERCLI
%SystemRoot%\Installer\{2E4FAF13-B720-4385-A23C-5C38D742D6C6}\DS64Key_486A5081294F4BBA8FCC02C819EA8C82.exe


#Encrypt Password
#https://gallery.technet.microsoft.com/Execute-PowerShell-Script-38881dce
#https://social.technet.microsoft.com/wiki/contents/articles/4546.working-with-passwords-secure-strings-and-credentials-in-windows-powershell.aspx?Redirected=true

############################################################################################################# 
###Script        :    Executing PS scripts from remote machine with alternate credentials with password PROMPTS 
###Developer    :    Chendrayan Venkatesan 
###Company        :     Tata Consultancy Service 
############################################################################################################# 
 
 
$ComputerName = "SERVER" 
$Credential = "DOMAIN\ADMIN" 
$Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Credential $Credential -Filter "Name='IISADMIN'" 
$Service


############################################################################################################# 
###Script        :    Executing PS scripts from remote machine with alternate credentials with password PROMPTS 
###Developer    :    Chendrayan Venkatesan 
###Company        :     Tata Consultancy Service 
############################################################################################################# 
 
 
$ComputerName = "SERVER" 
$UserName = Read-Host "Enter User Name:" 
$Password = Read-Host -AsSecureString "Enter Your Password:" 
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName , $Password 
$Service = Get-WmiObject -Class Win32_Service -ComputerName $ComputerName -Credential $Credential -Filter "Name='IISADMIN'" 
$Service

######################################################################################## 
###Script        :    To get Credential as SECURE STRING and save in Local Drive 
###Developer    :    Chendrayan Venkatesan 
###Company        :     Tata Consultancy Service 
######################################################################################## 
 
Read-Host "DOMAIN\USERNAME" -AsSecureString | ConvertFrom-SecureString | Out-File C:\SecureData\SecureString.txt


######################################################################################## 
###Script        :    To Execute PowerShell script with other credentials without prompts 
###Developer    :    Chendrayan Venkatesan 
###Company        :     Tata Consultancy Service 
######################################################################################## 
 
#SharePoint Admin Account 
$SPAdmin = "DOMAIN\ADMIN" 
$Password = Get-Content C:\SecureDate\securestring.txt | convertto-securestring 
$Credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $SPAdmin, $Password 
 
Get-WmiObject -Class Win32_Service -ComputerName "Server" -Filter "Name='ServiceName'" -Credential $Credential

#https://www.dropbox.com/sh/i001giq6jx67fl2/AAArfM_42DqmpOtiJlMX8Q33a?preview=GSO-LAB-UCS-REPORT.html
#UCS CONNECT
#https://blogs.cisco.com/developer/cisco-ucs-automation-part2-a-step-by-step-guide-to-connecting-and-disconnecting-using-ucs-powertool
#https://jeremywaldrop.wordpress.com/2012/04/04/cisco-ucs-powershell-health-check-report/
#UCS HEALTH CHECK

#KILL A PROCESS 
$id = Get-WmiObject -Class Win32_Service -Filter "Name like 'winrm'" | Select-Object -ExpandProperty ID
$id
Stop-Process -Id $id -Force -Verbose
Get-Service -Name WinRM | Start-Service
Get-Service -Name WinRM


#Enumerate dotnet type to find possible service status values.
$type = (Get-Service)[0].status.GetType().FullName

Get-EnumValue $type


#REMOVER O QUE NÃO ESTÁ EM OUTRO GRUPO. SERVE PARA ARRAYS
#https://stackoverflow.com/questions/6368386/comparing-two-arrays-get-the-values-which-are-not-common/35872835

$a = 1,2,3,4,5
$b = 4,5,6,7,8

$Yellow = $a | Where {$b -NotContains $_}
#$Yellow contains all the items in $a except the ones that are in $b:


$Blue = $b | Where {$a -NotContains $_}
#$Blue contains all the items in $b except the ones that are in $a:


$Green = $a | Where {$b -Contains $_}
#Not in question, but anyways; Green contains the items that are in both $a and $b.



#task schedules powershell 
#C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
#-nologo -noprofile -file "C:\SCRIPTS\BOX\Process\SCVMM\AVHDX\Get-ExcessiveAVHDX-LAN.ps1"
#C:\SCRIPTS\HYPerV\HealthCheck

#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_requires?view=powershell-7
#Requires -Version <N>[.<n>]
#Requires -PSSnapin <PSSnapin-Name> [-Version <N>[.<n>]]
#Requires -Modules { <Module-Name> | <Hashtable> }
#Requires -PSEdition <PSEdition-Name>
#Requires -ShellId <ShellId>
#Requires -RunAsAdministrator


#get windows drivers
Get-WindowsDriver –Online -All

Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion

Get-WmiObject -ComputerName SERVER-HYP0028 -class Win32_PnPSignedDriver| select devicename, driverversion | export-csv -NoTypeInformation  -Path C:\Temp\HYP029drivers.csv -Encoding UTF8


#Remove Hyper-V Network Adapter
#https://www.altaro.com/HYPer-v/work-Hyper-v-virtual-network-adapters/
Remove-VMNetworkAdapter -ManagementOS -Name "vNIC_XPTO" -Confirm:$true -Verbose

Get-VMNetworkAdapter -All



#Confirm
#Are you sure you want to perform this action?
#Remove-VMNetworkAdapter will remove the network adapter "vNIC_XPTO".



#TRUSTED HOSTS 
#https://blogs.technet.microsoft.com/heyscriptingguy/2012/11/15/powertip-use-powershell-to-view-trusted-hosts/

#http://winintro.ru/windowspowershell2corehelp.en/html/f23b65e2-c608-485d-95f5-a8c20e00f1fc.htm

Get-Item WSMan:\localhost\Client\TrustedHosts
get-item wsman:\localhost\Client\TrustedHosts

set-item wsman:\localhost\Client\TrustedHosts -value *

#POWERSHELL CITRIX DOCUMENTATION
https://citrix.github.io/delivery-controller-sdk/
https://citrix.github.io/delivery-controller-sdk/Broker/Get-BrokerDesktopGroup/



#VERSÃO DLL DLL VERSION
get-item "C:\Windows\System32\qmgr.dll" | Select-Object -ExpandProperty VersionInfo


#DIFFERENCE BETWEEN MODULES AND SNAP-INS
#https://blogs.technet.microsoft.com/aviraj/2011/12/03/powershell-using-modules-and-snap-ins-whats-the-difference-between-modules-snap-ins/

<#
A module is a package of commands and other items that you can use in Windows PowerShell. 
After you run the setup program or save the module to disk, you can import the module into your Windows PowerShell session and use the commands and items. 
You can also use modules to organize the cmdlets, providers, functions, aliases, and other commands that you create, and share them with others.

About Snap-ins

A Windows PowerShell snap-in (PSSnapin) is a dynamic link library (.dll) that implements cmdlets and providers. 
When you receive a snap-in, you need to install it, and then you can add the cmdlets and providers in the snap-in to your Windows PowerShell session.
#>

#rodar comandos num array de máquinas
$array = 200..299

foreach ($a in $array){

    $machineName = "ServerName" + "$a"

    Write-Output "Verificando a máquina $machineName"

    Get-SCVirtualMachine -Name $machineName | Set-SCVirtualMachine -EnableTimeSync $False -ErrorAction Continue -Verbose

    Start-Sleep -Milliseconds 300

}


#Powershell arrays
#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_arrays?view=powershell-6

$A = 22,5,10,8,12,9,80
$B = 5..8

$A.GetType()

[int32[]]$ia = 1500,2230,3350,4000

[Diagnostics.Process[]]$zz = Get-Process

$arrayteste = @()

$a = @("Hello World")
$a.Count

$b = @()
$b.Count


(0..20).Where{ $_ % 2 }



#https://gallery.technet.microsoft.com/HYPer-V-Network-VSP-Bind-cf937850
#HYPER-V NETWORK BIND


#xen app health check 6.5
#https://deptive.co.nz/blog/xenapp-farm-health-check-v2/


#UTC TIME HORÁRIO HORA
$server = Read-Host "Digite o nome do servidor"
$UTCTime = ([wmi]'').ConvertToDateTime((Get-WmiObject -Class win32_operatingsystem -ComputerName $server).LocalDateTime).toUniversalTime()
$LocalTime = ([wmi]'').ConvertToDateTime((Get-WmiObject -Class win32_operatingsystem -ComputerName $server).LocalDateTime)


#DATA COM LOCAL ESPECÍFICO SPECIFIC LOCALE
[System.Threading.Thread]::CurrentThread.CurrentUICulture = "en-US";[System.Threading.Thread]::CurrentThread.CurrentCulture = "en-US";(Get-Date -UFormat "%A, %d de %B de %Y - %R").ToString()

[System.Threading.Thread]::CurrentThread.CurrentUICulture = "pt-Br";[System.Threading.Thread]::CurrentThread.CurrentCulture = "pt-Br";(Get-Date -UFormat "%A, %d de %B de %Y - %R").ToString()


#RESET WINDOWS UPDATE
#https://gallery.technet.microsoft.com/scriptcenter/Reset-WindowsUpdateps1-e0c5eb78


#DATA E COMPUTERNAME
Get-WmiObject -Class win32_operatingsystem | Select-Object -Property CSName,Caption,@{LABEL='LocalDateTime';EXPRESSION={$_.ConverttoDateTime($_.LocalDateTime)}}


#SCVMM OPTIMIZE CLUSTER
$hostCluster = Get-SCVMHostCluster -Name "AUTOMITESRV01.sth.local"
Start-SCDynamicOptimization -VMHostCluster $hostCluster



#https://devblogs.microsoft.com/scripting/hey-scripting-guy-how-can-i-use-the-erroraction-preference-parameter/
#https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.actionpreference?redirectedfrom=MSDN&view=powershellsdk-7.0.0
#https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.actionpreference?redirectedfrom=MSDN&view=powershellsdk-1.1.0
#warningaction and erroraction
#ea 0 SilentlyContinue
#ea 1 Stop
#ea 2 Continue
#ea 3 Inquire

#Break	6	
#Continue	2	Handle this event as normal and continue
#Ignore	4	Ignore the event completely (not even logging it to the target stream)
#Inquire	3	Ask whether to stop or continue
#SilentlyContinue	0	Ignore this event and continue
#Stop	1	Stop the command
#Suspend	5  Suspend the command for further diagnosis. Supported only for workflows.


#Load the VMware Powershell snapin if the script is being executed in PowerShell
Add-PSSnapin VMware.VimAutomation.Core -ErrorAction 'SilentlyContinue'


#GET MEMBERS OF AD GROUP
Get-ADGroup -Identity _Automite_Grp_N3 | Get-ADGroupMember | Select-Object -Property Name,SamAccountName | Sort-Object -Property Name

#REMOVE MEMBERS OF A GROUP
Get-ADGroup -Identity _Automite_Grp_N3 | Remove-ADGroupMember -Members automiteusr0390,automiteusr0489,automiteusr0504


#ORDERED HASH TABLE
#https://devblogs.microsoft.com/scripting/use-powershell-to-create-ordered-dictionary/
New-Object PsObject -Property ([ordered]@{
    'Server Name'   = $CompName
    'Service_Name'  = $Services.Name
    'Status'        = $Services.Status
    'Started'       = $Services.STarted
    'Start Name'    = $Services.StartName
    'State'         = $Services.State
    'Path Name'     = $Services.PathName
    'File Size'     = $FileInfo.length
    'File Version'  = $FileInfo.VersionInfo.FileVersion
    'File Creation' = $FileINfo.CreationTime
    'Last Access'   = $FileINfo.LastAccessTime
    'Required Srvc' = $Required.RequiredServices.Name
}) 

$o = [ordered]@{a=1;b=2;c=3;d=4}

#https://social.technet.microsoft.com/Forums/en-US/be9fdff1-4d00-4e1e-b23b-224af3c74c12/newobject-order?forum=ITCG
#https://powershellexplained.com/2016-10-28-powershell-everything-you-wanted-to-know-about-pscustomobject/#creating-a-pscustomobject
$myHashtable = @{
    Name     = 'Kevin'
    Language = 'Powershell'
    State    = 'Texas'
    Age = '43'
    Surname = 'Billy'
}

$myObject = [pscustomobject]$myHashtable

$myHashtable

$myObject


#Create Hash Table inside foreach 
$Object = New-Object PSObject -Property @{
    AppName = $XAApp
    SessionCount  = $NrOfSessionApp
}

$reportArray += $Object
          
   
$reportArray | Select-Object -Property AppName,SessionCount 



#FIND GUID DA VM HYPER-V
Get-WmiObject Win32_Process -Filter "Name like '%vmwp%'" | Select-Object ProcessId, @{Label="VMName";Expression = {(Get-VM -Id $_.Commandline.split(" ")[1] | Select-Object VMName).VMName}} | ft -AutoSize 



#VIEW INSTALLED APPLICATIONS VER APLICAÇÕES INSTALADAS APLICATIVOS INSTALADOS
Get-WmiObject -Class Win32_SoftwareFeature | Select-Object -Property ProductName,Caption,Version | Format-Table

WMIC SOFTWAREFEATURE LIST BRIEF

Get-CimInstance -Class Win32_Product | Select-Object Name, PackageName, InstallDate, InstallLocation, InstallSource,Version | Out-GridView


#Create Array
#https://stackoverflow.com/questions/43083051/creating-an-array-with-large-initial-size-in-powershell/43083117
#https://powershellexplained.com/2018-10-15-Powershell-arrays-Everything-you-wanted-to-know/
$arr = [int[]]::new(10000); $arr.length
$arr = New-Object 'int[]' 10000; $arr.length


#Windows UUID GUID
#https://docs.microsoft.com/en-us/windows/desktop/cimwin32prov/win32-computersystemproduct##
get-wmiobject Win32_ComputerSystemProduct -computername "ServerName" | Select-Object -ExpandProperty UUID
(get-wmiobject Win32_ComputerSystemProduct -computername "ServerName").uuid


#https://technet.microsoft.com/en-us/windows/dn938435%28v=office.14%29?f=255&MSPPError=-2147217396
(Get-ADComputer -Identity "ServerName").SID | Format-List


#WIN32 CLASSESS WIN32_CLASS
Get-CimClass -ClassName win32* | where {$_.CimClassMethods} | select CimClassName,CimClassMethods


Get-WmiObject -Query 'Select * From Meta_Class WHERE __Class LIKE "win32%"' |
Where-Object { $_.PSBase.Methods } |
Select-Object Name, Methods

Get-CimClass -ClassName win32* | where CimClassMethods -ne $null  | select CimClassName,CimClassMethods

#VIEW BLOCK SIZE NTFS ALLOCATION UNIT
Get-WmiObject -Class Win32_Volume | Select-Object Label, BlockSize | Format-Table -AutoSize

Get-CimInstance -ClassName Win32_Volume | Select-Object Label, BlockSize | Format-Table -AutoSize


#EXPORT CSV PROBLEM "System.String[]" "System.Collections.Hashtable"
https://social.technet.microsoft.com/Forums/Azure/en-US/44b4e8aa-f82f-4315-8b07-b9ae2bf45121/exportcsv-mostly-working-but-one-column-displays-systemstring-exchange-tracking-logs?forum=winserverpowershell
https://powershell.org/forums/topic/system-string-export-to-csv/
http://blog.millersystems.com/powershell-exporting-multi-valued-attributes-via-export-csv-cmdlet/
http://techtalklive.org/ttlblog/powershell-exporting-hash-value-to-csv-file/
https://learn-powershell.net/2014/01/24/avoiding-system-object-or-similar-output-when-using-export-csv/


#mpio configuration multipath config
https://docs.netapp.com/ontap-9/index.jsp?topic=%2Fcom.netapp.doc.dot-cm-sanmig-fli%2FGUID-1120E516-ED3F-4C00-A43A-C301E45A3A52.html
https://support.microsoft.com/pt-br/help/3161579


#ACTIVE DIRECTORY WEB SERVICES ADWS
#https://blogs.msdn.microsoft.com/adpowershell/2009/04/06/active-directory-web-services-overview/
#escuta na porta 9389

#naa disks SCVMM NAA PWWN SWWN 
Get-SCVirtualFibreChannelAdapter | ft Name,PrimaryWorldWideNodeName,PrimaryWorldWidePortName,SecondaryWorldWideNodeName,SecondaryWorldWidePortName

#WINDOWS 2012 R2 NAA
Get-Disk | Select-Object -Property Number,Signature,UniqueID,SerialNumber,FriendlyName,@{label='AllocSize(GB)';expression={'{0:N2}' -f ($PSItem.AllocatedSize / 1GB)}},@{label='Size(GB)';expression={'{0:N2}' -f ($PSItem.Size / 1GB)}} | Format-Table -AutoSize -Wrap

#POWERCLI ERROR
#Error in deserializing body of reply message for operation


#PRODUCT KEY WINDOWS
(Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey
#wmic path softwarelicensingservice get OA3xOriginalProductKey

#CRIAR VHDX OU VHD PARA WINDOWS 2003 
#https://www.veritas.com/support/en_US/article.100012416
New-VHD "C:\ClusterStorage\VMDATA_PURESTORAGE_GOLD_01\DCServer01\DCServer01_DISK_2.vhdx" -SizeBytes 50GB -Fixed -PhysicalSectorSizeBytes 512

#SCVMM - TEMPLATES VIEW TEMPLATES
Get-Template | Select-Object -Property ID, OperatingSystem, CPUCount, Owner, ObjectType, AddedTime, ModifiedTime,Enabled, @{label='TotalVHDCapacity(MB)';expression={'{0:N2}' -f ($PSItem.TotalVHDCapacity / 1MB)}} | Out-File -FilePath .\AllTemplates_SCVMM_LAN.txt



Get-Process | Export-Clixml C:\ref.xml

Compare-Object -ReferenceObject (Import-Clixml C:\ref.xml) -DifferenceObject (Get-Process) -Property Name

Get-EventLog -Logname System -Newest 5 | Select -Property EventID, TimeGenerated, TimeWritten, Message | sort -Property TimeWritten | ConvertTo-Html | Out-File C:\Error.html

get-service | where {$_.status -eq "Running"}

get-service | where {$PSItem.status -eq "Running"}


get-service | where {$PSItem.status -eq "Running" -and $PSItem.name -like "b*"}


gps | where {$_.handles -ge 1000}

gps | where handles -ge 1000


#EXPORT DATA FROM DC ACTIVE DIRECTORY EXPORT DADOS ACTIVE DIRECTORY 
Get-ADComputer -Filter * -Properties * | Select-Object -Property Name,DnsHostName,whenCreated,Description,OperatingSystem,OperatingSystemVersion,Enabled,lastLogonTimestamp,LastLogonDate | Export-CSV AutomiteComputers.csv -NoTypeInformation -Encoding UTF8


[System.String]$todayDate = (Get-Date -format "ddMMyyyy-HHmm").ToString()

Get-ADComputer -Filter 'Name -notlike "AUT*" -and Name -notlike "Server*"' -Properties * | 
Select-Object -Property Name,DnsHostName,DistinguishedName,whenCreated,Description,OperatingSystem,OperatingSystemVersion,Enabled,@{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},LastLogonDate | 
Export-CSV .\ComputersPNA-$todayDate.csv -NoTypeInformation -Encoding UTF8 -Verbose


Get-ADComputer -Filter 'Name -notlike "AUT*" -and Name -notlike "Server*"' -Properties * | Select-Object -Property Name

Get-ADUser -Server "ServerName" -Filter * -Properties * | Select-Object -Property GivenName,Surname,CN,CreateTimeStamp,Enabled,LastLogonTimeStamp,LastLogonDate,mail | Export-CSV ps-UsersBrahma.csv -NoTypeInformation -Encoding UTF8


Get-ADUser -Filter "Enabled -eq 'True'" -Properties * | Select-Object -Property SamAccountName,
                                                                   GivenName,
                                                                   Surname,
                                                                   DisplayName,
                                                                   UserPrincipalName,
                                                                   CN,
                                                                   CreateTimeStamp,
                                                                   Enabled,
                                                                   ScriptPath,
                                                                   @{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},
                                                                   @{Name="pwdLastSet";Expression={([datetime]::FromFileTime($_.pwdLastSet))}},
                                                                   LastLogonDate,
                                                                   mail | Export-Csv .\EnabledUsersBrahma.csv -NoTypeInformation -Encoding UTF8


Get-ADUser -Server "ServerName" -Properties * | Select-Object -Property SamAccountName,
                                                   GivenName,
                                                   Surname,
                                                   DisplayName,
                                                   SID,
                                                   UserPrincipalName,
                                                   CN,
                                                   CreateTimeStamp,
                                                   Enabled,
                                                   ScriptPath,
                                                   @{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},
                                                   @{Name="pwdLastSet";Expression={([datetime]::FromFileTime($_.pwdLastSet))}},
                                                   LastLogonDate,
                                                   Lockedout, 
                                                   mail | Export-Csv .\AllUsersBrahma.csv -NoTypeInformation -Encoding UTF8 -OutBuffer 1000



#LASTLOGONTIMESTAMP
get-aduser chad -properties lastlogontimestamp,pwdLastSet | select samaccountname, `
     @{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}},`
     @{Name="pwdLastSet";Expression={([datetime]::FromFileTime($_.pwdLastSet))}}

$hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}}
 $hash_pwdLastSet = @{Name="pwdLastSet";Expression={([datetime]::FromFileTime($_.pwdLastSet))}}
  
 get-aduser chad -properties lastlogontimestamp,pwdLastSet | `
     select samaccountname, $hash_lastLogonTimestamp,$hash_pwdLastSet

#WinRM client received an HTTP status code 502 or 403 from the remote WS-Management service.
# ERROR 403 WINRM VERIFIQUE SE O PROXY NÃO ESTÁ ATIVADO. 
#https://blogs.msdn.microsoft.com/aseemb/2015/06/17/winrm-client-received-an-http-status-code-502-or-403-from-the-remote-ws-management-service/


#WINRM LISTENING ON NULL
#https://stackoverflow.com/questions/17281224/configure-and-listen-successfully-using-winrm-in-powershell
Remove-WSManInstance winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}

New-WSManInstance winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}

New-WSManInstance winrm/config/Listener -SelectorSet @{Address="IP:192.168.100.2";Transport="http"}

#https://social.technet.microsoft.com/Forums/azure/en-US/504b9e2c-5619-4777-8acf-45f4679d7827/geteventlog-and-remote-computers?forum=winserverpowershell
#PARA TRABALHAR COM REMOTE EVENT LOG O SERVIÇO REMOTE REGISTRY DEVE ESTAR HABILITADO
#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/limit-eventlog?view=powershell-5.1
$Logs = Get-EventLog -List | ForEach {$_.log}
Limit-EventLog -OverflowAction OverwriteAsNeeded -LogName $Logs
Get-EventLog -List


#CONVERT DISK TO FIXED SCVMM
$VirtualDiskDrive = Get-SCVirtualDiskDrive -VMMServer onetamvm002-vmm -All | where {$_.ID -eq "17e36c07-8d81-4390-9e73-042096658e6d"}

Convert-SCVirtualDiskDrive -VirtualDiskDrive $VirtualDiskDrive -Fixed -JobGroup c3577622-9b28-42c6-8641-56c21663b7ea 

$VirtualDiskDrive = Get-SCVirtualDiskDrive -VMMServer onetamvm002-vmm -All | where {$_.ID -eq "17e36c07-8d81-4390-9e73-042096658e6d"}

Set-SCVirtualDiskDrive -VirtualDiskDrive $VirtualDiskDrive -Bus 0 -LUN 0 -VolumeType None -IDE -JobGroup c3577622-9b28-42c6-8641-56c21663b7ea 

$VM = Get-SCVirtualMachine -VMMServer "SERVER01-VMM" -Name "AUTOMITE0112" -ID "3129e771-bd34-483c-bd20-3d7798d48da0" | where {$_.VMHost.Name -eq "AUTOMITESRV01.sth.local"}
$OperatingSystem = Get-SCOperatingSystem -VMMServer "SERVER01-VMM" -ID "00000000-0000-0000-0000-000000000000" | where {$_.Name -eq "Unknown"}

$CPUType = Get-SCCPUType -VMMServer "SERVER01-VMM" | where {$_.Name -eq "3.60 GHz Xeon (2 MB L2 cache)"}

Set-SCVirtualMachine -VM $VM -Name "AUTOMITESRV0112" -Description "" -OperatingSystem $OperatingSystem -CPUCount 8 -MemoryMB 49152 -DynamicMemoryEnabled $false -MemoryWeight 5000 -VirtualVideoAdapterEnabled $false -CPUExpectedUtilizationPercent 20 -DiskIops 0 -CPUMaximumPercent 100 -CPUReserve 0 -NumaIsolationRequired $false -NetworkUtilizationMbps 0 -CPURelativeWeight 100 -HighlyAvailable $true -HAVMPriority 2000 -DRProtectionRequired $false -NumLock $false -BootOrder "CD", "PxeBoot", "IdeHardDrive", "Floppy" -CPULimitFunctionality $false -CPULimitForMigration $false -CPUType $CPUType -Tag "(none)" -QuotaPoint 1 -JobGroup c3577622-9b28-42c6-8641-56c21663b7ea -RunAsynchronously -DelayStartSeconds 0 -BlockDynamicOptimization $false -EnableOperatingSystemShutdown $true -EnableTimeSynchronization $true -EnableDataExchange $true -EnableHeartbeat $true -EnableBackup $true -RunAsSystem -UseHardwareAssistedVirtualization $true 


#DISABLE DYNAMIC OPTIMIZATION SCVMM
$hostGroup = Get-SCVMHostGroup -ID "7bd2fe08-e2be-492e-b35d-90955febad61" -Name "CLUSTER PROVISIONING"
Set-SCVMHostGroup -EnableUnencryptedFileTransfer $true -RunAsynchronously -VMHostGroup $hostGroup -Name "CLUSTER PROVISIONING" -Description ""

$placementWeights = Get-SCPlacementConfiguration -VMHostGroup $hostGroup
Set-SCPlacementConfiguration -Inherit $true -PlacementConfiguration $placementWeights

$hostReserves = Get-SCHostReserve -VMHostGroup $hostGroup

$dynamicOptimizationSettings = Get-SCDynamicOptimizationConfiguration -VMHostGroup $hostGroup
Set-SCDynamicOptimizationConfiguration -DynamicOptimizationConfiguration $dynamicOptimizationSettings -ManualMode
Set-SCDynamicOptimizationConfiguration -DynamicOptimizationConfiguration $dynamicOptimizationSettings -Aggressiveness "3" -EnablePowerOptimization $false

Set-SCVMHostGroup -VMHostGroup $hostGroup -InheritNetworkSettings $false -RunAsynchronously


#START DO SCVMM
$hostCluster = Get-SCVMHostCluster -Name "AUTOMITESRV003CLU.sth.local"
Start-SCDynamicOptimization -VMHostCluster $hostCluster


#GET EVENTS MOVING SPECIFIC VM
Get-WinEvent -LogName Microsoft-Windows-FailoverClustering/Operational | Where-Object -FilterScript {$_.Message -like "*SERVERNAME-VMS05*"}


#FIND JOB OF SPECIFIC VM SCVMM
$VM = Get-SCVirtualMachine -Name "VM01"
Find-SCJob -MaxCount 10 -ObjectID $VM.Id

#UPDATE SCVMM AGENT
$credential = Get-SCRunAsAccount -Name "SRV_SCVMM" -ID "d9e99b21-6ee8-4e3d-a8d8-722ca7b9bdc2"
$managedComputer = Get-SCVMMManagedComputer -ComputerName "SERVER-HYP001.br.automite.net"
Update-SCVMMManagedComputer -Credential $credential -RunAsynchronously -VMMManagedComputer $managedComputer

#https://bobcares.com/blog/powershell-list-installed-software/
#List installed software:
Get-WmiObject -Class Win32_Product

Get-WmiObject -Class Win32_Product | where vendor -eq CodeTwo | select Name, Version

$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

$InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}

Get-WinEvent -ProviderName msiinstaller | where id -eq 1033 | select timecreated,message | FL *

Get-WmiObject Win32_Product -ComputerName $pcname | select Name,Version


$list=@()
$InstalledSoftwareKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
$InstalledSoftware=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$pcname)
$RegistryKey=$InstalledSoftware.OpenSubKey($InstalledSoftwareKey)
$SubKeys=$RegistryKey.GetSubKeyNames()
Foreach ($key in $SubKeys){
$thisKey=$InstalledSoftwareKey+"\\"+$key
$thisSubKey=$InstalledSoftware.OpenSubKey($thisKey)
$obj = New-Object PSObject
$obj | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $pcname
$obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
$obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
$list += $obj
}
$list | where { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion | FT


#Uninstall VMM DHCP Extension
(Get-WmiObject -Class Win32_Product -Filter “Name=’Microsoft System Center Virtual Machine Manager DHCP Server (x64)'” -ComputerName . ).Uninstall()

#Uninstall VMM Agent
(Get-WmiObject -Class Win32_Product -Filter “Name=’Microsoft System Center Virtual Machine Manager Agent (x64)'” -ComputerName . ).Uninstall()

Technet reference: http://technet.microsoft.com/en-us/library/dd347651.aspx

#SCVMM AGENT VERSION VMM AGENT
Get-VMMManagedComputer | Select-Object -Property Name,AgentVersion | Sort-Object -Property AgentVersion


#PERFMON SAMPLE
#https://blogs.technet.microsoft.com/yongrhee/2011/11/13/how-often-should-perfmon-sample/


###Turn ON/OFF Time Synchronization em uma VM:
Get-SCVirtualMachine -Name SERVER-VMS0249 | Set-SCVirtualMachine -EnableTimeSync $False
Get-SCVirtualMachine -Name SERVER-VMS0025 | Set-SCVirtualMachine -EnableTimeSync $False | FT VMHost,Name,TimeSynchronizationEnabled,MostRecentTaskIfLocal -AutoSize 


#VALIDATE SERVICE ZABBIX
Get-Service -ComputerName $serverList -Name 'Zabbix Agent' | Select-Object -Property MachineName,DisplayName,Status,StartType


#VIEW ENVIRONMENT VARIABLES
 Get-ChildItem env:

#CONVERT DECIMAL TO HEX
#https://community.idera.com/database-tools/powershell/ask_the_experts/f/learn_powershell-12/10514/simple-converting-from-decimal-to-hex
$b = 10 #any value can be inserted here
$c = [int] $b
$c = "{0:X}" -f $c
$c


#MOVER VM DE CLUSTER
Get-ClusterGroup “VM01” | Get-ClusterResource | Set-ClusterParameter OfflineAction 1 #Ativa Quick Migration que por default é desabilitado via Powershell
Get-Cluster -Name AUTOMITESRV002CLU | Get-ClusterGroup -Name "ServerName" | Move-ClusterGroup  #Quick Migration da VM - Cuidado!
Move-ClusterGroup -Name "VM01" -Node "HV2" #Quick Migration da VM - Cuidado! 
#Você só usa Quick em UMA SITUAÇÃO
#Divergência de processador entre host de origem e de destino



#EXECUÇÃO PARALELA - SIMULTANEA - PARALLEL
# list of computers to connect to
$listOfComputers = 'PC10','TRAIN1','TRAIN2','AD001'
# exclude your own computer
$listOfComputers = $listOfComputers -ne $env:COMPUTERNAME
# code to execute remotely
$code = {
"Hello" | Out-File -FilePath "c:\users\Public\Desktop\result.txt"
}
# invoke code on all machines
Invoke-Command -ScriptBlock $code -ComputerName $listOfComputers -Throttle 1000


#WINRAR POWERSHELL
Invoke-Command -ComputerName SERVER-VMM0123 -ScriptBlock {& "C:\Program Files (x86)\winrar\Rar.exe" a -ep -ep1 "C:\temp\gateway\nlog-own-2019-09-07.rar" "C:\temp\gateway\nlog-own-2019-09-07.log"}


#RESET COMPUTER ACCOUNT ACTIVE DIRECTORY
Get-ADComputer -Identity "ServerName" -Properties passwordlastset

Invoke-Command -ComputerName "ServerName" -ScriptBlock {Test-ComputerSecureChannel -Verbose}

#Fixing Trust Relationship by Domain Rejoin
#https://theitbros.com/fix-trust-relationship-failed-without-domain-rejoining/
Reset-ComputerMachinePassword -Server lon-dc01 -Credential corpdsmith

Test-ComputerSecureChannel -Repair -Credential corpdsmith



#CREATE USER AND ADD TO DOMAIN GROUP"
Import-Module ServerManager

Add-WindowsFeature -Name "RSAT-AD-PowerShell"

New-ADUser -Name "SCVMM Service" -SamAccountName "vmm-svc" -DisplayName "SCVMM Service Acct" -Enabled $true -ChangePasswordAtLogon $false -AccountPassword (ConvertTo-SecureString "type here the password" -AsPlainText -force) -PasswordNeverExpires $true

$admgroup = [ADSI]"WinNT://./Administrators,group"

$admgroup.Psbase.Invoke("Add",([ADSI]"WinNT://sth.local/vmm-svc").Path)


$admGroup = [ADSI]"WinNT://./Domain Admins,group"



$strDate = "Oct 12 23:59:59 2018"
[datetime]::ParseExact($strDate,'MMM dd HH:mm:ss yyyy', [cultureinfo]::InvariantCulture)


#CONVERTER HORA DA CLASSE Win32_NetworkLoginProfile
#https://social.technet.microsoft.com/Forums/en-US/2c68ba5a-df2f-4064-90a5-fecdc6591878/win32networkloginprofile-lastlogon-the-results-are-incorrect-in-domain-joined-machines?forum=ITCG
#https://blogs.technet.microsoft.com/dsheehan/2017/09/24/powershell-datetime-throws-the-error-string-was-not-recognized-as-a-valid-datetime/
#https://community.idera.com/database-tools/powershell/ask_the_experts/f/learn_powershell_from_don_jones-24/21672/change-date-format
#https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-networkloginprofile
#https://blogs.technet.microsoft.com/dsheehan/2017/09/24/powershell-datetime-throws-the-error-string-was-not-recognized-as-a-valid-datetime/
#https://stackoverflow.com/questions/38717490/convert-a-string-to-datetime-in-powershell
#https://powershell.org/forums/topic/not-able-to-insert-datetime-values-in-datetime-declared-empty-array/
#http://powershell-guru.com/powershell-tip-7-convert-wmi-date-to-datetime/

$LogonList = Get-WmiObject -Class Win32_NetworkLoginProfile

foreach ($logon in $logonList){

    $LastLogonH = $logon.ConvertToDateTime($logon.LastLogon)
    $newHora = $LastLogonH | Get-Date -Format 'dd/MM/yyyy HH:mm'
    $stringHora = $newHora.ToString()

}

$driverDate = $netinfo[0].DriverDate
[Management.ManagementDateTimeConverter]::ToDateTime($driverDate)


$installDate = (Get-WmiObject -Class Win32_OperatingSystem).InstallDate
# Solution 1
[Management.ManagementDateTimeConverter]::ToDateTime($installDate)
# Solution 2
([WMI] '').ConvertToDateTime($installDate)


Get-WmiObject -ComputerName $HostHYP -Class win32_PnPSignedDriver | 
Where-Object -FilterScript {$PSItem.devicename -like "Qlogic*"} | 
Select-Object -Property PSComputerName,DeviceName,DriverVersion,@{label='DriverDate';expression={[Management.ManagementDateTimeConverter]::ToDateTime($Psitem.DriverDate)}},IsSigned,InfName | 
Format-Table -AutoSize | Out-File -Width 4096 -FilePath $outputFile -Append


Get-CimInstance -ClassName CIM_Service -Filter "Name='srv'" |Invoke-CimMethod -MethodName ChangeStartMode -Arguments @{StartMode='Manual'}


#CORRIGIR  NET ADAPTER

Get-NetAdapterVmq | FT Name,InterfaceDescription,Enabled,BaseProcessorNumber,MaxProcessors,NumberOfReceiveQueues -autosize
#Abaixo procedimento de correção VMQ para MaxProcessors nos Hosts DELL POWER EDGE M630:

Set-NetAdapterVMQ -Name 10G-PORT-01 -BaseProcessorNumber 2 -MaxProcessors 5
Set-NetAdapterVMQ -Name 10G-PORT-02 -BaseProcessorNumber 26 -MaxProcessors 5
Set-NetAdapterVMQ -Name 10G-PORT-03 -BaseProcessorNumber 12 -MaxProcessors 5
Set-NetAdapterVMQ -Name 10G-PORT-04 -BaseProcessorNumber 36 -MaxProcessors 5

#Abaixo procedimento de correção VMQ para MaxProcessors nos Hosts M620:

Set-NetAdapterVMQ -Name 10G-PORT-01 -BaseProcessorNumber 2 -MaxProcessors 5
Set-NetAdapterVMQ -Name 10G-PORT-02 -BaseProcessorNumber 22 -MaxProcessors 5
Set-NetAdapterVMQ -Name 10G-PORT-03 -BaseProcessorNumber 12 -MaxProcessors 4
Set-NetAdapterVMQ -Name 10G-PORT-04 -BaseProcessorNumber 32 -MaxProcessors 4


#GET FAILED WINDOWS UPDATE
gwmi -cl win32_reliabilityRecords -filter "sourcename = 'Microsoft-Windows-WindowsUpdateClient'" |where { $_.message -match 'failure' } |select @{LABEL = "date";EXPRESSION = {$_.ConvertToDateTime($_.timegenerated)}},
@{LABEL = "failed update"; EXPRESSION = { $_.productname }}| FT -AutoSize –Wrap



#ALTERAR PERMISSÃO, FORÇAR FULL CONTROLL
$Acl = Get-Acl '.\Windows Defender\'
$Ar = New-Object System.Security.AccessControl.FilesystemAccessRule("automite\julianoabr","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.SetAccessRule($Ar)
Get-ChildItem -Path 'C:\Program Files\Windows Defender\' -Recurse -Force | Set-Acl -AclObject $Acl


$acl = Get-Acl 'C:\Program Files\Windows Defender Advanced Threat Protection'
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.SetAccessRule($accessRule)
Set-Acl "C:\Program Files\Windows Defender Advanced Threat Protection" $Acl


#REMOVE HOTFIX
(get-hotfix).hotfixid.replace("KB","") | % {& wusa.exe /uninstall /KB:$_ /quiet /norestart}

Wusa.exe /uninstall /KB:4054517 /norestart


#DISABLE AND ENABLE IPV6 INTERFACE
Get-NetAdapter
Get-NetAdapterBinding -Name LocalNetwork
Disable-NetAdapterBinding -Name LocalNetwork -ComponentID ms_tcpip6 -PassThru


#ENCONDING UTF8
Send-MailMessage -SmtpServer $smtpserver -From $fromaddress -To $toaddress -Cc $CCaddress -Subject $XenApp65Subject -Attachments $XenApp65Attachment -Body $XenAppBody -BodyAsHtml -Priority Normal -Encoding ([System.Text.Encoding]::UTF8)


#CONVERT TO BOOLEAN - CONVERTER BOOLEANO
$persistent = “False”
$variable = [System.Convert]::ToBoolean($persistent)



#CONFLITO DE COMANDOS - SAME COMMAND ON TWO DIFFERENT MODULES 
#Você deve colocar [module]\command]
https://mcpmag.com/articles/2013/08/20/powershell-name-duplicates.aspx

Import-Module -Name Vmware.VimAutomation.Core -Force

Vmware.VimAutomation.Core\Start-VM -VM $tmpVM -Confirm:$false -RunAsync -Verbose


#https://learn-powershell.net/2015/04/09/quick-hits-finding-exception-types-with-powershell/
#TRY CATCH FIND EXCEPTION
Try {
# Do something
}
Catch [SpecificExceptionGoesHere]
{ # Do something else if the above fails }

$Error[0].Exception.GetType().FullName

}

$Error[0].Exception.GetType().fullname

#EXCEL MODULE
#https://www.powershellgallery.com/packages/ImportExcel/7.1.0


#https://petri.com/search-active-directory-locked-out-user-accounts-powershell
#Locked Users AD
$lockedUsers = Search-ADAccount –LockedOut

$totalUsers = $lockedUsers.Count

$totalUsers


#https://www.experts-exchange.com/questions/28995486/Need-to-remove-Remote-Desktop-services-Profile-for-Bulk-users.html
#https://devblogs.microsoft.com/scripting/hey-scripting-guy-how-can-i-edit-terminal-server-profiles-for-users-in-active-directory/
#https://social.technet.microsoft.com/Forums/ie/en-US/0edebfdf-74c1-4482-b339-fa69a37536a9/set-terminal-services-attributes-to-null?forum=ITCG
#Remove Desktop Services Profiles and Home Directory


#GET ALL DNS SERVERS IN A DOMAIN
Get-DnsServerResourceRecord -ComputerName automitesrv01 -ZoneName 'br.automite.net' -RRType 'NS' -Node


#ver seu próprio IP
Invoke-RestMethod http://ipinfo.io/json | Select-Object -ExpandProperty IP


#search object by guid, sid
get-adobject -id {guid} | fl



#https://techcommunity.microsoft.com/t5/failover-clustering/configuring-ip-addresses-and-dependencies-for-multi-subnet/ba-p/371698
#Add Second IP to Cluster Core Resource
$Vlan500Ntw = Get-ClusterNetwork | Where-Object -FilterScript {$PSItem.Address -like "10.154*"}

#role 1 = Allow cluster network communication on this network
#role 3 = Allow clients to connect through this network
#role 0 = Do not allow cluster network communication on this network

if ($vlan500Ntw.Role -ne 1){

    Write-Output "I will change to permit cluster and client communication"

}

FailoverClusters\Get-Cluster -Name "AutomiteSRV01" | Add-ClusterResource -Name "Backup IP Address" -ResourceType "Ip Address" -Group "Cluster Group"


#get service using hashtable 
$h=@{Class="win32_service";Property="Name","Displayname","StartMode","StartName","State","PathName"}
Get-WmiObject @h -ComputerName (Get-content "$env:SystemDrive\Scripts\Box\Input\Windows\PendingReboot\HostsAutomite.txt")


#Change Process Priority
#Idle
#BelowNormal
#Normal
#AboveNormal
#High
#RealTime

$process = Get-Process -Id $pid
$process.PriorityClass = 'PRIORITYLEVEL'

#CONVERT DATE TIME
# Solution 1
$datetimeToString = '{0:MM/dd/yy}' -f (Get-Date '07/15/2015')

# Solution 2
$datetimeToString = (Get-Date '07/15/2015').ToShortDateString()


# Solution 1
$stringToDatetime1 = '07/15/2015' | Get-Date
$stringToDatetime = '07-15-2015' | Get-Date

# Solution 2
$stringToDatetime2 = [Datetime]::ParseExact('07/15/2015', 'MM/dd/yyyy', $null)

# Solution 3
$stringToDatetime3 = [Datetime]'7/15/2015'


#RESULTADO EM PORCENTAGEM
(5/21).tostring("P")


#CREATE CONSTANT VARIABLE
#https://codesteps.com/2019/02/06/powershell-how-to-create-read-only-and-constant-variables/#:~:text=Create%20constant%20variables%20in%20PowerShell&text=Constants%20CAN'T%20be%20altered,values%20of%20the%20constant%20variables.
New-Variable -Name pi -Value 3.14159265359 -Option Constant

New-Variable -Name read_only_var -Value "A NEW value to me!" -Option ReadOnly -Force


#https://docs.microsoft.com/en-us/windows/client-management/troubleshoot-tcpip-port-exhaust
#Port tcpip-port-exhaust
Get-NetTCPConnection | Group-Object -Property State, OwningProcess | Select -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort Count -Descending


netsh int ipv4 show dynamicport tcp
netsh int ipv4 show dynamicport udp
netsh int ipv6 show dynamicport tcp
netsh int ipv6 show dynamicport udp

netsh int ipv4 set dynamicport udp start=49152 num=1024
netsh int ipv4 set dynamicport tcp start=49152 num=1024



#COPY FILES RECURSIVELY TO A DIRECTORY
$location = (Get-Location).Path

$collection = @()

#$collection = ('SERVER','group')

$collection = (Get-content "$location\file.txt")

foreach ($item in $collection)
{
   
   get-childitem -file -Depth 2 -Path "$env:SystemDrive\" | Where-Object -FilterScript {$PSItem.name -like "*$item*"} -OutBuffer 100 | ForEach-Object {Copy-Item $_.FullName -Destination (("$location\Output\") + $_.Name) -Force -Verbose} 

}


#https://adamtheautomator.com/powershell-try-catch/
#https://stackoverflow.com/questions/35610660/unable-to-catch-drivenotfoundexception-from-get-psdrive
#https://docs.microsoft.com/pt-br/powershell/scripting/learn/deep-dives/everything-about-exceptions?view=powershell-7.1

$file_list = Get-Content .\filelist.txt
try {
    foreach ($file in $file_list) {
        Write-Output "Reading file $file"
        Get-Content $file -ErrorAction STOP
    }
}
catch [System.Management.Automation.ItemNotFoundException]{
    Write-Host "The file $file is not found." -ForegroundColor RED
}
catch {
    Write-Host $PSItem.Exception.Message -ForegroundColor RED
}
finally {
    $Error.Clear()
}

#https://www.millersystems.com/powershell-exporting-multi-valued-attributes-via-export-csv-cmdlet/ 
#WHEN EXPORT CSV THE RESULT APPEARS SYSTEM.STRING[] 
Get-QADUser seth -IncludeAllProperties | select name, @{Name=’proxyAddresses’;Expression={[string]::join(“;”, ($_.proxyAddresses))}} | Export-Csv .seth-all_proxyaddresses.csv


#RENAME COMPUTER
Rename-Computer -ComputerName "AutomiteSRV01" -NewName "AutomiteSRV02" -DomainCredential (Get-Credential) -Force -Restart -Verbose

#TRANSCRIPT GRAVAR SESSAO POWERSHELL, GRAVAR HISTORICO DE COMANDOS
#https://sid-500.com/2017/07/15/powershell-documenting-your-work-with-start-transcript/
Start-Transcript -Path "$env:SystemDrive\Temp\Log1.txt"
Start-Transcript -NoClobber -Path "$env:SystemDrive\Temp\Log1.txt" #No overwrite files
Start-Transcript -Append "$env:SystemDrive\Temp\Log1.txt" #append
Stop-Transcript

#Transcript on remote servers
Enter-PSSession -ComputerName dc01
Start-Transcript

#automatic transcript
New-Item -Path $Profile -Force
Add-Content -Path $Profile -Value "Start-Transcript"

#create powershell profile
#https://sid-500.com/2017/08/15/how-to-create-powershell-profiles/

Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned
New-Item -ItemType File -Path $Profile -Force
New-Item -ItemType File -Path $PROFILE.AllUsersAllHosts -Force
ise $profile.AllUsersAllHosts
ise $profile

Write-Host "Welcome to" (Invoke-Expression hostname) -ForegroundColor Green
Write-Host "You are logged in as" (Invoke-Expression whoami)
Write-Host "Today:" (Get-Date)
Set-Location c:\
New-Alias Time Get-Date -Force
Write-Host "PowerShell"($PSVersionTable.PSVersion.Major)"awaiting your commands."


set-location c:\
cls
$Shell = $Host.UI.RawUI
$size = $Shell.WindowSize
$size.width=80
$size.height=34
$Shell.WindowSize = $size
$size = $Shell.BufferSize
$size.width=80
$size.height=3000
$Shell.BufferSize = $size
Start-Transcript

#USE HASH TABLE PARA INVOCAR UM COMANDO
$params = @{
    AsJob = $true
    ComputerName = (Get-Content "$env:SystemDrive\tmp\computers.txt")
    FilePath = 'C:\tmp\Get-LocalGroupMember-Csv.ps1'
    JobName = 'ColetaRemoteUsers'
  }


Invoke-Command @params


#CLUSTER AWARE UPDATE - MUST HAVE MODULE ClusterAwareUpdating Installed
Set-CauClusterRole -ClusterName SERVER-VMM0263 -Force -CauPluginName Microsoft.WindowsUpdatePlugin -CauPluginArguments @{ 'IncludeRecommendedUpdates' = 'False' } -MaxRetriesPerNode 3 -RequireAllNodesOnline -RebootTimeoutMinutes 120 -StartDate "01/12/2020 20:00:00" -DaysOfWeek 16 -WeeksOfMonth @(1) -UseDefault -EnableFirewallRules;Enable-CauClusterRole -ClusterName SERVER-VMM0263 -Force;



#GET USERS OF A GROUP WITH MORE THAN 5000 USERS - GRUPOS COM MUITOS MEMBROS - GRUPO GIGANTE
#Get-ADGroupMember : The size limit for this request was exceeded ERROR ERRO
$group =[adsi]”LDAP://CN=_VDI_STD,OU=Groups,OU=VD,OU=Corporativo,DC=brz,DC=automyte,DC=net” 
$members = $group.psbase.invoke("Members") | foreach {$_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null)} 
$members.count

$group =[adsi]”LDAP://CN=_AUTOMITE_VCENTER_MSFT_N2,OU=Service_Groups,OU=ADM_CENTRAL_AC,OU=Corporativo,DC=brz,DC=automyte,DC=net”  
$members = $group.psbase.invoke("Members") | foreach {$_.GetType().InvokeMember("DistinguishedName",'GetProperty',$null,$_,$null)} 

$members.count

#USE ESTA LINHA APENAS PARA EXPORTAR OS USUÁRIOS
$members | Out-File -FilePath "$env:SystemDrive\temp\_VD_ST_Users.csv" -Verbose




#USE O FOREACH PARA EXPORTAR OS USUÁRIOS COM PROPRIEDADES
foreach ($member in $members){

    Get-ADUser -Identity $member | Select-Object -Property DistinguishedName,Enabled,Name,SamAccountName,SID,PrincipalName | Export-Csv -Path "$env:SystemDrive\temp\_VD_ST_Users.csv" -NoTypeInformation -Append


}


#MEASURE SCRIPT TIME
Measure-Command -Expression { .\do_something.ps1 }

Measure-Command -Expression { .\do_something.ps1 | Out-Default }


#GENERATE RANDOM NUMBERS AND SHOW FIRST 6
1..60 | Get-Random -Count 6

#https://serverfault.com/questions/359000/how-to-avoid-remove-item-powershell-errors-process-cannot-access-the-file
#ACCESS DENIED TO REMOVE ITEM
get-process | foreach{
          $pName = $_
          if ( $pName.Path -like ( $INSTALL_PATH + '*') ) {
            Stop-Process $pName.id -Force -ErrorAction SilentlyContinue
          }
        }
       Remove-Item  -Force -Recurse $INSTALL_PATH


Get-ChildItem * -Include *.csv -recurse | ForEach-Object {
    $removeErrors = @()
    $_ | Remove-Item -ErrorAction SilentlyContinue -ErrorVariable removeErrors
    $removeErrors | where-object { $_.Exception.Message -notlike '*it is being used by another process*' }
}


#MERGE CSV ONE LINER
Get-Content *.csv| Add-Content output.csv


#GET YOUR PUBLIC IP
Invoke-RestMethod http://ipinfo.io/json | Select-Object -ExpandProperty IP


#UNCHECK PROTECT AGAINST ACCIDENTAL DELETION
Get-ADOrganizationalUnit -SearchBase "OU=Groups,OU=CHILDOU,OU=BASEOU,DC=yourcompany,DC=com" -Filter * | Set-ADObject -ProtectedFromAccidentalDeletion $false -Confirm:$false -Verbose

Get-ADOrganizationalUnit -SearchBase "OU=Groups,OU=CHILDOU,OU=BASEOU,DC=yourcompany,DC=com" -Filter * | Set-ADObject -ProtectedFromAccidentalDeletion $true -Confirm:$false -Verbose


#VIEW IF A COMPUTER IS SERVER CORE, SE RETORNAR TRUE NÃO É, FALSE É
Test-Path -Path '\\AUTOMITESRV01\c$\Windows\explorer.exe'
Test-Path -Path '\\AUTOMITESRV02\c$\Windows\explorer.exe'



@('\\server\nova\folder', '\\server\nova\folder', '\\server\nova\folder2', '\\server\nova\folder3') | 
    Sort-Object -Property @{Expression={$_.Trim()}} -Unique


#https://www.markou.me/2018/03/force-disk-rescan-on-a-windows-failover-cluster-using-powershell/
#Force Disk Rescan on Failover Cluster
$Nodes = (Get-ClusterNode).Name -Join "," 
Invoke-Command -ComputerName $Nodes -ScriptBlock {Update-HostStorageCache}



#path long 248 260 caracteres
#The specified path, file name, or both are too long. The fully qualified file name must be less than 260 characters, and the directory name must be less than 248 characters.
#https://c-nergy.be/blog/?p=15339
#https://learn-powershell.net/2013/04/01/list-all-files-regardless-of-260-character-path-restriction-using-powershell-and-robocopy/
#If you are accessing files locally 
get-childItem -LiteralPath \\?\e:\TopFolders\ 

#If you are accessing files through network Share 
get-childItem -LiteralPath \\?\UNC\MyFileServerHostName\Share\



https://morgantechspace.com/2015/08/powershell-get-environment-variable-remote-machine.html
[Environment]::GetEnvironmentVariables()

[Environment]::GetEnvironmentVariables("Machine")

[Environment]::GetEnvironmentVariables("User")

[Environment]::GetEnvironmentVariable("ComputerName")


Invoke-Command -ComputerName "ESVR01" -ScriptBlock {[Environment]::GetEnvironmentVariable(“ComputerName”)}


Invoke-Command -ComputerName "ESVR01" -ScriptBlock {[Environment]::GetEnvironmentVariable(“Temp”,”Machine”)}

Invoke-Command -ComputerName "ESVR01" -ScriptBlock {[Environment]::GetEnvironmentVariable(“Temp”,”User”)} -Credential Kevin



#Fix 'The underlying connection was closed' error in Invoke-RestMethod from PowerShell
#http://blog.vaneykelen.com/2018/11/26/Fix-The-underlying-connection-was-closed-error-in-Invoke-RestMethod-from-PowerShell/
Invoke-RestMethod -Uri https://dashboarddelivery.nextens.nl/api/invalidate/

#Resolva rodando: 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


#Fix: 'The response content cannot be parsed because the internet explorer engine is not available, or internet's explorer first launch and try again
Invoke-RestMethod -Uri "https://dashboarddelivery.nextens.nl/api/invalidate/" -Method Get -UseBasicParsing



#PRODUCT VERSION
$Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

Get-ItemProperty -Path $Path |
Select-Object -Property ProductName, CurrentBuild, ReleaseId, UBR


#LAST LOGGED ON USER
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"

$key = Get-Item -Path $Path
$key.GetValue('LastLoggedOnUser')


#LAST LOGGED ON USER REMOTE

$rFileList = Get-ChildItem -File -Include *.tmp,*.crdownload,*.partial,*.cddownload -Recurse -Attributes "Normal,Hidden,Compressed,Temporary,ReadOnly,Encrypted" -OutBuffer 1000

$rFileList | Out-File -FilePath $env:systemdrive\Temp\FilesExclude.txt -Width 4096 -Append #exportar para arquivo

$rFileList | Remove-Item -WhatIf -Verbose #só mostrar 

$rFileList | Remove-Item -Force -Verbose -ErrorAction SilentlyContinue #assim pra excluir direto


#FIREWALL RULES FOR POWERSHELL REMOTING
#https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/what-port-does-powershell-remoting-use/ba-p/571480
#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.1
#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-7.1

Get-NetFirewallRule -Name 'WINRM*' | Select-Object Name
Get-NetFirewallRule -Name 'WMI*' | Select-Object Name

Set-Item WSMan:\localhost\Service\EnableCompatibilityHttpListener -Value true

Set-Item WSMan:\localhost\Service\EnableCompatibilityHttpsListener -Value true

Set-Item wsman:\localhost\listener\listener*\port –value 80

Set-Item wsman:\localhost\listener\listener*\port –value 443

#https://qastack.com.br/programming/13023920/how-to-export-import-putty-sessions-list
#Export Registry PUTTY SESSIONS
reg export HKCU\Software\SimonTatham\PuTTY\Sessions ([Environment]::GetFolderPath("Desktop") + "\putty-sessions.reg")
reg export HKCU\Software\SimonTatham ([Environment]::GetFolderPath("Desktop") + "\putty.reg")


#VIEW SMB SHARES ON LOCAL MACHINE
Get-SmbMapping

Remove-SmbMapping -RemotePath \\AUTOMITESRV01.automyte.local\c$

#Export Registry KEY
Start-Process -FilePath "$env:windir\regedit.exe" -ArgumentList "/e Myfile2.reg `"HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.`""

$regKey = "HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc."

Start-Process -FilePath "$env:windir\regedit.exe" -ArgumentList "/e Myfile2.reg `"$regKey`""


#UPDATE VMM MACHINE CONFIGURATION - MUST HAVE MODULE FAILOVER CLUSTER INSTALLED
#https://learn.microsoft.com/en-us/powershell/module/failoverclusters/?view=windowsserver2022-ps
Get-ClusterResource | where {$_.ownergroup -match "ONETAMMG011" -and $_.resourcetype.name -eq 'virtual machine configuration'} | Update-ClusterVirtualMachineConfiguration


#CONVERT TO UNIX TIME SECONDS
[DateTimeOffset]::Now.ToUnixTimeSeconds()

$DateTime = Get-Date #or any other command to get DateTime object
([DateTimeOffset]$DateTime).ToUnixTimeSeconds()



#view groups
(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().memberOf



Get-Volume | Select-Object -Property FileSystemLabel, 
                                     FileSystem, 
                                     HealthStatus, 
                                     @{Label="SizeGB";Expression={[math]::Round(($_.Size/1GB),2)}}, 
                                     @{Label="SizeGB-Remaining";Expression={[math]::Round(($_.SizeRemaining/1GB),2)}}, 
                                     @{Label="Percent Remaining"; Expression={[math]::Round(($_.SizeRemaining / $_.Size),2)}} | Format-Table -AutoSize -Wrap


#INSTALL TELNET
Install-WindowsFeature -Name 'Telnet-Client' -Confirm:$false -Verbose



#SID ACTIVE DIRECTORY FIND USERS
#https://infrasos.com/find-sid-in-active-directory-users-and-computers-using-powershell/

<#


S-1-0-0	Null SID	A group with no member objects. This SID is often used when a SID value is null or unknown.
S-1-1-0	World	A group that includes everyone or all users.
S-1-2-0	Local	Users who log on to local (physically connected)
S-1-2-1	Console Logon	A group includes users logged on the physical console.
S-1-3-0	Creator Owner ID	A SID to be replaced by the user’s security identifier who created a new object. This SID is used in inheritable ACEs.
S-1-3-1	Creator Group ID	A SID is replaced by the primary-group SID of the user who created a new object. Use this SID in inheritable ACEs.
S-1-3-2	Creator Owner Server	 
S-1-3-3	Creator Group Server	 
S-1-3-4	Owner Rights	A SID that represents the current owner of the object. When an ACE that carries this SID is applied to an object, the system ignores the object owner’s implicit READ_CONTROL and WRITE_DAC permissions for the object owner.
S-1-4	Non-unique Authority	A Security Identifier that represents an identifier authority.
S-1-5	NT Authority	A Security Identifier that represents an identifier authority.
S-1-5-80-0	All Services	A group includes all service processes configured on the system. The operating system controls membership.

#>

Get-LocalUser -Name $env:USERNAME | Select-Object  sid

Get-LocalUser -Name 'automyte\julianoabr' | Select-Object  sid

Get-AdUser -Identity julianoabr | Select Name, SID, UserPrincipalName

Get-ADComputer -Filter * | Select-Object Name, SID

Get-ADGroup -Identity SalesLeader | Select-Object Name, SID

(Get-ADForest).Domains| %{Get-ADDomain -Server $_} | Select-Object name, domainsid


#RSAT ON WINDOWS 10
#http://woshub.com/install-rsat-feature-windows-10-powershell/

Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State

Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”

Add-WindowsCapability –online –Name “Rsat.Dns.Tools~~~~0.0.1.0”

Add-WindowsCapability -Online -Name Rsat.FileServices.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.IPAM.Client.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.LLDP.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.NetworkController.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.NetworkLoadBalancing.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.RemoteAccess.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.RemoteDesktop.Services.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Shielded.VM.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.StorageMigrationService.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.StorageReplica.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.SystemInsights.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.VolumeActivation.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.WSUS.Tools~~~~0.0.1.0


#To install all the available RSAT tools at once, run:

Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online

#To install only disabled RSAT components, run:

Get-WindowsCapability -Online |? {$_.Name -like "*RSAT*" -and $_.State -eq "NotPresent"} | Add-WindowsCapability -Online

#Create Multiple Files for Test
1..20 | foreach {New-Item -Path .\$_.txt}


#This pipeline example gets the text files in the current directory, selects only the files that are more than 10,000 bytes long, sorts them by length, and displays the name and length of each file in a table.
Get-ChildItem -Path *.txt |
  Where-Object {$_.length -gt 10000} |
    Sort-Object -Property length |
      Format-Table -Property name, length


#GET SERVICES AND DEPENDENT SERVICES
Get-Service | Where-Object -FilterScript {$_.DependentServices -ne $null} | Select-Object -Property Name,DependentServices | Format-Table -AutoSize
