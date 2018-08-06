function new-ClientVHDX {
    param
    (
        [string]$vhdxpath,
        [Parameter(Mandatory = $false)]
        [string]$unattend = "none",
        [string]$WinISO
    )
    $convmod = get-module -ListAvailable -Name 'Convert-WindowsImage'
    if ($convmod.count -ne 1) {
        Install-Module -name 'Convert-WindowsImage' -Scope AllUsers
    }
    else {
        Update-Module -Name 'Convert-WindowsImage'    
    }
    Import-module -name 'Convert-Windowsimage'
    if ($unattend -eq "none") {
        Convert-WindowsImage -SourcePath $WinISO -Edition 3 -VhdType Dynamic -VhdFormat VHDX -VhdPath $vhdxpath -DiskLayout UEFI -SizeBytes 127gb
    }
    else {
        Convert-WindowsImage -SourcePath $WinISO -Edition 3 -VhdType Dynamic -VhdFormat VHDX -VhdPath $vhdxpath -DiskLayout UEFI -SizeBytes 127gb -UnattendPath $unattend    
    }
}
function Write-LogEntry {
    [cmdletBinding()]
    param (
        [ValidateSet("Information", "Error")]
        $Type = "Information",
        [parameter(Mandatory = $true)]
        $Message
    )
    switch ($Type) {
        'Error' {
            $Severity = 3
            break;
        }
        'Information' {
            $Severity = 6
            break;
        }
    }
    $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
    $DateTime.SetVarDate($(Get-Date))
    $UtcValue = $DateTime.Value
    $UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)
    $scriptname = (Get-PSCallStack)[1]
    $logline = `
        "<![LOG[$message]LOG]!>" + `
        "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " + `
        "date=`"$(Get-Date -Format M-d-yyyy)`" " + `
        "component=`"$($scriptname.Command)`" " + `
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
        "type=`"$Severity`" " + `
        "thread=`"$PID`" " + `
        "file=`"$($Scriptname.ScriptName)`">";
        
    $logline | Out-File -Append -Encoding utf8 -FilePath $Logfile -Force
    Write-Verbose $Message
}

function new-clientVM {
    [cmdletBinding()]
    param (
        [string]$vmname,
        [string]$refvhdx,
        [string]$clientpath,
        [string]$localadmin,
        [string]$refAPVHDX
    )
    copy-item -Path $RefVHDX -Destination "$ClientPath\$vmname.vhdx"
    new-vm -Name $vmname -MemoryStartupBytes 8Gb -VHDPath "$ClientPath\$vmname.vhdx" -Generation 2 | out-null
    Enable-VMIntegrationService -VMName $vmname -Name "Guest Service Interface"
    set-vm -name $vmname -CheckpointType Disabled
    start-vm -Name $vmname
    Get-VMNetworkAdapter -vmname $vmname | Connect-VMNetworkAdapter -SwitchName 'Internet' | Set-VMNetworkAdapter -Name 'Internet' -DeviceNaming On
    while ((Invoke-Command -VMName $vmname -Credential $localadmin {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {Start-Sleep -Seconds 5}
    $wkssession = new-PSSession -VMName $vmname -Credential $localadmin
    $ap = Invoke-Command -Session $wkssession -ScriptBlock {Install-PackageProvider -name "nuget" -ForceBootstrap -Force | Out-Null; Install-Script -Name "get-windowsautopilotinfo" -Force; Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; get-windowsautopilotinfo.ps1}
    $ap | Select-Object 'Device Serial Number', 'Windows Product ID', 'hardware hash' | export-csv -path "$clientpath\ap.csv" -NoTypeInformation -append
    Stop-VM -Name $vmname -TurnOff -Force
    copy-item -path $refAPVHDX -Destination "$ClientPath\$vmname.vhdx"
}

$scriptpath = $PSScriptRoot
$config = Get-Content "$scriptpath\client.json" -Raw | ConvertFrom-Json
$ClientDetails = $config.ENVConfig | Where-Object {$_.ClientName -eq $config.Client}
$ClientPath = "$($config.ClientVMPath)\$($config.Client)"
if (!(Test-Path $ClientPath)) {new-item -ItemType Directory -Force -Path $ClientPath | Out-Null}
$script:logfile = "$ClientPath\Build.log"
$RefVHDX = $config.Win10VHDX
Write-LogEntry -Type Information -Message "Path to Reference VHDX is: $RefVHDX"
$refAPVHDX = $config.Win10APVHDX
Write-LogEntry -Type Information -Message "Path to AutoPilot Reference VHDX is: $refAPVHDX"
$clientname = $ClientDetails.ClientName
Write-LogEntry -Type Information -Message "Client name is: $clientname"
$win10iso = $config.Win101803ISO
Write-LogEntry -Type Information -Message "Win10 ISO is located: $win10iso"
$defaultclientpassword = $config.defaultpassword
Write-LogEntry -Type Information -Message "Default Password is: $defaultclientpassword"
$localadmin = new-object -typename System.Management.Automation.PSCredential -argumentlist "administrator", (ConvertTo-SecureString -String $defaultclientpassword -AsPlainText -Force)
Write-LogEntry -Type Information -Message "Path to client VMs will be: $clientpath"
$numofVMs = $ClientDetails.NumberofClients
Write-LogEntry -Type Information -Message "Number of VMs to create: $numofvms"
$adminuser = $ClientDetails.adminuser
Write-LogEntry -type Information -Message "Admin user for tenant: $clientname is: $adminuser"
$aadsecgroup = $ClientDetails.AADDynGroupName
Write-LogEntry -Type Information -Message "AAD Security group name is: $aadsecgroup"
$APOrderNumber = $config.OrderNumber
Write-LogEntry -Type Information -Message "Auto Pilot order number is: $APOrderNumber"

if (!(test-path -path $RefVHDX -ErrorAction SilentlyContinue)) {
    Write-LogEntry -Type Information -Message "Creating Workstation VHDX"
    new-ClientVHDX -vhdxpath $refvhdx -unattend "$scriptpath\wks-unattended.xml" -winiso $win10iso
    Write-LogEntry -Type Information -Message "Workstation VHDX has been created"
}
if (!(test-path -path $RefapVHDX -ErrorAction SilentlyContinue)) {
    Write-LogEntry -Type Information -Message "Creating Workstation AutoPilot VHDX"
    new-ClientVHDX -vhdxpath $refapvhdx -winiso $win10iso
    Write-LogEntry -Type Information -Message "Workstation AutoPilot VHDX has been created"
}

if (!(test-path -Path $ClientPath)) {New-Item -ItemType Directory -Force -Path $ClientPath}
if (!$numofVMs -gt 1) {
    $vmname = "$($clientname)ap$numofvms"
    new-clientVM -vmname $vmname -refvhdx $RefVHDX -clientpath $ClientPath -localadmin $localadmin -refAPVHDX $refAPVHDX
}
else {
    $vnum = 1
    while ($vnum -ne ($numofVMs + 1)) {
        $vmname = "$($clientname)ap$vnum"
        new-clientVM -vmname $vmname -refvhdx $RefVHDX -clientpath $ClientPath -localadmin $localadmin -refAPVHDX $refAPVHDX
        $vnum++
    }
}
if ((get-module -listavailable -name AzureADPreview).count -ne 1) {
    install-module -name AzureADPreview -scope allusers -Force -AllowClobber
}
else {
    update-module -name AzureADPreview
}
import-module -name AzureADPreview
if ((get-module -listavailable -name WindowsAutoPilotIntune).count -ne 1) {
    install-module -name WindowsAutoPilotIntune -scope allusers -Force
}
else {
    update-module -name WindowsAutoPilotIntune
}
import-module -name WindowsAutoPilotIntune
Set-Clipboard $adminuser
connect-azuread
$apcontent = Import-Csv "$clientpath\ap.csv"
Connect-AutoPilotIntune -user $adminuser | Out-Null
Import-AutoPilotCSV -csvFile "$ClientPath\ap.csv" -orderIdentifier $APOrderNumber
$grp = get-azureadgroup -SearchString $aadsecgroup
foreach ($ap in $apcontent) {
    while ((Get-AzureADDevice -SearchString $ap.'Device Serial Number').count -ne 1) {Start-Sleep -Seconds 10}
    $device = Get-AzureADDevice -SearchString $ap.'Device Serial Number'
    Add-AzureADGroupMember -ObjectId $grp.objectid -RefObjectId $device.objectid
}
#Start-Sleep -Seconds 600
#get-vm "$($clientname)ap*" | start-vm