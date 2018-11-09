#region Functions
function New-ClientVHDX {
    param
    (
        [string]$vhdxPath,
        [Parameter(Mandatory = $false)]
        [string]$unattend = "none",
        [string]$WinISO
    )
    $convMod = get-module -ListAvailable -Name 'Convert-WindowsImage'
    if ($convMod.count -ne 1) {
        Install-Module -name 'Convert-WindowsImage' -Scope AllUsers
    }
    else {
        Update-Module -Name 'Convert-WindowsImage'    
    }
    Import-module -name 'Convert-Windowsimage'
    if ($unattend -eq "none") {
        Convert-WindowsImage -SourcePath $WinISO -Edition 3 -VhdType Dynamic -VhdFormat VHDX -VhdPath $vhdxPath -DiskLayout UEFI -SizeBytes 127gb
    }
    else {
        Convert-WindowsImage -SourcePath $WinISO -Edition 3 -VhdType Dynamic -VhdFormat VHDX -VhdPath $vhdxPath -DiskLayout UEFI -SizeBytes 127gb -UnattendPath $unattend    
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
            $severity = 3
            $fgColor = "Red"
            break;
        }
        'Information' {
            $severity = 6
            $fgColour = "Yellow"
            break;
        }
    }
    $dateTime = New-Object -ComObject WbemScripting.SWbemDateTime
    $dateTime.SetVarDate($(Get-Date))
    $utcValue = $dateTime.Value
    $utcOffset = $utcValue.Substring(21, $utcValue.Length - 21)
    $scriptName = (Get-PSCallStack)[1]
    $logLine = `
        "<![LOG[$message]LOG]!>" + `
        "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($utcOffset)`" " + `
        "date=`"$(Get-Date -Format M-d-yyyy)`" " + `
        "component=`"$($scriptName.Command)`" " + `
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
        "type=`"$severity`" " + `
        "thread=`"$PID`" " + `
        "file=`"$($scriptName.ScriptName)`">";
        
    $logLine | Out-File -Append -Encoding utf8 -FilePath $logFile -Force
    Write-Host $Message -ForegroundColor $fgColor
}

function New-ClientVM {
    [cmdletBinding()]
    param (
        [string]$vmName,
        [string]$refVHDX,
        [string]$clientPath,
        [pscredential]$localAdmin,
        [string]$refApVHDX
    )
    Copy-Item -Path $refVHDX -Destination "$clientPath\$vmName.vhdx"
    new-vm -Name $vmName -MemoryStartupBytes 2Gb -VHDPath "$clientPath\$vmName.vhdx" -Generation 2 | out-null
    Enable-VMIntegrationService -vmName $vmName -Name "Guest Service Interface"
    set-vm -name $vmName -CheckpointType Disabled
    start-vm -Name $vmName
    Get-VMNetworkAdapter -vmName $vmName | Connect-VMNetworkAdapter -SwitchName 'Internet' | Set-VMNetworkAdapter -Name 'Internet' -DeviceNaming On
    while ((Invoke-Command -vmName $vmName -Credential $localAdmin {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {Start-Sleep -Seconds 5}
    $wkSession = new-PSSession -vmName $vmName -Credential $localAdmin

    $serial = Invoke-Command -Session $wkSession -ScriptBlock {(Get-WmiObject -Class Win32_BIOS).SerialNumber}
    $hash = Invoke-Command -Session $wkSession -ScriptBlock {(Get-WMIObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData}
    #$ap = Invoke-Command -Session $wkSession -ScriptBlock {Install-PackageProvider -name "nuget" -ForceBootstrap -Force | Out-Null; Install-Script -Name "get-windowsautopilotinfo" -Force; Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; get-windowsautopilotinfo.ps1}
    $ap = [PSCustomObject]@{
        "Device Serial Number" = $serial
        "Windows Product ID" = ""
        "Hardware Hash" = $hash
    }
    Stop-VM -Name $vmName -TurnOff -Force
    copy-item -path $refApVHDX -Destination "$clientPath\$vmName.vhdx"
    return $ap
}
#endregion
#region Config
$scriptPath = $PSScriptRoot
$config = Get-Content "$scriptPath\client.json" -Raw | ConvertFrom-Json
$clientDetails = $config.ENVConfig | Where-Object {$_.ClientName -eq $config.Client}
$clientPath = "$($config.ClientVMPath)\$($config.Client)"
if (!(Test-Path $clientPath)) {new-item -ItemType Directory -Force -Path $clientPath | Out-Null}
$script:logfile = "$clientPath\Build.log"
$refVHDX = $config.Win10VHDX
$refApVHDX = $config.Win10APVHDX
$clientName = $clientDetails.ClientName
$win10iso = $config.Win101803ISO
$defaultClientPassword = $config.defaultpassword
$localAdmin = new-object -typename System.Management.Automation.PSCredential -argumentlist "administrator", (ConvertTo-SecureString -String $defaultClientPassword -AsPlainText -Force)
$numOfVMs = $clientDetails.NumberofClients
$adminUser = $clientDetails.adminuser
$aadsecgroup = $clientDetails.AADDynGroupName
$APOrderNumber = $config.OrderNumber
Write-LogEntry -Type Information -Message "Path to Reference VHDX is: $refVHDX"
Write-LogEntry -Type Information -Message "Path to AutoPilot Reference VHDX is: $refApVHDX"
Write-LogEntry -Type Information -Message "Client name is: $clientName"
Write-LogEntry -Type Information -Message "Win10 ISO is located: $win10iso"
Write-LogEntry -Type Information -Message "Default Password is: $defaultClientPassword"
Write-LogEntry -Type Information -Message "Path to client VMs will be: $clientPath"
Write-LogEntry -Type Information -Message "Number of VMs to create: $numOfVMs"
Write-LogEntry -type Information -Message "Admin user for tenant: $clientName is: $adminUser"
Write-LogEntry -Type Information -Message "AAD Security group name is: $aadsecgroup"
Write-LogEntry -Type Information -Message "Auto Pilot order number is: $APOrderNumber"
#endregion
#region New ClientVHDX
if (!(test-path -path $refVHDX -ErrorAction SilentlyContinue)) {
    Write-LogEntry -Type Information -Message "Creating Workstation VHDX"
    new-ClientVHDX -vhdxpath $refVHDX -unattend "$scriptPath\wks-unattended.xml" -winiso $win10iso
    Write-LogEntry -Type Information -Message "Workstation VHDX has been created"
}
if (!(test-path -path $refApVHDX -ErrorAction SilentlyContinue)) {
    Write-LogEntry -Type Information -Message "Creating Workstation AutoPilot VHDX"
    new-ClientVHDX -vhdxpath $refApVHDX -winiso $win10iso
    Write-LogEntry -Type Information -Message "Workstation AutoPilot VHDX has been created"
}
#endregion
#region New Client VM
$apOut = @()
if (!(test-path -Path $clientPath)) {New-Item -ItemType Directory -Force -Path $clientPath}
if ($numOfVMs -eq 1) {
    $vmName = "$($clientName)ap$numOfVMs"
    $AP = new-clientVM -vmName $vmName -refVHDX $refVHDX -clientpath $clientPath -localAdmin $localAdmin -refAPVHDX $refApVHDX
    $ap | Out-File -FilePath "$clientPath\ap$numOfVMs.csv"
    $apOut += $ap
}
else {
    $vnum = 1
    while ($vnum -ne ($numOfVMs + 1)) {
        $vmName = "$($clientName)ap$vnum"
        $apOut += new-clientVM -vmName $vmName -refVHDX $refVHDX -clientpath $clientPath -localAdmin $localAdmin -refAPVHDX $refApVHDX
        $vnum++
    }
}
#endregion
#region Device Enrolment
($apOut | Select-Object 'Device Serial Number', 'Windows Product ID', 'hardware hash' | convertto-csv -NoTypeInformation ) -replace "`"", "" | out-file "$clientPath\ap.csv" -append
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
Set-Clipboard $adminUser
Write-LogEntry -Message "admin user email added to clipboard: $adminUser"
connect-azuread
$apContent = Import-Csv "$clientPath\ap.csv"
Connect-AutoPilotIntune -user $adminUser | Out-Null
Import-AutoPilotCSV -csvFile "$clientPath\ap.csv"
$grp = get-azureadgroup -SearchString $aadsecgroup
foreach ($ap in $apContent) {
    while ((Get-AzureADDevice -SearchString $ap.'Device Serial Number').count -ne 1) {
        Start-Sleep -Seconds 10
    }
    $device = Get-AzureADDevice -SearchString $ap.'Device Serial Number'
    Add-AzureADGroupMember -ObjectId $grp.objectid -RefObjectId $device.objectid
}
#endregion
