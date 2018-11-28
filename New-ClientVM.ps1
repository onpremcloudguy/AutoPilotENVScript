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
        [string]$clientPath,
        [pscredential]$localAdmin,
        [string]$refApVHDX
    )
    copy-item -path $refApVHDX -Destination "$clientPath\$vmName.vhdx"
    $disk = (Mount-VHD -Path "$clientPath\$vmName.vhdx" -Passthru | Get-disk | Get-Partition | Where-Object {$_.type -eq 'Basic'}).DriveLetter
    copy-item -path "$clientPath\" -Destination "$disk`:\Windows\Provisioning\Autopilot\" -Recurse -Filter "AutopilotConfigurationFile.json"
    dismount-vhd "$clientPath\$vmName.vhdx"
    new-vm -Name $vmName -MemoryStartupBytes 2Gb -VHDPath "$clientPath\$vmName.vhdx" -Generation 2 | out-null
    Enable-VMIntegrationService -vmName $vmName -Name "Guest Service Interface"
    set-vm -name $vmName -CheckpointType Disabled
    start-vm -Name $vmName
    Get-VMNetworkAdapter -vmName $vmName | Connect-VMNetworkAdapter -SwitchName 'Internet' | Set-VMNetworkAdapter -Name 'Internet' -DeviceNaming On
}
#endregion
#region Config
$scriptPath = $PSScriptRoot
$config = Get-Content "$scriptPath\client.json" -Raw | ConvertFrom-Json
$clientDetails = $config.ENVConfig | Where-Object {$_.ClientName -eq $config.Client}
$clientPath = "$($config.ClientVMPath)\$($config.Client)"
if (!(Test-Path $clientPath)) {new-item -ItemType Directory -Force -Path $clientPath | Out-Null}
$script:logfile = "$clientPath\Build.log"
$refApVHDX = $config.Win10APVHDX
$clientName = $clientDetails.ClientName
$win10iso = $config.Win101809ISO
$numOfVMs = $clientDetails.NumberofClients
$adminUser = $clientDetails.adminuser
Write-LogEntry -Type Information -Message "Path to AutoPilot Reference VHDX is: $refApVHDX"
Write-LogEntry -Type Information -Message "Client name is: $clientName"
Write-LogEntry -Type Information -Message "Win10 ISO is located: $win10iso"
Write-LogEntry -Type Information -Message "Path to client VMs will be: $clientPath"
Write-LogEntry -Type Information -Message "Number of VMs to create: $numOfVMs"
Write-LogEntry -type Information -Message "Admin user for tenant: $clientName is: $adminUser"
if (!(test-path -path $refApVHDX -ErrorAction SilentlyContinue)) {
    Write-LogEntry -Type Information -Message "Creating Workstation AutoPilot VHDX"
    new-ClientVHDX -vhdxpath $refApVHDX -winiso $win10iso
    Write-LogEntry -Type Information -Message "Workstation AutoPilot VHDX has been created"
}
#endregion
#region getAPPolicy
if (!(Test-path -path "$clientPath\AutopilotConfigurationFile.json" -ErrorAction SilentlyContinue)) {
    if ((get-module -listavailable -name WindowsAutoPilotIntune).count -ne 1) {
        install-module -name WindowsAutoPilotIntune -scope allusers -Force
    }
    else {
        update-module -name WindowsAutoPilotIntune
    }
    import-module -name WindowsAutoPilotIntune
    Connect-AutoPilotIntune -user $adminUser
    Get-AutoPilotProfile | ConvertTo-AutoPilotConfigurationJSON | Out-File "$clientPath\AutopilotConfigurationFile.json" -Encoding ascii
}
#endregion
#region New Client VM
$apOut = @()
if (!(test-path -Path $clientPath)) {New-Item -ItemType Directory -Force -Path $clientPath}
if ($numOfVMs -eq 1) {
    $vmName = "$($clientName)ap$numOfVMs"
    $AP = new-clientVM -vmName $vmName -clientpath $clientPath -localAdmin $localAdmin -refAPVHDX $refApVHDX
    $ap | Out-File -FilePath "$clientPath\ap$numOfVMs.csv"
    $apOut += $ap
}
else {
    $vnum = 1
    while ($vnum -ne ($numOfVMs + 1)) {
        $vmName = "$($clientName)ap$vnum"
        $apOut += new-clientVM -vmName $vmName -clientpath $clientPath -localAdmin $localAdmin -refAPVHDX $refApVHDX
        $vnum++
    }
}
#endregion