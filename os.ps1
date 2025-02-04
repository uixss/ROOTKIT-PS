function Get-OSVersion {
    try {
        $osVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
        return $osVersion
    } catch {
        Write-Host "." -ForegroundColor Red
        exit
    }
}

function Check-SupportedOS {
    $supportedVersions = @(
        "Windows 10 Home",
        "Windows 10 Pro",
        "Windows 10 Education",
        "Windows 10 Enterprise",
        "Windows 11 Home",
        "Windows 11 Pro",
        "Windows 11 Education",
        "Windows 11 Enterprise"
    )

    $currentOS = Get-OSVersion

    if ($supportedVersions -notcontains $currentOS) {
        exit
    } else {
        Write-Host "$currentOS" -ForegroundColor Green
    }
}

Check-SupportedOS