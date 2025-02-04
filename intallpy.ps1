function Install-Python {
    try {
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.10.2/python-3.10.2-amd64.exe" -OutFile "python-3.10.2-amd64.exe"
        Start-Process -FilePath ".\python-3.10.2-amd64.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -NoNewWindow -Wait
        $result = python --version 2>&1
        Write-Host "Python installation result: $result"
    } catch {
        Write-Host "An error occurred: $_"
    }
}

Install-Python
