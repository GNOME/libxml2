if (-not (Get-Command "7za.exe" -ErrorAction SilentlyContinue)) {
    Invoke-WebRequest -Uri https://www.7-zip.org/a/7z2201.msi -OutFile 7z2201.msi
    msiexec /i $Installer7Zip /qb
}
