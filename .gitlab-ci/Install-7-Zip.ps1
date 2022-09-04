if (-not (Test-Path 7za.exe)) {
    Invoke-WebRequest -Uri https://www.7-zip.org/a/7z1900-extra.7z -OutFile 7z1900-extra.7z
    cmake -E tar xf 7z1900-extra.7z 7za.exe
}
