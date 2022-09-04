if (-not (Test-Path libxml2-build/xmlconf)) {
    Invoke-WebRequest -Uri https://www.w3.org/XML/Test/xmlts20080827.tar.gz -OutFile xmlts20080827.tar.gz
    .\7za.exe x xmlts20080827.tar.gz -olibxml2-build
}
