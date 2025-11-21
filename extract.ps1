# === Configuration ===
$baseFolder = "D:\DiskUtils"
$outputFolder = Join-Path $baseFolder "Extracted"

# Path to 7-Zip executable
$sevenZipPath = "D:\DiskUtils\7z.exe"
if (-not (Test-Path $sevenZipPath)) {
    Write-Error "7z.exe not found at $sevenZipPath"
    return
}

# Create output folder if it doesn't exist
if (-not (Test-Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder | Out-Null
}

# === Find all VHDX files recursively ===
$vhds = Get-ChildItem -Path $baseFolder -Filter *.vhdx -Recurse

if ($vhds.Count -eq 0) {
    Write-Host "No VHDX files found in $baseFolder"
    return
}

# List all found VHDX files
Write-Host "Found $($vhds.Count) VHDX files:"
$vhds | ForEach-Object { Write-Host " - $($_.FullName)" }

# === Process each VHDX ===
foreach ($vhd in $vhds) {

    # Extract username from filename: profile_user.vhdx => user
    $username = ($vhd.BaseName -split "_")[-1]
    $outFile = Join-Path $outputFolder ("confCons_" + $username + ".xml")

    # Temp folder for extraction
    $tempDir = Join-Path $outputFolder ("temp_$username")
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    $internalPath = "Profile\AppData\Roaming\mRemoteNG\confCons.xml"

Write-Host "Processing $($vhd.FullName)... " -NoNewline

# Run 7-Zip silently using call operator
& "$sevenZipPath" e "$($vhd.FullName)" "$internalPath" "-o$tempDir" -y | Out-Null

# Move extracted file to final output
$extractedFile = Join-Path $tempDir "confCons.xml"
if (Test-Path $extractedFile) {
    Move-Item -Path $extractedFile -Destination $outFile -Force
    Write-Host "[+] completed"
} else {
    Write-Host "[-] not found"
}


    # Clean up temp folder
    Remove-Item $tempDir -Recurse -Force
}
