# portview installer for Windows
# Usage: irm https://raw.githubusercontent.com/mapika/portview/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo = 'mapika/portview'
$Binary = 'portview.exe'
$InstallDir = "$env:USERPROFILE\.portview\bin"

# -- Detect architecture --

$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($Arch) {
    'X64'   { $Target = 'windows-x86_64' }
    default { Write-Error "Unsupported architecture: $Arch"; exit 1 }
}

# -- Fetch latest release --

Write-Host "-> Detecting latest release..."
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
$Version = $Release.tag_name -replace '^v', ''

if (-not $Version) {
    Write-Error "Could not determine latest version."
    exit 1
}

$Url = "https://github.com/$Repo/releases/download/v$Version/portview-$Target.zip"
$ChecksumUrl = "https://github.com/$Repo/releases/download/v$Version/SHA256SUMS"

Write-Host "-> Downloading portview v$Version for $Target..."

# -- Download and verify --

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "portview-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    $ZipPath = Join-Path $TmpDir 'portview.zip'
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

    # Try to download and verify checksum
    try {
        $SumsPath = Join-Path $TmpDir 'SHA256SUMS'
        Invoke-WebRequest -Uri $ChecksumUrl -OutFile $SumsPath -UseBasicParsing

        Write-Host "-> Verifying checksum..."
        $Expected = (Get-Content $SumsPath | Where-Object { $_ -match "portview-$Target\.zip" }) -replace '\s+.*$', ''
        $Actual = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()

        if (-not $Expected) {
            Write-Host "Warning: No checksum found for portview-$Target.zip in SHA256SUMS"
        } elseif ($Expected -ne $Actual) {
            Write-Error "Checksum verification failed!`n  Expected: $Expected`n  Actual:   $Actual"
            exit 1
        } else {
            Write-Host "Checksum verified"
        }
    } catch {
        Write-Host "Warning: SHA256SUMS not available, skipping integrity verification"
    }

    # -- Extract --

    Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

    # -- Install --

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Copy-Item -Path (Join-Path $TmpDir $Binary) -Destination (Join-Path $InstallDir $Binary) -Force
    Write-Host "Installed portview to $InstallDir\$Binary"

    # Add to user PATH if not already present
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$InstallDir;$UserPath", 'User')
        Write-Host "  Added $InstallDir to user PATH (restart your terminal to take effect)"
    }

    Write-Host "  Run 'portview' to get started."
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
