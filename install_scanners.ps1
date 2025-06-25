# PowerShell script to install Trivy, Grype, and setup Clair on Windows

Write-Host "Installing Vulnerability Scanners..." -ForegroundColor Green

# Function to check if command exists
function Test-CommandExists {
    param($command)
    $null = Get-Command $command -ErrorAction SilentlyContinue
    return $?
}

# Install Trivy
Write-Host "`nInstalling Trivy..." -ForegroundColor Yellow
if (Test-CommandExists "trivy") {
    Write-Host "Trivy already installed" -ForegroundColor Green
} else {
    if (Test-CommandExists "choco") {
        choco install trivy -y
    } else {
        Write-Host "Downloading Trivy from GitHub..." -ForegroundColor Blue
        $trivyVersion = "0.52.2"
        $trivyUrl = "https://github.com/aquasecurity/trivy/releases/download/v$trivyVersion/trivy_$($trivyVersion)_Windows-64bit.zip"
        $trivyZip = "$env:TEMP\trivy.zip"
        $trivyDir = "$env:USERPROFILE\trivy"
        
        Invoke-WebRequest -Uri $trivyUrl -OutFile $trivyZip
        Expand-Archive -Path $trivyZip -DestinationPath $trivyDir -Force
        
        # Add to PATH (for current session)
        $env:PATH += ";$trivyDir"
        
        Write-Host "Trivy installed to $trivyDir" -ForegroundColor Green
        Write-Host "Add $trivyDir to your system PATH for permanent access" -ForegroundColor Blue
    }
}

# Install Grype
Write-Host "`nInstalling Grype..." -ForegroundColor Yellow
if (Test-CommandExists "grype") {
    Write-Host "Grype already installed" -ForegroundColor Green
} else {
    Write-Host "Downloading Grype from GitHub..." -ForegroundColor Blue
    $grypVersion = "0.74.7"
    $grypeUrl = "https://github.com/anchore/grype/releases/download/v$grypVersion/grype_$($grypVersion)_windows_amd64.zip"
    $grypeZip = "$env:TEMP\grype.zip"
    $grypeDir = "$env:USERPROFILE\grype"
    
    Invoke-WebRequest -Uri $grypeUrl -OutFile $grypeZip
    Expand-Archive -Path $grypeZip -DestinationPath $grypeDir -Force
    
    # Add to PATH (for current session)
    $env:PATH += ";$grypeDir"
    
    Write-Host "Grype installed to $grypeDir" -ForegroundColor Green
    Write-Host "Add $grypeDir to your system PATH for permanent access" -ForegroundColor Blue
}

# Check Docker for Clair
Write-Host "`nChecking Docker for Clair..." -ForegroundColor Yellow
if (Test-CommandExists "docker") {
    Write-Host "Docker found" -ForegroundColor Green
    Write-Host "To start Clair, run: docker-compose up -d" -ForegroundColor Blue
} else {
    Write-Host "Docker not found. Please install Docker Desktop for Windows" -ForegroundColor Red
    Write-Host "Download from: https://www.docker.com/products/docker-desktop" -ForegroundColor Blue
}

# Test installations
Write-Host "`nTesting installations..." -ForegroundColor Yellow

if (Test-CommandExists "trivy") {
    $trivyVersion = & trivy --version
    Write-Host "Trivy: $trivyVersion" -ForegroundColor Green
} else {
    Write-Host "Trivy not found in PATH" -ForegroundColor Red
}

if (Test-CommandExists "grype") {
    $grypeVersion = & grype version
    Write-Host "Grype: $grypeVersion" -ForegroundColor Green
} else {
    Write-Host "Grype not found in PATH" -ForegroundColor Red
}

Write-Host "`nInstallation complete!" -ForegroundColor Green
Write-Host "Usage examples:" -ForegroundColor Blue
Write-Host "   python scan_all.py nginx:latest" -ForegroundColor White
Write-Host "   python scan_all.py ." -ForegroundColor White
Write-Host "   python scan_all.py https://github.com/user/repo" -ForegroundColor White
