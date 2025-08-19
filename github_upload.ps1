# CyberFortress Pro - GitHub Upload Script

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "CyberFortress Pro - GitHub Upload" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Check git
if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git is not installed. Please install Git first." -ForegroundColor Red
    exit
}

# Initialize repository
if (!(Test-Path .git)) {
    Write-Host "Initializing Git repository..." -ForegroundColor Yellow
    git init
}

# Add files
Write-Host "Adding files..." -ForegroundColor Yellow
git add .

# Commit
Write-Host "Creating commit..." -ForegroundColor Yellow
git commit -m "Initial commit: CyberFortress Pro v1.0.0 - Enterprise cybersecurity suite"

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Create repository on GitHub.com/new" -ForegroundColor Yellow
Write-Host "   Name: cyberfortress-pro" -ForegroundColor White
Write-Host ""
Write-Host "2. Run these commands:" -ForegroundColor Yellow
Write-Host "   git remote add origin https://github.com/YOUR_USERNAME/cyberfortress-pro.git" -ForegroundColor Cyan
Write-Host "   git branch -M main" -ForegroundColor Cyan
Write-Host "   git push -u origin main" -ForegroundColor Cyan
Write-Host ""
Write-Host "Ready to upload!" -ForegroundColor Green
