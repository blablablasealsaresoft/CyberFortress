# Script to upload CyberFortress Pro to GitHub

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "CyberFortress Pro - GitHub Upload" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Check if git is installed
if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git is not installed. Please install Git first." -ForegroundColor Red
    Write-Host "Download from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit
}

# Initialize git repository if not already initialized
if (!(Test-Path .git)) {
    Write-Host "`nInitializing Git repository..." -ForegroundColor Yellow
    git init
    Write-Host "✅ Git repository initialized" -ForegroundColor Green
} else {
    Write-Host "✅ Git repository already initialized" -ForegroundColor Green
}

# Add all files
Write-Host "`nAdding files to Git..." -ForegroundColor Yellow
git add .
Write-Host "✅ Files added to staging" -ForegroundColor Green

# Create initial commit
Write-Host "`nCreating initial commit..." -ForegroundColor Yellow
git commit -m "Initial commit: CyberFortress Pro v1.0.0

- Complete enterprise-grade cybersecurity suite
- 648 backend API endpoints
- 50+ Python security tools
- Identity protection & data broker removal
- Quantum-resistant encryption
- Automated threat response
- OSINT investigation tools
- Digital forensics suite
- Blockchain security
- ML-powered detection
- Network security features"

Write-Host "✅ Initial commit created" -ForegroundColor Green

# Instructions for GitHub
Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Next Steps to Upload to GitHub:" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

Write-Host "`n1. Create a new repository on GitHub:" -ForegroundColor Yellow
Write-Host "   - Go to: https://github.com/new" -ForegroundColor White
Write-Host "   - Repository name: cyberfortress-pro" -ForegroundColor White
Write-Host "   - Description: Enterprise-Grade Cybersecurity Suite for Individuals" -ForegroundColor White
Write-Host "   - Make it Public or Private as desired" -ForegroundColor White
Write-Host "   - DON'T initialize with README (we already have one)" -ForegroundColor Red
Write-Host "   - Click 'Create repository'" -ForegroundColor White

Write-Host "`n2. After creating the repository, run these commands:" -ForegroundColor Yellow
Write-Host "   (Replace 'yourusername' with your GitHub username)" -ForegroundColor Red

Write-Host "`n" -NoNewline
Write-Host '   git remote add origin https://github.com/yourusername/cyberfortress-pro.git' -ForegroundColor Cyan
Write-Host '   git branch -M main' -ForegroundColor Cyan
Write-Host '   git push -u origin main' -ForegroundColor Cyan

Write-Host "`n3. Optional: Create additional branches for development:" -ForegroundColor Yellow
Write-Host '   git checkout -b develop' -ForegroundColor Cyan
Write-Host '   git push -u origin develop' -ForegroundColor Cyan

Write-Host "`n4. Optional: Add GitHub Actions for CI/CD:" -ForegroundColor Yellow
Write-Host "   - Create .github/workflows/ directory" -ForegroundColor White
Write-Host "   - Add rust.yml for Rust tests" -ForegroundColor White
Write-Host "   - Add node.yml for frontend tests" -ForegroundColor White

Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Repository Structure:" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

# Show what will be uploaded
Write-Host "`nMain directories to be uploaded:" -ForegroundColor Yellow
Get-ChildItem -Directory | Select-Object -First 10 | ForEach-Object {
    Write-Host "  📁 $($_.Name)" -ForegroundColor White
}

Write-Host "`nMain files to be uploaded:" -ForegroundColor Yellow
Get-ChildItem -File | Select-Object -First 10 | ForEach-Object {
    Write-Host "  📄 $($_.Name)" -ForegroundColor White
}

# Count statistics
$rustFiles = (Get-ChildItem -Path app/backend/src -Filter *.rs -Recurse).Count
$tsFiles = (Get-ChildItem -Path app/frontend/src -Filter *.tsx -Recurse -ErrorAction SilentlyContinue).Count
$pyFiles = (Get-ChildItem -Path app/tools/python -Filter *.py -Recurse).Count

Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "Project Statistics:" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "  Rust files: $rustFiles" -ForegroundColor Yellow
Write-Host "  TypeScript/React files: $tsFiles" -ForegroundColor Yellow
Write-Host "  Python tools: $pyFiles" -ForegroundColor Yellow
Write-Host "  Total API endpoints: 648" -ForegroundColor Green
Write-Host "  Security features: 50+" -ForegroundColor Green

Write-Host "`n✅ Ready to upload to GitHub!" -ForegroundColor Green
Write-Host "Follow the steps above to complete the upload." -ForegroundColor White
