# Test script to verify which features are working

Write-Host "`n=== Testing CyberFortress Features ===" -ForegroundColor Cyan

# Get auth token
$login = @{ email="user@example.com"; password="Passw0rd!" } | ConvertTo-Json
$token = (Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/auth/login -ContentType 'application/json' -Body $login).access_token

if (!$token) {
    Write-Host "Failed to get auth token!" -ForegroundColor Red
    exit
}

Write-Host "✅ Authentication working" -ForegroundColor Green

# Test function
function Test-Action {
    param($Name, $Action, $Params)
    
    Write-Host "`nTesting: $Name" -ForegroundColor Yellow
    
    $body = @{
        action = $Action
        params = $Params
    } | ConvertTo-Json -Depth 10
    
    try {
        $result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action `
            -Headers @{ Authorization = "Bearer $token" } `
            -ContentType 'application/json' `
            -Body $body -ErrorAction Stop
        
        if ($result.error) {
            Write-Host "  ❌ Error: $($result.error)" -ForegroundColor Red
            return $false
        } else {
            Write-Host "  ✅ Success" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "  ❌ Failed: $_" -ForegroundColor Red
        return $false
    }
}

# Test various features
$tests = @(
    @{Name="OSINT Collection"; Action="osint.collect"; Params=@{target="example.com"}},
    @{Name="OSINT Social"; Action="osint.social"; Params=@{username="testuser"}},
    @{Name="Forensics Process Tree"; Action="forensics.get_process_tree"; Params=@{}},
    @{Name="Forensics Artifacts"; Action="forensics.collect_artifacts"; Params=@{}},
    @{Name="Blockchain Rugpull"; Action="crypto.contract.rugpull"; Params=@{features=@{liquidity_locked=$false; ownership_renounced=$false; mint_function=$true}}},
    @{Name="ML Model List"; Action="ml.model.list"; Params=@{}},
    @{Name="Identity Breach Check"; Action="identity.check_breaches"; Params=@{email="test@example.com"}},
    @{Name="Quantum Key Gen"; Action="quantum.keygen"; Params=@{security_level="high"}},
    @{Name="Response Assessment"; Action="response.assess"; Params=@{threat_data=@{type="malware"; score=85}}}
)

$passed = 0
$failed = 0

foreach ($test in $tests) {
    if (Test-Action -Name $test.Name -Action $test.Action -Params $test.Params) {
        $passed++
    } else {
        $failed++
    }
}

Write-Host "`n=== Results ===" -ForegroundColor Cyan
Write-Host "Passed: $passed/$($tests.Count)" -ForegroundColor Green
Write-Host "Failed: $failed/$($tests.Count)" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })

if ($failed -gt 0) {
    Write-Host "`nSome features are not working. This is likely because:" -ForegroundColor Yellow
    Write-Host "1. Python tools are returning plain text instead of JSON" -ForegroundColor Yellow
    Write-Host "2. Python dependencies are not installed" -ForegroundColor Yellow
    Write-Host "3. File paths are incorrect" -ForegroundColor Yellow
    
    Write-Host "`nTo fix:" -ForegroundColor Cyan
    Write-Host "1. Install Python dependencies: pip install -r requirements.txt" -ForegroundColor White
    Write-Host "2. Make sure Python scripts return valid JSON" -ForegroundColor White
}
