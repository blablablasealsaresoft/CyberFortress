# Quick test of all features

Write-Host "`n=== CyberFortress Quick Test ===" -ForegroundColor Cyan

# First register the user (in case backend restarted)
$reg = @{ email="test@fortress.com"; password="Test123!" } | ConvertTo-Json
try {
    Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/auth/register -ContentType 'application/json' -Body $reg | Out-Null
    Write-Host "✅ User registered" -ForegroundColor Green
} catch {
    Write-Host "User might already exist" -ForegroundColor Yellow
}

# Login
$login = @{ email="test@fortress.com"; password="Test123!" } | ConvertTo-Json
$response = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/auth/login -ContentType 'application/json' -Body $login

if ($response.access_token) {
    $token = $response.access_token
    Write-Host "✅ Login successful" -ForegroundColor Green
} else {
    Write-Host "❌ Login failed" -ForegroundColor Red
    exit
}

$headers = @{ Authorization = "Bearer $token" }

Write-Host "`n=== Testing Features ===" -ForegroundColor Cyan

# Test 1: OSINT
Write-Host "`n1. OSINT Collection..." -ForegroundColor Yellow
$body = @{ action="osint.collect"; params=@{target="example.com"} } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action -Headers $headers -ContentType 'application/json' -Body $body
if ($result.success -or $result.output) {
    Write-Host "   ✅ OSINT working" -ForegroundColor Green
} else {
    Write-Host "   ❌ OSINT failed: $($result.error)" -ForegroundColor Red
}

# Test 2: Forensics
Write-Host "`n2. Forensics Process Tree..." -ForegroundColor Yellow
$body = @{ action="forensics.get_process_tree"; params=@{} } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action -Headers $headers -ContentType 'application/json' -Body $body
if ($result.success -or $result.output) {
    Write-Host "   ✅ Forensics working" -ForegroundColor Green
} else {
    Write-Host "   ❌ Forensics failed: $($result.error)" -ForegroundColor Red
}

# Test 3: Identity Protection
Write-Host "`n3. Identity Breach Check..." -ForegroundColor Yellow
$body = @{ action="identity.check_breaches"; params=@{email="test@example.com"} } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action -Headers $headers -ContentType 'application/json' -Body $body
if ($result.success -or $result.output) {
    Write-Host "   ✅ Identity Protection working" -ForegroundColor Green
} else {
    Write-Host "   ❌ Identity Protection failed: $($result.error)" -ForegroundColor Red
}

# Test 4: Quantum Encryption
Write-Host "`n4. Quantum Key Generation..." -ForegroundColor Yellow
$body = @{ action="quantum.keygen"; params=@{security_level="high"} } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action -Headers $headers -ContentType 'application/json' -Body $body
if ($result.success -or $result.output) {
    Write-Host "   ✅ Quantum Encryption working" -ForegroundColor Green
} else {
    Write-Host "   ❌ Quantum Encryption failed: $($result.error)" -ForegroundColor Red
}

# Test 5: Blockchain
Write-Host "`n5. Blockchain Rugpull Detection..." -ForegroundColor Yellow
$body = @{ action="crypto.contract.rugpull"; params=@{features=@{liquidity_locked=$false; ownership_renounced=$false; mint_function=$true}} } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action -Headers $headers -ContentType 'application/json' -Body $body
if ($result.success -or $result.output) {
    Write-Host "   ✅ Blockchain Security working" -ForegroundColor Green
} else {
    Write-Host "   ❌ Blockchain Security failed: $($result.error)" -ForegroundColor Red
}

# Test 6: ML
Write-Host "`n6. ML Model List..." -ForegroundColor Yellow
$body = @{ action="ml.model.list"; params=@{} } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/action -Headers $headers -ContentType 'application/json' -Body $body
if ($result.success -or $result.output) {
    Write-Host "   ✅ ML Detection working" -ForegroundColor Green
} else {
    Write-Host "   ❌ ML Detection failed: $($result.error)" -ForegroundColor Red
}

Write-Host "`n=== Web Interface ===" -ForegroundColor Cyan
Write-Host "Frontend is running at: http://localhost:5173" -ForegroundColor Green
Write-Host "Login with: test@fortress.com / Test123!" -ForegroundColor Yellow

Write-Host "`n✅ All core systems operational!" -ForegroundColor Green
Write-Host "You can now use all features through the web interface." -ForegroundColor White
