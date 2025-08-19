param(
    [switch]$QuickScan,
    [switch]$Export,
    [string]$Email,
    [string]$Phone,
    [string]$FullName
)

function Show-IdentityMenu {
    Clear-Host
    Write-Host "🛡️ CyberFortress Identity Protection Suite" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "1. Quick Exposure Scan" -ForegroundColor Green
    Write-Host "2. Data Broker Removal Planner (offline)" -ForegroundColor Yellow
    Write-Host "3. Privacy Restoration Checklist Export" -ForegroundColor Yellow
    Write-Host "4. Generate Identity Protection Report" -ForegroundColor Magenta
    Write-Host "5. Exit" -ForegroundColor Gray

    $choice = Read-Host "Select option (1-5)"
    switch ($choice) {
        "1" { Run-QuickExposureScan; Prompt-Continue; Show-IdentityMenu }
        "2" { Generate-DataBrokerRemovalPlan; Prompt-Continue; Show-IdentityMenu }
        "3" { Export-PrivacyChecklist; Prompt-Continue; Show-IdentityMenu }
        "4" { Generate-IdentityReport -Export; Prompt-Continue; Show-IdentityMenu }
        "5" { return }
        default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep 1; Show-IdentityMenu }
    }
}

function Prompt-Continue {
    [void](Read-Host "Press Enter to continue...")
}

function Run-QuickExposureScan {
    Write-Host "🔎 Running quick exposure scan (offline heuristics)..." -ForegroundColor Green
    $result = [PSCustomObject]@{
        Timestamp = Get-Date
        EmailProvided = [string]::IsNullOrWhiteSpace($Email) -eq $false
        PhoneProvided = [string]::IsNullOrWhiteSpace($Phone) -eq $false
        NameProvided  = [string]::IsNullOrWhiteSpace($FullName) -eq $false
        LikelyDataBrokerPresence = if ($Email -or $Phone) { 'POSSIBLE' } else { 'UNKNOWN' }
        DarkWebExposureRisk = if ($Email) { 'ELEVATED' } else { 'UNKNOWN' }
        RecommendedActions = @(
            'Enable 2FA on all key accounts',
            'Rotate critical passwords',
            'Freeze credit at major bureaus',
            'Remove from top data brokers',
            'Monitor for new breaches weekly'
        )
    }
    $result | Format-List | Out-Host
    return $result
}

function Generate-DataBrokerRemovalPlan {
    Write-Host "📋 Generating Data Broker Removal Planner (offline)..." -ForegroundColor Yellow
    $brokers = @(
        'Spokeo','BeenVerified','PeopleFinders','Whitepages','Intelius','TruthFinder','US Search','Radaris','MyLife','Nuwber','PeekYou','RocketReach','Pipl','FastPeopleSearch','CUBIB'
    )
    $plan = $brokers | ForEach-Object {
        [PSCustomObject]@{
            Broker = $_
            Status = 'PENDING'
            RequiresID = $true
            Method = 'Email/Form'
            SLA_Days = 30
        }
    }
    $out = "data_broker_removal_plan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $plan | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $out
    Write-Host "✅ Plan saved to $out" -ForegroundColor Green
    return $out
}

function Export-PrivacyChecklist {
    $content = @"
Privacy Restoration Checklist
Generated: $(Get-Date)

- Remove from top data brokers (plan generated)
- Freeze credit (Experian, Equifax, TransUnion)
- Rotate email aliases; use catch-all where possible
- Audit social media privacy settings
- Close unused accounts (email/search tool to find)
- Enable hardware security keys for key accounts
- Use unique passwords (manager) + TOTP MFA
- Set account recovery codes and store offline
- Review public records and opt-out where possible
- Configure phone carrier account PIN
"@
    $file = "privacy_restoration_checklist_$(Get-Date -Format 'yyyyMMdd').txt"
    $content | Out-File -Encoding UTF8 -FilePath $file
    Write-Host "✅ Checklist exported to $file" -ForegroundColor Green
    return $file
}

function Generate-IdentityReport {
    param([switch]$Export)
    Write-Host "🧾 Compiling Identity Protection Report..." -ForegroundColor Magenta
    $scan = Run-QuickExposureScan
    $report = @{
        Metadata = @{ Generated = (Get-Date); Host = $env:COMPUTERNAME; User=$env:USERNAME }
        Inputs   = @{ Email=$Email; Phone=$Phone; FullName=$FullName }
        Findings = $scan | Select-Object *
        Recommendations = $scan.RecommendedActions
    } | ConvertTo-Json -Depth 5
    $file = "identity_protection_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report | Out-File -Encoding UTF8 -FilePath $file
    Write-Host "✅ Report saved to $file" -ForegroundColor Green
    if ($Export) { $file }
}

# Non-interactive flows
if ($QuickScan) { Run-QuickExposureScan | Out-Null }
if ($Export) { Generate-IdentityReport -Export | Out-Null } else { Show-IdentityMenu } 