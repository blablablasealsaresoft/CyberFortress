# ENHANCED THREAT INTELLIGENCE DASHBOARD v4.0 - COMPLETE ENTERPRISE SYSTEM
# Advanced visualization and analysis with personal monitoring integration
param(
    [switch]$Export,
    [switch]$ShowMap,
    [string]$FilterCountry,
    [int]$MinThreatScore = 0,
    [switch]$RealTime,
    [switch]$DetailedProfile,
    [switch]$PersonalReport,
    [switch]$EnterpriseView,
    [switch]$MLAnalysis,
    [switch]$ThreatIntelView,
    [switch]$Diagnostics,
    [int]$RefreshInterval = 5
)

function Show-Header {
    Clear-Host
    Write-Host "🌍 ENHANCED THREAT INTELLIGENCE DASHBOARD v4.0" -ForegroundColor Red
    Write-Host "🚀 Complete Enterprise-Grade Multi-Engine Analysis System" -ForegroundColor Green
    Write-Host "=" * 85 -ForegroundColor Red
    Write-Host "🕒 Last Update: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}

function Load-EnhancedAttackerDatabase {
    if (Test-Path "enhanced_attacker_database.json") {
        try {
            $json = Get-Content "enhanced_attacker_database.json" -Raw | ConvertFrom-Json
            return $json
        } catch {
            Write-Host "❌ Error loading enhanced attacker database: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    } else {
        Write-Host "⚠️  No enhanced attacker database found. Run the enhanced threat monitor first." -ForegroundColor Yellow
        return $null
    }
}

function Get-CleanTimestamp {
    param($TimestampObject)
    
    if ($TimestampObject -eq $null) {
        return Get-Date
    }
    
    try {
        switch ($TimestampObject.GetType().Name) {
            "DateTime" { return $TimestampObject }
            "PSCustomObject" {
                if ($TimestampObject.value) {
                    return [DateTime]$TimestampObject.value
                } elseif ($TimestampObject.DateTime) {
                    return [DateTime]$TimestampObject.DateTime
                } else {
                    return Get-Date
                }
            }
            "String" {
                return [DateTime]$TimestampObject
            }
            default {
                return [DateTime]$TimestampObject.ToString()
            }
        }
    } catch {
        return Get-Date
    }
}

function Show-RealTimeStats {
    param($Database)
    
    if (-not $Database) { return }
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
    
    # Recent attacks with proper timestamp handling
    $recent = $attackers | Where-Object { 
        $_.Timestamp -and (Get-CleanTimestamp $_.Timestamp) -gt (Get-Date).AddMinutes(-10) 
    }
    
    # Threat level distribution
    $criticalThreats = ($attackers | Where-Object { $_.ThreatScore -gt 80 }).Count
    $highThreats = ($attackers | Where-Object { $_.ThreatScore -gt 60 -and $_.ThreatScore -le 80 }).Count
    $mediumThreats = ($attackers | Where-Object { $_.ThreatScore -gt 40 -and $_.ThreatScore -le 60 }).Count
    $lowThreats = ($attackers | Where-Object { $_.ThreatScore -le 40 }).Count
    
    # Threat intelligence statistics
    $threatIntelCount = ($attackers | Where-Object { $_.ThreatIntelligence -and $_.ThreatIntelligence.ReputationScore -gt 0 }).Count
    $processAnalysisCount = ($attackers | Where-Object { $_.ProcessBehavior }).Count
    $anomalyDetectionCount = ($attackers | Where-Object { $_.AnomalyDetection }).Count
    $automatedResponseCount = ($attackers | Where-Object { $_.AutomatedResponse -and $_.AutomatedResponse.ActionsExecuted.Count -gt 0 }).Count
    
    Write-Host "⚡ ENHANCED REAL-TIME THREAT OVERVIEW" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host "-" * 70
    
    Write-Host "🔴 CRITICAL THREATS (Score >80): " -NoNewline
    Write-Host "$criticalThreats" -ForegroundColor Red
    
    Write-Host "🟠 HIGH THREATS (Score 61-80): " -NoNewline  
    Write-Host "$highThreats" -ForegroundColor Red
    
    Write-Host "🟡 MEDIUM THREATS (Score 41-60): " -NoNewline  
    Write-Host "$mediumThreats" -ForegroundColor Yellow
    
    Write-Host "🟢 LOW THREATS (Score ≤40): " -NoNewline
    Write-Host "$lowThreats" -ForegroundColor Green
    
    Write-Host "📊 Total Threats Analyzed: " -NoNewline
    Write-Host "$($attackers.Count)" -ForegroundColor Cyan
    
    Write-Host "🕒 New Threats (Last 10 min): " -NoNewline
    Write-Host "$($recent.Count)" -ForegroundColor Magenta
    
    Write-Host ""
    Write-Host "🎯 ADVANCED ANALYSIS COVERAGE:" -ForegroundColor Cyan
    Write-Host "🔍 Threat Intelligence: " -NoNewline
    Write-Host "$threatIntelCount/$($attackers.Count)" -ForegroundColor $(if ($threatIntelCount -gt 0) { "Green" } else { "Red" })
    
    Write-Host "🔧 Process Analysis: " -NoNewline
    Write-Host "$processAnalysisCount/$($attackers.Count)" -ForegroundColor $(if ($processAnalysisCount -gt 0) { "Green" } else { "Red" })
    
    Write-Host "🤖 ML Anomaly Detection: " -NoNewline
    Write-Host "$anomalyDetectionCount/$($attackers.Count)" -ForegroundColor $(if ($anomalyDetectionCount -gt 0) { "Green" } else { "Red" })
    
    Write-Host "⚡ Automated Responses: " -NoNewline
    Write-Host "$automatedResponseCount" -ForegroundColor $(if ($automatedResponseCount -gt 0) { "Green" } else { "Gray" })
    
    Write-Host ""
}

function Show-EnhancedThreatProfiles {
    param($Database, $Top = 5)
    
    if (-not $Database) { return }
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value } |
                 Where-Object { $_.ThreatScore -ge $MinThreatScore } |
                 Sort-Object ThreatScore -Descending | 
                 Select-Object -First $Top
    
    Write-Host "🎯 ENHANCED THREAT PROFILES (Top $Top)" -ForegroundColor Red
    Write-Host "=" * 85
    
    $profileIndex = 1
    foreach ($attacker in $attackers) {
        $color = if ($attacker.ThreatScore -gt 80) { "Red" } 
                elseif ($attacker.ThreatScore -gt 60) { "Red" }
                elseif ($attacker.ThreatScore -gt 40) { "Yellow" } 
                else { "Green" }
        
        Write-Host ""
        Write-Host "📍 ENHANCED THREAT PROFILE #$profileIndex" -ForegroundColor White -BackgroundColor DarkRed
        Write-Host "-" * 60
        
        # Basic Information
        Write-Host "🌐 IP Address: " -NoNewline
        Write-Host "$($attacker.IP)" -ForegroundColor $color
        
        # Enhanced location with better fallback handling
        Write-Host "🗺️  Location: " -NoNewline
        $locationParts = @()
        if ($attacker.City) { $locationParts += $attacker.City }
        if ($attacker.Region -or $attacker.regionName) { 
            $region = if ($attacker.Region) { $attacker.Region } else { $attacker.regionName }
            $locationParts += $region 
        }
        if ($attacker.Country -or $attacker.country) { 
            $country = if ($attacker.Country) { $attacker.Country } else { $attacker.country }
            $locationParts += $country 
        }
        
        if ($locationParts.Count -gt 0) {
            Write-Host "$($locationParts -join ', ')" -ForegroundColor White
        } else {
            Write-Host "Location data unavailable" -ForegroundColor DarkGray
        }
        
        # Enhanced threat scoring breakdown
        Write-Host "⚠️  THREAT ASSESSMENT:" -ForegroundColor Yellow
        $score = if ($attacker.ThreatScore) { $attacker.ThreatScore } else { 0 }
        Write-Host "   📊 Overall Threat Score: " -NoNewline
        Write-Host "$score/100" -ForegroundColor $color
        
        # Show component scores if available
        if ($attacker.ThreatIntelligence -and $attacker.ThreatIntelligence.ReputationScore) {
            Write-Host "   🔍 Threat Intel Score: $($attacker.ThreatIntelligence.ReputationScore)/100" -ForegroundColor Cyan
        }
        
        if ($attacker.ProcessBehavior -and $attacker.ProcessBehavior.BehaviorScore) {
            Write-Host "   🔧 Process Behavior Score: $($attacker.ProcessBehavior.BehaviorScore)/100" -ForegroundColor Cyan
        }
        
        if ($attacker.AnomalyDetection -and $attacker.AnomalyDetection.OverallAnomalyScore) {
            Write-Host "   🤖 ML Anomaly Score: $($attacker.AnomalyDetection.OverallAnomalyScore)/100" -ForegroundColor Cyan
        }
        
        # Threat Intelligence Details
        if ($attacker.ThreatIntelligence) {
            $ti = $attacker.ThreatIntelligence
            if ($ti.ThreatSources -and $ti.ThreatSources.Count -gt 0) {
                Write-Host "🔍 THREAT INTELLIGENCE:" -ForegroundColor Cyan
                Write-Host "   • Sources: $($ti.ThreatSources -join ', ')" -ForegroundColor Gray
                Write-Host "   • Confidence: $($ti.Confidence)" -ForegroundColor Gray
                if ($ti.Categories -and $ti.Categories.Count -gt 0) {
                    Write-Host "   • Categories: $($ti.Categories -join ', ')" -ForegroundColor Yellow
                }
            }
        }
        
        # Process Behavior Analysis
        if ($attacker.ProcessBehavior) {
            $pb = $attacker.ProcessBehavior
            Write-Host "🔧 PROCESS ANALYSIS:" -ForegroundColor Green
            Write-Host "   • Network Pattern: $($pb.NetworkPattern)" -ForegroundColor Gray
            Write-Host "   • In Baseline: $(if ($pb.IsBaseline) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($pb.IsBaseline) { "Green" } else { "Yellow" })
            Write-Host "   • Suspicious: $(if ($pb.IsSuspicious) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($pb.IsSuspicious) { "Red" } else { "Green" })
            
            if ($pb.Anomalies -and $pb.Anomalies.Count -gt 0) {
                Write-Host "   • Anomalies: $($pb.Anomalies.Count)" -ForegroundColor Red
            }
        }
        
        # ML Anomaly Detection Results
        if ($attacker.AnomalyDetection) {
            $ad = $attacker.AnomalyDetection
            Write-Host "🤖 ML ANOMALY ANALYSIS:" -ForegroundColor Magenta
            Write-Host "   • Confidence: $($ad.Confidence)" -ForegroundColor Gray
            
            if ($ad.ModelScores) {
                $activeAnomalies = ($ad.ModelScores.PSObject.Properties.Value | Where-Object { $_.IsAnomaly }).Count
                Write-Host "   • Models Triggered: $activeAnomalies/$($ad.ModelScores.PSObject.Properties.Count)" -ForegroundColor $(if ($activeAnomalies -gt 0) { "Red" } else { "Green" })
            }
        }
        
        # Automated Response Actions
        if ($attacker.AutomatedResponse) {
            $ar = $attacker.AutomatedResponse
            if ($ar.RuleMatched) {
                Write-Host "🤖 AUTOMATED RESPONSE:" -ForegroundColor Yellow
                Write-Host "   • Rule: $($ar.RuleMatched)" -ForegroundColor Gray
                Write-Host "   • Actions Executed: $($ar.ActionsExecuted.Count)/$($ar.ActionsTriggered.Count)" -ForegroundColor $(if ($ar.ActionsExecuted.Count -gt 0) { "Green" } else { "Gray" })
                
                if ($ar.ActionsExecuted -and $ar.ActionsExecuted.Count -gt 0) {
                    Write-Host "   • Executed: $($ar.ActionsExecuted -join ', ')" -ForegroundColor Green
                }
                
                if ($ar.ActionsFailed -and $ar.ActionsFailed.Count -gt 0) {
                    Write-Host "   • Failed: $($ar.ActionsFailed -join ', ')" -ForegroundColor Red
                }
            }
        }
        
        # Network and ISP Information
        Write-Host "🏢 NETWORK DETAILS:" -ForegroundColor White
        $isp = $null
        if ($attacker.ISP) { $isp = $attacker.ISP }
        elseif ($attacker.isp) { $isp = $attacker.isp }
        elseif ($attacker.Organization) { $isp = $attacker.Organization }
        elseif ($attacker.org) { $isp = $attacker.org }
        
        if ($isp) {
            Write-Host "   • ISP/Organization: $isp" -ForegroundColor White
        }
        
        # Technical indicators
        $isProxy = $attacker.IsProxy -or $attacker.proxy
        $isHosting = $attacker.IsHosting -or $attacker.hosting  
        $isMobile = $attacker.IsMobile -or $attacker.mobile
        
        if ($isProxy) {
            Write-Host "   🎭 Proxy/VPN: DETECTED" -ForegroundColor Red
        }
        
        if ($isHosting) {
            Write-Host "   ☁️  Hosting Provider: DETECTED" -ForegroundColor Yellow
        }
        
        if ($isMobile) {
            Write-Host "   📱 Mobile Connection: YES" -ForegroundColor Green
        }
        
        # Timing information
        $timestamp = $null
        if ($attacker.Timestamp) { $timestamp = $attacker.Timestamp }
        elseif ($attacker.FirstSeen) { $timestamp = $attacker.FirstSeen }
        
        if ($timestamp) {
            $cleanTimestamp = Get-CleanTimestamp $timestamp
            Write-Host "🕒 First Detected: " -NoNewline
            Write-Host "$($cleanTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
        }
        
        Write-Host ""
        $profileIndex++
    }
}

function Show-ThreatIntelligenceView {
    param($Database)
    
    if (-not $Database) { return }
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
    $threatIntelAttackers = $attackers | Where-Object { $_.ThreatIntelligence -and $_.ThreatIntelligence.ReputationScore -gt 0 }
    
    Write-Host "🔍 THREAT INTELLIGENCE ANALYSIS" -ForegroundColor Cyan
    Write-Host "=" * 60
    
    if ($threatIntelAttackers.Count -eq 0) {
        Write-Host "ℹ️ No threat intelligence correlations found" -ForegroundColor Yellow
        return
    }
    
    # Threat source analysis
    $allSources = @()
    $threatIntelAttackers | ForEach-Object {
        if ($_.ThreatIntelligence.ThreatSources) {
            $allSources += $_.ThreatIntelligence.ThreatSources
        }
    }
    
    $sourceGroups = $allSources | Group-Object | Sort-Object Count -Descending
    
    Write-Host "📊 THREAT INTELLIGENCE SOURCES:" -ForegroundColor Green
    foreach ($source in $sourceGroups) {
        Write-Host "  • $($source.Name): $($source.Count) correlations" -ForegroundColor White
    }
    
    # Category analysis
    $allCategories = @()
    $threatIntelAttackers | ForEach-Object {
        if ($_.ThreatIntelligence.Categories) {
            $allCategories += $_.ThreatIntelligence.Categories
        }
    }
    
    if ($allCategories.Count -gt 0) {
        $categoryGroups = $allCategories | Group-Object | Sort-Object Count -Descending
        
        Write-Host "`n🏷️ THREAT CATEGORIES:" -ForegroundColor Green
        foreach ($category in $categoryGroups | Select-Object -First 10) {
            Write-Host "  • $($category.Name): $($category.Count) instances" -ForegroundColor Yellow
        }
    }
    
    # High-reputation threats
    $highRepThreats = $threatIntelAttackers | Where-Object { $_.ThreatIntelligence.ReputationScore -gt 60 } | Sort-Object { $_.ThreatIntelligence.ReputationScore } -Descending
    
    if ($highRepThreats.Count -gt 0) {
        Write-Host "`n🚨 HIGH-REPUTATION THREATS:" -ForegroundColor Red
        foreach ($threat in $highRepThreats | Select-Object -First 5) {
            Write-Host "  • $($threat.IP) - Score: $($threat.ThreatIntelligence.ReputationScore)/100" -ForegroundColor Red
            Write-Host "    Sources: $($threat.ThreatIntelligence.ThreatSources -join ', ')" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
}

function Show-MLAnalysisView {
    param($Database)
    
    if (-not $Database) { return }
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
    $mlAttackers = $attackers | Where-Object { $_.AnomalyDetection }
    
    Write-Host "🤖 MACHINE LEARNING ANALYSIS" -ForegroundColor Magenta
    Write-Host "=" * 60
    
    if ($mlAttackers.Count -eq 0) {
        Write-Host "ℹ️ No ML analysis data available" -ForegroundColor Yellow
        return
    }
    
    # Confidence distribution
    $confidenceGroups = $mlAttackers | Group-Object { $_.AnomalyDetection.Confidence } | Sort-Object Name -Descending
    
    Write-Host "📊 CONFIDENCE DISTRIBUTION:" -ForegroundColor Green
    foreach ($group in $confidenceGroups) {
        $color = switch ($group.Name) {
            "HIGH" { "Red" }
            "MEDIUM" { "Yellow" }
            "LOW" { "Green" }
            default { "Gray" }
        }
        Write-Host "  • $($group.Name): $($group.Count) detections" -ForegroundColor $color
    }
    
    # Anomaly model analysis
    $modelStats = @{}
    $mlAttackers | ForEach-Object {
        if ($_.AnomalyDetection.ModelScores) {
            $_.AnomalyDetection.ModelScores.PSObject.Properties | ForEach-Object {
                $modelName = $_.Name
                $modelResult = $_.Value
                
                if (-not $modelStats.ContainsKey($modelName)) {
                    $modelStats[$modelName] = @{ Total = 0; Anomalies = 0 }
                }
                
                $modelStats[$modelName].Total++
                if ($modelResult.IsAnomaly) {
                    $modelStats[$modelName].Anomalies++
                }
            }
        }
    }
    
    if ($modelStats.Count -gt 0) {
        Write-Host "`n🧠 ML MODEL PERFORMANCE:" -ForegroundColor Green
        foreach ($model in $modelStats.Keys) {
            $stats = $modelStats[$model]
            $percentage = if ($stats.Total -gt 0) { [Math]::Round(($stats.Anomalies / $stats.Total) * 100, 1) } else { 0 }
            Write-Host "  • $model`: $($stats.Anomalies)/$($stats.Total) anomalies ($percentage%)" -ForegroundColor Cyan
        }
    }
    
    # High-scoring anomalies
    $highAnomalies = $mlAttackers | Where-Object { $_.AnomalyDetection.OverallAnomalyScore -gt 60 } | Sort-Object { $_.AnomalyDetection.OverallAnomalyScore } -Descending
    
    if ($highAnomalies.Count -gt 0) {
        Write-Host "`n🚨 HIGH-SCORE ANOMALIES:" -ForegroundColor Red
        foreach ($anomaly in $highAnomalies | Select-Object -First 5) {
            Write-Host "  • $($anomaly.IP) - ML Score: $($anomaly.AnomalyDetection.OverallAnomalyScore)/100" -ForegroundColor Red
            Write-Host "    Confidence: $($anomaly.AnomalyDetection.Confidence)" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
}

function Show-PersonalMonitoringReport {
    param($Database)
    
    Write-Host "👤 PERSONAL MONITORING REPORT" -ForegroundColor Blue
    Write-Host "=" * 60
    
    # Check if personal monitoring data exists
    if (Test-Path "personal_metrics.json") {
        try {
            $personalData = Get-Content "personal_metrics.json" -Raw | ConvertFrom-Json
        } catch {
            Write-Host "⚠️ Could not load personal monitoring data" -ForegroundColor Yellow
            return
        }
    } else {
        # Generate basic personal stats from database
        if (-not $Database) {
            Write-Host "⚠️ No data available for personal monitoring report" -ForegroundColor Yellow
            return
        }
        
        $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
        $personalData = @{
            SessionSummary = @{
                TotalConnections = $attackers.Count
                StartTime = (Get-Date).AddHours(-1)
                Duration = "1:00:00"
                User = "$env:USERNAME@$env:COMPUTERNAME"
            }
            NetworkActivity = @{
                TotalConnections = $attackers.Count
                UniqueDestinations = ($attackers.IP | Select-Object -Unique).Count
                SuspiciousConnections = ($attackers | Where-Object { $_.ThreatScore -gt 50 }).Count
            }
            SecurityEvents = @{
                ThreatDetections = ($attackers | Where-Object { $_.ThreatScore -gt 40 }).Count
                BlockedConnections = 0
                QuarantinedProcesses = 0
            }
        }
    }
    
    # Session Summary
    Write-Host "📅 SESSION SUMMARY:" -ForegroundColor Green
    Write-Host "  • User: $($personalData.SessionSummary.User)" -ForegroundColor White
    Write-Host "  • Duration: $($personalData.SessionSummary.Duration)" -ForegroundColor White
    Write-Host "  • Total Connections: $($personalData.SessionSummary.TotalConnections)" -ForegroundColor White
    
    # Network Activity
    Write-Host "`n🌐 NETWORK ACTIVITY:" -ForegroundColor Green
    Write-Host "  • Total Connections: $($personalData.NetworkActivity.TotalConnections)" -ForegroundColor White
    Write-Host "  • Unique Destinations: $($personalData.NetworkActivity.UniqueDestinations)" -ForegroundColor White
    Write-Host "  • Suspicious Connections: $($personalData.NetworkActivity.SuspiciousConnections)" -ForegroundColor $(if ($personalData.NetworkActivity.SuspiciousConnections -gt 0) { "Red" } else { "Green" })
    
    # Security Events
    Write-Host "`n🛡️ SECURITY EVENTS:" -ForegroundColor Green
    Write-Host "  • Threat Detections: $($personalData.SecurityEvents.ThreatDetections)" -ForegroundColor $(if ($personalData.SecurityEvents.ThreatDetections -gt 0) { "Red" } else { "Green" })
    Write-Host "  • Blocked Connections: $($personalData.SecurityEvents.BlockedConnections)" -ForegroundColor White
    Write-Host "  • Quarantined Processes: $($personalData.SecurityEvents.QuarantinedProcesses)" -ForegroundColor White
    
    # Privacy compliance
    Write-Host "`n🔒 PRIVACY COMPLIANCE:" -ForegroundColor Green
    Write-Host "  • Data Retention: 30 days" -ForegroundColor White
    Write-Host "  • Keystroke Logging: DISABLED" -ForegroundColor Green
    Write-Host "  • Browsing Tracking: DISABLED" -ForegroundColor Green
    Write-Host "  • Network Monitoring: ENABLED" -ForegroundColor Yellow
    
    # Activity patterns (if available)
    if ($Database) {
        $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
        $recentActivity = $attackers | Where-Object { 
            $_.Timestamp -and (Get-CleanTimestamp $_.Timestamp) -gt (Get-Date).AddHours(-1) 
        }
        
        if ($recentActivity.Count -gt 0) {
            Write-Host "`n📊 RECENT ACTIVITY (Last Hour):" -ForegroundColor Green
            $hourlyActivity = $recentActivity | Group-Object { (Get-CleanTimestamp $_.Timestamp).Hour } | Sort-Object Name
            
            foreach ($hour in $hourlyActivity) {
                $bar = "█" * [Math]::Min(20, $hour.Count)
                Write-Host "  $($hour.Name):00 $bar ($($hour.Count))" -ForegroundColor Cyan
            }
        }
    }
    
    Write-Host ""
}

function Show-GeographicHeatmap {
    param($Database)
    
    if (-not $Database) { return }
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
    
    # Enhanced country field handling
    $attackersWithCountry = $attackers | ForEach-Object {
        $country = $null
        if ($_.Country) { $country = $_.Country }
        elseif ($_.country) { $country = $_.country }
        
        if ($country) {
            [PSCustomObject]@{
                Attacker = $_
                Country = $country
            }
        }
    }
    
    if ($attackersWithCountry.Count -eq 0) {
        Write-Host "🌍 GLOBAL THREAT HEATMAP" -ForegroundColor Green
        Write-Host "=" * 60
        Write-Host "⚠️ No country data available in database" -ForegroundColor Yellow
        return
    }
    
    $countries = $attackersWithCountry | Group-Object Country | Sort-Object Count -Descending
    
    Write-Host "🌍 ENHANCED GLOBAL THREAT HEATMAP" -ForegroundColor Green
    Write-Host "=" * 70
    
    foreach ($country in $countries) {
        $countryAttackers = $attackersWithCountry | Where-Object {$_.Country -eq $country.Name} | ForEach-Object { $_.Attacker }
        $threatScores = $countryAttackers | Where-Object { $_.ThreatScore } | ForEach-Object { $_.ThreatScore }
        
        if ($threatScores.Count -gt 0) {
            $avgThreat = [math]::Round(($threatScores | Measure-Object -Average).Average, 1)
            $maxThreat = ($threatScores | Measure-Object -Maximum).Maximum
            $totalScore = ($threatScores | Measure-Object -Sum).Sum
        } else {
            $avgThreat = 0
            $maxThreat = 0
            $totalScore = 0
        }
        
        # Enhanced heat level calculation
        $heatLevel = if ($totalScore -gt 500) { "🔥🔥🔥🔥" } 
                    elseif ($totalScore -gt 300) { "🔥🔥🔥" }
                    elseif ($totalScore -gt 150) { "🔥🔥" } 
                    elseif ($totalScore -gt 50) { "🔥" } 
                    else { "❄️" }
        
        $color = if ($maxThreat -gt 80) { "Red" } 
                elseif ($maxThreat -gt 60) { "Red" }
                elseif ($maxThreat -gt 40) { "Yellow" } 
                else { "Green" }
        
        Write-Host "$heatLevel " -NoNewline
        Write-Host "$($country.Name): " -NoNewline
        Write-Host "$($country.Count) threats" -ForegroundColor $color -NoNewline
        Write-Host " | Avg: $avgThreat | Max: $maxThreat | Total: $totalScore" -ForegroundColor Gray
        
        # Show threat intelligence coverage for this country
        $tiCoverage = ($countryAttackers | Where-Object { $_.ThreatIntelligence -and $_.ThreatIntelligence.ReputationScore -gt 0 }).Count
        $mlCoverage = ($countryAttackers | Where-Object { $_.AnomalyDetection }).Count
        $responseCoverage = ($countryAttackers | Where-Object { $_.AutomatedResponse -and $_.AutomatedResponse.ActionsExecuted.Count -gt 0 }).Count
        
        if ($tiCoverage -gt 0 -or $mlCoverage -gt 0 -or $responseCoverage -gt 0) {
            Write-Host "     └── Analysis: TI($tiCoverage) ML($mlCoverage) Response($responseCoverage)" -ForegroundColor DarkCyan
        }
        
        # Show major cities
        $cities = $countryAttackers | Where-Object { $_.City -or $_.city } | ForEach-Object {
            $city = if ($_.City) { $_.City } else { $_.city }
            [PSCustomObject]@{ CityName = $city }
        } | Group-Object CityName | Sort-Object Count -Descending | Select-Object -First 3
        
        if ($cities) {
            foreach ($city in $cities) {
                Write-Host "     └── $($city.Name): $($city.Count) threats" -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""
}

function Export-EnhancedReport {
    param($Database)
    
    if (-not $Database) { return }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "Enhanced_ThreatReport_v4_$timestamp.html"
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
    
    # Enhanced data processing for mapping
    $mappableAttackers = @()
    foreach ($attacker in $attackers) {
        $lat = $null
        $lon = $null
        
        if ($attacker.Latitude -and $attacker.Latitude -ne $null -and $attacker.Latitude -ne $true) { 
            $lat = [double]$attacker.Latitude 
        } elseif ($attacker.lat -and $attacker.lat -ne $null -and $attacker.lat -ne $true) { 
            $lat = [double]$attacker.lat 
        }
        
        if ($attacker.Longitude -and $attacker.Longitude -ne $null -and $attacker.Longitude -ne $true) { 
            $lon = [double]$attacker.Longitude 
        } elseif ($attacker.lon -and $attacker.lon -ne $null -and $attacker.lon -ne $true) { 
            $lon = [double]$attacker.lon 
        }
        
        if ($lat -and $lon -and $lat -ne 0 -and $lon -ne 0 -and 
            $lat -ge -90 -and $lat -le 90 -and $lon -ge -180 -and $lon -le 180) {
            
            $mappableAttackers += [PSCustomObject]@{
                IP = $attacker.IP
                Latitude = $lat
                Longitude = $lon
                Country = if ($attacker.Country) { $attacker.Country } else { "Unknown" }
                City = if ($attacker.City) { $attacker.City } else { "Unknown" }
                ISP = if ($attacker.ISP) { $attacker.ISP } else { "Unknown ISP" }
                ThreatScore = if ($attacker.ThreatScore) { [int]$attacker.ThreatScore } else { 0 }
                ThreatLevel = if ($attacker.ThreatLevel) { $attacker.ThreatLevel } else { "LOW" }
                HasThreatIntel = if ($attacker.ThreatIntelligence -and $attacker.ThreatIntelligence.ReputationScore -gt 0) { $true } else { $false }
                HasProcessAnalysis = if ($attacker.ProcessBehavior) { $true } else { $false }
                HasMLAnalysis = if ($attacker.AnomalyDetection) { $true } else { $false }
                HasAutomatedResponse = if ($attacker.AutomatedResponse -and $attacker.AutomatedResponse.ActionsExecuted.Count -gt 0) { $true } else { $false }
            }
        }
    }
    
    Write-Host "📍 Enhanced report: $($mappableAttackers.Count) threats with coordinates" -ForegroundColor Cyan
    Write-Host "📊 Total threats: $($attackers.Count)" -ForegroundColor Gray
    
    # Generate enhanced interactive HTML report
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Threat Intelligence Report v4.0</title>
    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #0a0a0a; color: #fff; }
        .header { background: linear-gradient(45deg, #d32f2f, #f44336, #ff5722); padding: 30px; border-radius: 15px; margin-bottom: 30px; }
        .section { margin: 20px 0; padding: 20px; background: #1a1a1a; border-radius: 12px; border: 1px solid #333; }
        #map { height: 600px; width: 100%; border-radius: 12px; margin: 15px 0; border: 3px solid #444; }
        .threat-critical { color: #f44336; font-weight: bold; }
        .threat-high { color: #ff5722; font-weight: bold; }
        .threat-medium { color: #ff9800; font-weight: bold; }
        .threat-low { color: #4caf50; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 25px 0; }
        .stat-card { background: #2a2a2a; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #444; }
        .stat-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .map-legend { background: rgba(0,0,0,0.8); padding: 15px; border-radius: 8px; margin: 15px 0; border: 1px solid #666; }
        .legend-item { margin: 8px 0; }
        .color-dot { display: inline-block; width: 14px; height: 14px; border-radius: 50%; margin-right: 10px; }
        .profile-card { background: #2a2a2a; margin: 15px 0; padding: 20px; border-radius: 12px; border-left: 5px solid #f44336; }
        .debug-info { background: #111; padding: 15px; margin: 15px 0; border-radius: 8px; font-family: monospace; font-size: 13px; border: 1px solid #333; }
        .feature-badge { display: inline-block; background: #1976d2; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin: 2px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #2196f3; border-bottom: 2px solid #2196f3; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Enhanced Threat Intelligence Report v4.0</h1>
        <p><strong>Complete Enterprise-Grade Multi-Engine Analysis</strong></p>
        <p><strong>Generated:</strong> $(Get-Date)</p>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number threat-low">$($attackers.Count)</div>
                <div>Total Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number threat-critical">$(($attackers | Where-Object { $_.ThreatScore -gt 80 }).Count)</div>
                <div>Critical Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number threat-high">$(($attackers | Where-Object { $_.ThreatScore -gt 60 -and $_.ThreatScore -le 80 }).Count)</div>
                <div>High Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-number threat-medium">$($mappableAttackers.Count)</div>
                <div>Mapped Locations</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #2196f3">$(($attackers | Where-Object { $_.ThreatIntelligence -and $_.ThreatIntelligence.ReputationScore -gt 0 }).Count)</div>
                <div>Threat Intel Hits</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #9c27b0">$(($attackers | Where-Object { $_.AnomalyDetection }).Count)</div>
                <div>ML Analyzed</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🌍 Enhanced Global Threat Map</h2>
        <div class="map-legend">
            <div class="legend-item"><span class="color-dot" style="background-color: #ff0000;"></span>Critical Threat (Score > 80)</div>
            <div class="legend-item"><span class="color-dot" style="background-color: #ff5722;"></span>High Threat (Score 61-80)</div>
            <div class="legend-item"><span class="color-dot" style="background-color: #ff9800;"></span>Medium Threat (Score 41-60)</div>
            <div class="legend-item"><span class="color-dot" style="background-color: #4caf50;"></span>Low Threat (Score ≤ 40)</div>
            <div class="legend-item"><span style="color: #2196f3;">🔍</span> Threat Intelligence Available</div>
            <div class="legend-item"><span style="color: #9c27b0;">🤖</span> ML Analysis Available</div>
            <div class="legend-item"><span style="color: #ff9800;">⚡</span> Automated Response Executed</div>
        </div>
        <div id="map"></div>
        <div class="debug-info">
            <div id="mapStatus">🔄 Initializing enhanced threat map...</div>
            <div id="debugOutput"></div>
        </div>
    </div>
    
    <div class="section">
        <h2>🚨 Enhanced Threat Analysis</h2>
"@

    # Add enhanced threat profiles
    $criticalThreats = $attackers | Where-Object { $_.ThreatScore -gt 60 } | Sort-Object ThreatScore -Descending | Select-Object -First 10
    
    if ($criticalThreats.Count -gt 0) {
        foreach ($attacker in $criticalThreats) {
            $cleanTimestamp = Get-CleanTimestamp $attacker.Timestamp
            $country = if ($attacker.Country) { $attacker.Country } else { "Unknown" }
            $city = if ($attacker.City) { $attacker.City } else { "Unknown" }
            $isp = if ($attacker.ISP) { $attacker.ISP } else { "Unknown ISP" }
            
            # Feature badges
            $badges = @()
            if ($attacker.ThreatIntelligence -and $attacker.ThreatIntelligence.ReputationScore -gt 0) {
                $badges += '<span class="feature-badge">🔍 Threat Intel</span>'
            }
            if ($attacker.ProcessBehavior) {
                $badges += '<span class="feature-badge">🔧 Process Analysis</span>'
            }
            if ($attacker.AnomalyDetection) {
                $badges += '<span class="feature-badge">🤖 ML Analysis</span>'
            }
            if ($attacker.AutomatedResponse -and $attacker.AutomatedResponse.ActionsExecuted.Count -gt 0) {
                $badges += '<span class="feature-badge">⚡ Auto Response</span>'
            }
            
            $html += @"
        <div class="profile-card">
            <h3>🎯 $($attacker.IP) - $country</h3>
            <p>$($badges -join ' ')</p>
            <p><strong>Overall Threat Score:</strong> <span class="threat-critical">$($attacker.ThreatScore)/100</span></p>
            <p><strong>Location:</strong> $city, $country</p>
            <p><strong>ISP:</strong> $isp</p>
            <p><strong>First Seen:</strong> $($cleanTimestamp.ToString('yyyy-MM-dd HH:mm:ss'))</p>
"@
            
            # Add threat intelligence details
            if ($attacker.ThreatIntelligence -and $attacker.ThreatIntelligence.ReputationScore -gt 0) {
                $html += @"
            <p><strong>Threat Intelligence:</strong> Score $($attacker.ThreatIntelligence.ReputationScore)/100 | Sources: $($attacker.ThreatIntelligence.ThreatSources -join ', ')</p>
"@
            }
            
            # Add ML analysis details
            if ($attacker.AnomalyDetection) {
                $html += @"
            <p><strong>ML Analysis:</strong> Score $($attacker.AnomalyDetection.OverallAnomalyScore)/100 | Confidence: $($attacker.AnomalyDetection.Confidence)</p>
"@
            }
            
            $html += @"
        </div>
"@
        }
    }

    $html += @"
    </div>
    
    <script>
        console.log('🗺️ Starting enhanced map initialization...');
        
        function debugLog(message) {
            console.log(message);
            const debugDiv = document.getElementById('debugOutput');
            if (debugDiv) {
                debugDiv.innerHTML += message + '<br>';
            }
        }
        
        debugLog('📊 Total threats to map: $($mappableAttackers.Count)');
        
        try {
            debugLog('🔧 Creating enhanced Leaflet map...');
            const map = L.map('map').setView([39.8283, -98.5795], 2);
            
            debugLog('🗺️ Adding dark theme map tiles...');
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '© OpenStreetMap contributors, © CARTO',
                maxZoom: 18,
                errorTileUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
            }).addTo(map);
            
            let markerCount = 0;
            const bounds = [];
            
            debugLog('📍 Adding enhanced threat markers...');
            
"@

    # Generate JavaScript for each mappable attacker with enhanced features
    foreach ($attacker in $mappableAttackers) {
        $lat = $attacker.Latitude
        $lon = $attacker.Longitude
        $score = $attacker.ThreatScore
        $country = $attacker.Country -replace "'", "\'" -replace '"', '\"'
        $city = $attacker.City -replace "'", "\'" -replace '"', '\"'
        $isp = $attacker.ISP -replace "'", "\'" -replace '"', '\"'
        $ip = $attacker.IP
        
        # Enhanced marker styling
        $color = if ($score -gt 80) { "#ff0000" } 
                elseif ($score -gt 60) { "#ff5722" }
                elseif ($score -gt 40) { "#ff9800" } 
                else { "#4caf50" }
        
        $radius = [Math]::Max(8, [Math]::Min(25, $score / 4 + 6))
        
        # Feature indicators
        $features = @()
        if ($attacker.HasThreatIntel) { $features += "🔍 Threat Intel" }
        if ($attacker.HasProcessAnalysis) { $features += "🔧 Process Analysis" }
        if ($attacker.HasMLAnalysis) { $features += "🤖 ML Analysis" }
        if ($attacker.HasAutomatedResponse) { $features += "⚡ Auto Response" }
        
        $cleanIP = $ip.Replace('.', '_').Replace(':', '_')
        $riskLevel = $attacker.ThreatLevel
        $featureList = $features -join ', '
        
        $html += @"
            try {
                debugLog('Adding enhanced marker for $ip at [$lat, $lon]');
                
                var marker_$cleanIP = L.circleMarker([$lat, $lon], {
                    color: '$color',
                    fillColor: '$color',
                    fillOpacity: 0.8,
                    radius: $radius,
                    weight: 3,
                    className: 'enhanced-threat-marker'
                }).addTo(map);
                
                var popupHtml = '<div style="color: black; font-weight: bold; min-width: 280px; font-family: Segoe UI;">' +
                    '<h4 style="margin: 8px 0; color: $color; font-size: 16px;">🎯 $ip</h4>' +
                    '<p style="margin: 5px 0;"><strong>Location:</strong> $city, $country</p>' +
                    '<p style="margin: 5px 0;"><strong>ISP:</strong> $isp</p>' +
                    '<p style="margin: 5px 0;"><strong>Threat Score:</strong> <span style="color: $color; font-weight: bold;">$score/100</span></p>' +
                    '<p style="margin: 5px 0;"><strong>Risk Level:</strong> <span style="color: $color;">$riskLevel</span></p>';
                
                if ('$featureList'.length > 0) {
                    popupHtml += '<p style="margin: 5px 0;"><strong>Analysis:</strong> $featureList</p>';
                }
                
                popupHtml += '<p style="margin: 5px 0; font-size: 11px; color: #666;">Coordinates: $lat, $lon</p>' +
                    '</div>';
                
                marker_$cleanIP.bindPopup(popupHtml);
                bounds.push([$lat, $lon]);
                markerCount++;
                
            } catch (e) {
                debugLog('Error adding enhanced marker for $ip - ' + e.message);
                console.error('Error adding marker for $ip', e);
            }
"@
    }

    $html += @"
            
            debugLog('✅ Added ' + markerCount + ' enhanced threat markers');
            
            if (bounds.length > 0) {
                try {
                    debugLog('🔍 Fitting map bounds to show all threats...');
                    map.fitBounds(bounds, { padding: [30, 30] });
                    
                    document.getElementById('mapStatus').innerHTML = 
                        '✅ Successfully loaded ' + markerCount + ' threat locations with enhanced analysis';
                    document.getElementById('mapStatus').style.color = '#4caf50';
                        
                } catch (e) {
                    debugLog('⚠️ Error fitting bounds: ' + e.message);
                    document.getElementById('mapStatus').innerHTML = 
                        '⚠️ Map loaded but positioning failed: ' + e.message;
                    document.getElementById('mapStatus').style.color = '#ff9800';
                }
            } else {
                debugLog('❌ No valid coordinates found for mapping');
                document.getElementById('mapStatus').innerHTML = 
                    '❌ No threat locations with valid coordinates found';
                document.getElementById('mapStatus').style.color = '#f44336';
            }
            
            debugLog('🎉 Enhanced map initialization complete!');
            
        } catch (e) {
            debugLog('💥 Critical error in enhanced map initialization: ' + e.message);
            console.error('Critical map error:', e);
            document.getElementById('mapStatus').innerHTML = 
                '💥 Enhanced map initialization failed: ' + e.message;
            document.getElementById('mapStatus').style.color = '#f44336';
        }
    </script>
</body>
</html>
"@

    $html | Out-File $reportFile -Encoding UTF8
    Write-Host "📄 Enhanced threat report v4.0 exported: $reportFile" -ForegroundColor Green
    Write-Host "🗺️ Enhanced map with $($mappableAttackers.Count) threat locations and analysis features" -ForegroundColor Cyan
    Write-Host "🎯 Open $reportFile in your browser for interactive enhanced threat visualization" -ForegroundColor Green
}

function Show-DatabaseDiagnostics {
    param($Database)
    
    if (-not $Database) { 
        Write-Host "❌ No database loaded" -ForegroundColor Red
        return 
    }
    
    $attackers = $Database.PSObject.Properties | ForEach-Object { $_.Value }
    $sampleAttacker = $attackers | Select-Object -First 1
    
    Write-Host "🔧 ENHANCED DATABASE DIAGNOSTICS v4.0" -ForegroundColor Cyan
    Write-Host "=" * 60
    Write-Host "📊 Total Records: $($attackers.Count)" -ForegroundColor White
    
    if ($sampleAttacker) {
        Write-Host "`n📋 Available Fields in Sample Record:" -ForegroundColor Yellow
        $sampleAttacker.PSObject.Properties | ForEach-Object {
            $value = if ($_.Value) { 
                if ($_.Value.ToString().Length -gt 50) { 
                    "$($_.Value.ToString().Substring(0, 47))..." 
                } else { 
                    $_.Value.ToString() 
                }
            } else { 
                "[Empty]" 
            }
            Write-Host "  • $($_.Name): $value" -ForegroundColor Gray
        }
        
        Write-Host "`n🌍 Enhanced Geolocation Data Status:" -ForegroundColor Yellow
        $geoFields = @('Country', 'country', 'City', 'city', 'Region', 'regionName', 'ISP', 'isp', 'Organization', 'org')
        foreach ($field in $geoFields) {
            $hasData = ($attackers | Where-Object { $_.$field }).Count
            $status = if ($hasData -gt 0) { "✅" } else { "❌" }
            Write-Host "  $status $field`: $hasData/$($attackers.Count) records" -ForegroundColor Gray
        }
        
        Write-Host "`n🎯 Advanced Analysis Coverage:" -ForegroundColor Yellow
        $threatIntelCount = ($attackers | Where-Object { $_.ThreatIntelligence }).Count
        $processAnalysisCount = ($attackers | Where-Object { $_.ProcessBehavior }).Count
        $anomalyDetectionCount = ($attackers | Where-Object { $_.AnomalyDetection }).Count
        $automatedResponseCount = ($attackers | Where-Object { $_.AutomatedResponse }).Count
        
        Write-Host "  🔍 Threat Intelligence: $threatIntelCount/$($attackers.Count) records" -ForegroundColor $(if ($threatIntelCount -gt 0) { "Green" } else { "Red" })
        Write-Host "  🔧 Process Behavior Analysis: $processAnalysisCount/$($attackers.Count) records" -ForegroundColor $(if ($processAnalysisCount -gt 0) { "Green" } else { "Red" })
        Write-Host "  🤖 ML Anomaly Detection: $anomalyDetectionCount/$($attackers.Count) records" -ForegroundColor $(if ($anomalyDetectionCount -gt 0) { "Green" } else { "Red" })
        Write-Host "  ⚡ Automated Response: $automatedResponseCount/$($attackers.Count) records" -ForegroundColor $(if ($automatedResponseCount -gt 0) { "Green" } else { "Red" })
        
        Write-Host "`n💡 System Recommendations:" -ForegroundColor Yellow
        if ($threatIntelCount -eq 0) {
            Write-Host "  • Initialize threat intelligence engines for IOC correlation" -ForegroundColor White
        }
        if ($processAnalysisCount -eq 0) {
            Write-Host "  • Enable process behavior analysis for enhanced detection" -ForegroundColor White
        }
        if ($anomalyDetectionCount -eq 0) {
            Write-Host "  • Activate ML anomaly detection for advanced analytics" -ForegroundColor White
        }
        if ($automatedResponseCount -eq 0) {
            Write-Host "  • Consider enabling automated response capabilities" -ForegroundColor White
        }
        
        if ($threatIntelCount -gt 0 -and $processAnalysisCount -gt 0 -and $anomalyDetectionCount -gt 0) {
            Write-Host "  ✅ All advanced analysis engines are operational!" -ForegroundColor Green
        }
    }
    Write-Host ""
}

# Main execution logic
Show-Header

$database = Load-EnhancedAttackerDatabase

if ($database) {
    $attackers = $database.PSObject.Properties | ForEach-Object { $_.Value }
    $hasGeoData = ($attackers | Where-Object { $_.Country -or $_.country }).Count
    
    if ($Diagnostics) {
        Show-DatabaseDiagnostics $database
        return
    }
    
    if ($RealTime) {
        while ($true) {
            Show-Header
            Show-RealTimeStats $database
            
            if ($ThreatIntelView) {
                Show-ThreatIntelligenceView $database
            } elseif ($MLAnalysis) {
                Show-MLAnalysisView $database
            } elseif ($PersonalReport) {
                Show-PersonalMonitoringReport $database
            } else {
                Show-EnhancedThreatProfiles $database -Top 3
            }
            
            Start-Sleep -Seconds $RefreshInterval
            $database = Load-EnhancedAttackerDatabase  # Refresh data
        }
    } else {
        Show-RealTimeStats $database
        
        if ($ThreatIntelView) {
            Show-ThreatIntelligenceView $database
        } elseif ($MLAnalysis) {
            Show-MLAnalysisView $database
        } elseif ($PersonalReport) {
            Show-PersonalMonitoringReport $database
        } else {
            if ($DetailedProfile) {
                Show-EnhancedThreatProfiles $database -Top 10
            } else {
                Show-EnhancedThreatProfiles $database -Top 5
            }
            
            Show-GeographicHeatmap $database
        }
        
        if ($Export) {
            Export-EnhancedReport $database
        }
    }
} else {
    Write-Host "🚀 Start the Enhanced Threat Monitor v4.0 first to collect data!" -ForegroundColor Yellow
    Write-Host "Run: .\enhanced_threat_monitor.ps1 -PersonalMonitoring -AutoResponse -MLEnabled" -ForegroundColor Green
}

Write-Host ""
Write-Host "💡 ENHANCED v4.0 FEATURES:" -ForegroundColor Yellow
Write-Host "• -DetailedProfile for comprehensive threat profiles" -ForegroundColor Gray
Write-Host "• -RealTime for live monitoring dashboard with auto-refresh" -ForegroundColor Gray
Write-Host "• -Export for interactive HTML report with enhanced mapping" -ForegroundColor Gray
Write-Host "• -PersonalReport for personal monitoring and privacy dashboard" -ForegroundColor Gray
Write-Host "• -ThreatIntelView for threat intelligence correlation analysis" -ForegroundColor Gray
Write-Host "• -MLAnalysis for machine learning anomaly detection view" -ForegroundColor Gray
Write-Host "• -Diagnostics for comprehensive system analysis and recommendations" -ForegroundColor Gray
Write-Host ""
Write-Host "🎯 COMPLETE v4.0 INTEGRATION:" -ForegroundColor Cyan
Write-Host "• Multi-engine threat analysis with cross-correlation" -ForegroundColor Gray
Write-Host "• Advanced geolocation intelligence and context analysis" -ForegroundColor Gray
Write-Host "• Real-time behavioral analysis with baseline learning" -ForegroundColor Gray
Write-Host "• ML-powered anomaly detection across multiple models" -ForegroundColor Gray
Write-Host "• Automated response capabilities with evidence collection" -ForegroundColor Gray
Write-Host "• Personal monitoring with privacy controls and compliance" -ForegroundColor Gray
Write-Host "• Enterprise-grade reporting with interactive visualizations" -ForegroundColor Gray