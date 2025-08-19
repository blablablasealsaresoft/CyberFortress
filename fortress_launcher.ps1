function Prompt-Continue { [void](Read-Host "Press Enter to continue...") }

function Show-MasterMenu {
	Clear-Host
	Write-Host "🛡️ CyberFortress Pro - Master Launcher" -ForegroundColor Cyan
	Write-Host "=" * 60 -ForegroundColor Cyan
	Write-Host "1. Start Enhanced Monitor (Standard)" -ForegroundColor Green
	Write-Host "2. Start Enhanced Monitor (Enterprise)" -ForegroundColor Yellow
	Write-Host "3. Open Threat Dashboard" -ForegroundColor Green
	Write-Host "4. Identity Protection Suite" -ForegroundColor Cyan
	Write-Host "5. OSINT Investigator Suite" -ForegroundColor Cyan
	Write-Host "6. Quantum Crypto Suite" -ForegroundColor Magenta
	Write-Host "7. Exit" -ForegroundColor Gray
	$choice = Read-Host "Select option (1-7)"
	switch ($choice) {
		"1" {
			if (Test-Path "enhanced_threat_monitor.ps1") { .\enhanced_threat_monitor.ps1 -ScanInterval 10 }
			else { Write-Host "enhanced_threat_monitor.ps1 not found" -ForegroundColor Red }
			Prompt-Continue; Show-MasterMenu
		}
		"2" {
			if (Test-Path "enhanced_threat_monitor.ps1") { .\enhanced_threat_monitor.ps1 -EnterpriseMode -DeepScan -AutoResponse -MLEnabled }
			else { Write-Host "enhanced_threat_monitor.ps1 not found" -ForegroundColor Red }
			Prompt-Continue; Show-MasterMenu
		}
		"3" {
			if (Test-Path "enhanced_threat_dashboard.ps1") { .\enhanced_threat_dashboard.ps1 -RealTime }
			else { Write-Host "enhanced_threat_dashboard.ps1 not found" -ForegroundColor Red }
			Prompt-Continue; Show-MasterMenu
		}
		"4" {
			if (Test-Path "identity_protection.ps1") { .\identity_protection.ps1 }
			else { Write-Host "identity_protection.ps1 not found" -ForegroundColor Red }
			Prompt-Continue; Show-MasterMenu
		}
		"5" {
			if (Test-Path "osint_investigator.ps1") { .\osint_investigator.ps1 }
			else { Write-Host "osint_investigator.ps1 not found" -ForegroundColor Red }
			Prompt-Continue; Show-MasterMenu
		}
		"6" {
			if (Test-Path "quantum_crypto.ps1") { .\quantum_crypto.ps1 }
			else { Write-Host "quantum_crypto.ps1 not found" -ForegroundColor Red }
			Prompt-Continue; Show-MasterMenu
		}
		"7" { return }
		default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep 1; Show-MasterMenu }
	}
}

Show-MasterMenu 