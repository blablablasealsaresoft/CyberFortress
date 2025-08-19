param(
	[switch]$QuickReport,
	[string]$TargetIP,
	[string]$Email,
	[string]$Username
)

function Show-OSINTMenu {
	Clear-Host
	Write-Host "🕵️ CyberInvestigator OSINT Suite (Offline Mode)" -ForegroundColor Cyan
	Write-Host "=" * 60 -ForegroundColor Cyan
	Write-Host "1. Build Offline Case File" -ForegroundColor Green
	Write-Host "2. Generate Link Analysis (synthetic)" -ForegroundColor Yellow
	Write-Host "3. Export Case Bundle" -ForegroundColor Magenta
	Write-Host "4. Exit" -ForegroundColor Gray

	$choice = Read-Host "Select option (1-4)"
	switch ($choice) {
		"1" { Build-CaseFile; Prompt-Continue; Show-OSINTMenu }
		"2" { Export-LinkAnalysis; Prompt-Continue; Show-OSINTMenu }
		"3" { Export-CaseBundle; Prompt-Continue; Show-OSINTMenu }
		"4" { return }
		default { Write-Host "Invalid option" -ForegroundColor Red; Start-Sleep 1; Show-OSINTMenu }
	}
}

function Prompt-Continue { [void](Read-Host "Press Enter to continue...") }

function Build-CaseFile {
	Write-Host "📁 Building case file (offline synthesis)..." -ForegroundColor Green
	$meta = [PSCustomObject]@{
		CaseId = (New-Guid).Guid
		Created = Get-Date
		Inputs = @{ IP=$TargetIP; Email=$Email; Username=$Username }
		ChainOfCustody = @(@{ Timestamp=(Get-Date); Action='Created'; By=$env:USERNAME })
	}
	$artifacts = @(
		@{ Type='AttributionHypothesis'; Details='Correlate username and email patterns' },
		@{ Type='BehaviorPatterns'; Details='Time-of-day activity clustering' },
		@{ Type='NetworkSummary'; Details='Geo assumptions based on IP metadata' }
	)
	$case = @{ Metadata=$meta; Artifacts=$artifacts }
	$file = "case_file_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
	($case | ConvertTo-Json -Depth 6) | Out-File -Encoding UTF8 -FilePath $file
	Write-Host "✅ Case file saved to $file" -ForegroundColor Green
	return $file
}

function Export-LinkAnalysis {
	Write-Host "🗺️ Generating synthetic link analysis graph..." -ForegroundColor Yellow
	$labelEmail = if ([string]::IsNullOrWhiteSpace($Email)) { 'email' } else { $Email }
	$labelUser  = if ([string]::IsNullOrWhiteSpace($Username)) { 'username' } else { $Username }
	$labelIP    = if ([string]::IsNullOrWhiteSpace($TargetIP)) { 'ip' } else { $TargetIP }
	$nodes = @(
		@{ id='target'; label='Target'; group=0 },
		@{ id='email'; label=$labelEmail; group=1 },
		@{ id='user'; label=$labelUser; group=1 },
		@{ id='ip'; label=$labelIP; group=2 }
	)
	$edges = @(
		@{ from='target'; to='email' },
		@{ from='target'; to='user' },
		@{ from='target'; to='ip' }
	)
	$html = @"
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8"/>
	<title>OSINT Link Analysis</title>
	<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
	<style> html, body, #m { height: 100%; margin:0; background:#0a0a0a; color:#fff } </style>
</head>
<body>
	<div id="m"></div>
	<script>
	const nodes = new vis.DataSet(@($(ConvertTo-Json $nodes)));
	const edges = new vis.DataSet(@($(ConvertTo-Json $edges)));
	const container = document.getElementById('m');
	const data = { nodes, edges };
	const options = { physics: { stabilization: true }, nodes: { color: '#2196f3' }, edges: { color: '#888' } };
	new vis.Network(container, data, options);
	</script>
</body>
</html>
"@
	$out = "osint_link_analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
	$html | Out-File -Encoding UTF8 -FilePath $out
	Write-Host "✅ Link analysis exported to $out" -ForegroundColor Green
	return $out
}

function Export-CaseBundle {
	$case = Get-ChildItem -Filter 'case_file_*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
	$graph = Get-ChildItem -Filter 'osint_link_analysis_*.html' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
	$bundle = "osint_bundle_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
	if ($case -or $graph) {
		Add-Type -AssemblyName System.IO.Compression.FileSystem
		$zip = [System.IO.Compression.ZipFile]
		$zip::CreateFromDirectory('.', $bundle) | Out-Null
		Write-Host "✅ Bundle created: $bundle" -ForegroundColor Green
	} else {
		Write-Host "No case or graph files found to bundle." -ForegroundColor Yellow
	}
}

if ($QuickReport) { Build-CaseFile | Out-Null; Export-LinkAnalysis | Out-Null } else { Show-OSINTMenu } 