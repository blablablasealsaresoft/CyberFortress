param(
	[ValidateSet('Encrypt','Decrypt','Menu')]
	[string]$Action = 'Menu',
	[string]$InputFile,
	[string]$OutputFile,
	[string]$Passphrase
)

function Derive-KeyIv {
	param([string]$Passphrase)
	$bytes = [Text.Encoding]::UTF8.GetBytes($Passphrase)
	$sha = [System.Security.Cryptography.SHA256]::Create()
	$key = $sha.ComputeHash($bytes)
	$iv = $key[0..15]
	return ,@($key,$iv)
}

function Encrypt-File {
	param([string]$In,[string]$Out,[string]$Secret)
	$key,$iv = Derive-KeyIv -Passphrase $Secret
	$aes = [System.Security.Cryptography.Aes]::Create()
	$aes.Mode = 'CBC'
	$aes.Key = $key
	$aes.IV = $iv
	$encryptor = $aes.CreateEncryptor()
	$plain = [IO.File]::ReadAllBytes($In)
	$pad = 16 - ($plain.Length % 16)
	$plainPadded = $plain + (,[byte]$pad * $pad)
	$cipher = $encryptor.TransformFinalBlock($plainPadded,0,$plainPadded.Length)
	[IO.File]::WriteAllBytes($Out, $cipher)
}

function Decrypt-File {
	param([string]$In,[string]$Out,[string]$Secret)
	$key,$iv = Derive-KeyIv -Passphrase $Secret
	$aes = [System.Security.Cryptography.Aes]::Create()
	$aes.Mode = 'CBC'
	$aes.Key = $key
	$aes.IV = $iv
	$decryptor = $aes.CreateDecryptor()
	$cipher = [IO.File]::ReadAllBytes($In)
	$plainPadded = $decryptor.TransformFinalBlock($cipher,0,$cipher.Length)
	$pad = $plainPadded[-1]
	$plain = $plainPadded[0..($plainPadded.Length-$pad-1)]
	[IO.File]::WriteAllBytes($Out, $plain)
}

function Show-QuantumMenu {
	Clear-Host
	Write-Host "🔐 Quantum-Safe Crypto Suite (Placeholder)" -ForegroundColor Cyan
	Write-Host "=" * 60
	Write-Host "Note: AES-CBC used locally as placeholder. PQC integration planned (Kyber/SPHINCS+)." -ForegroundColor Yellow
	Write-Host "1. Encrypt File (local AES)" -ForegroundColor Green
	Write-Host "2. Decrypt File (local AES)" -ForegroundColor Green
	Write-Host "3. Exit" -ForegroundColor Gray
	$choice = Read-Host "Select option (1-3)"
	switch ($choice) {
		"1" {
			$in = Read-Host "Input file path"; $out = Read-Host "Output file path"; $pw = Read-Host "Passphrase"
			Encrypt-File -In $in -Out $out -Secret $pw
			Write-Host "✅ Encrypted to $out" -ForegroundColor Green
			[void](Read-Host "Press Enter to continue...")
			Show-QuantumMenu
		}
		"2" {
			$in = Read-Host "Input file path"; $out = Read-Host "Output file path"; $pw = Read-Host "Passphrase"
			Decrypt-File -In $in -Out $out -Secret $pw
			Write-Host "✅ Decrypted to $out" -ForegroundColor Green
			[void](Read-Host "Press Enter to continue...")
			Show-QuantumMenu
		}
		"3" { return }
		default { Show-QuantumMenu }
	}
}

if ($Action -eq 'Encrypt') { Encrypt-File -In $InputFile -Out $OutputFile -Secret $Passphrase }
elseif ($Action -eq 'Decrypt') { Decrypt-File -In $InputFile -Out $OutputFile -Secret $Passphrase }
else { Show-QuantumMenu } 