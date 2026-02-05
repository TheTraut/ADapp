Param(
	[string]$Path,
	[switch]$ExcludeReference
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$docsRoot = if ($Path) { Resolve-Path $Path } else { Join-Path $repoRoot 'docs' }
$refRoot  = Join-Path $docsRoot 'reference'

Write-Host "Adding/Updating 'Related commands' sections under: $docsRoot" -ForegroundColor Cyan

function Get-RelativeSlug {
	param([string]$FullPath)
	$root = (Resolve-Path $docsRoot).Path
	$full = [System.IO.Path]::GetFullPath($FullPath)
	$rel = $full.Substring($root.Length)
	$rel = $rel -replace '^[\\/]+',''
	$rel = $rel -replace '\\','/'
	if ($rel.EndsWith('.md', [System.StringComparison]::OrdinalIgnoreCase)) {
		$rel = [System.IO.Path]::ChangeExtension($rel, $null)
	}
	$rel = $rel.TrimEnd('.')
	return $rel
}

# Build index of commands from docs/reference/<Module>/<Command>.md
$commandToSlug   = @{}
$moduleToCmdList = @{}
if (Test-Path $refRoot) {
	$moduleDirs = Get-ChildItem -Path $refRoot -Directory | Sort-Object Name
	foreach ($mod in $moduleDirs) {
		$cmdFiles = Get-ChildItem -Path $mod.FullName -Filter *.md -File | Sort-Object Name
		foreach ($f in $cmdFiles) {
			$cmdName = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
			$slug    = Get-RelativeSlug -FullPath $f.FullName
			$commandToSlug[$cmdName] = $slug
			if (-not $moduleToCmdList.ContainsKey($mod.Name)) { $moduleToCmdList[$mod.Name] = New-Object System.Collections.ArrayList }
			[void]$moduleToCmdList[$mod.Name].Add($cmdName)
		}
	}
}

# Fallback mapping from doc slugs to modules
$pageToModules = @{
	'usage/search'            = @('ADSearch','SearchHistory')
	'usage/users'             = @('UserManagement','QUserQuery')
	'usage/computers'         = @('ComputerManagement','PDQInventory')
	'usage/groups'            = @('SecurityGroups')
	'usage/bitlocker'         = @('BitLockerRecovery')
	'usage/user-location'     = @('UserLocationIndex')
	'usage/favorites-history' = @('Favorites','SearchHistory')
	'architecture'            = @('Logging','Settings','Transcript')
}

function Detect-CommandsInContent {
	param([string]$Content)
	$found = New-Object System.Collections.ArrayList
	if ($commandToSlug.Count -eq 0) { return $found }
	# Avoid code fences: split by triple backticks blocks and only scan non-code segments
	$segments = [regex]::Split($Content, '```[\s\S]*?```', [System.Text.RegularExpressions.RegexOptions]::Singleline)
	foreach ($seg in $segments) {
		foreach ($cmd in $commandToSlug.Keys) {
			$pattern = '(?<![\w-])' + [regex]::Escape($cmd) + '(?![\w-])'
			if ([regex]::IsMatch($seg, $pattern)) {
				if (-not $found.Contains($cmd)) { [void]$found.Add($cmd) }
			}
		}
	}
	return $found
}

function Upsert-RelatedCommands {
	param([string]$FilePath)
	$slug = Get-RelativeSlug -FullPath $FilePath
	$raw  = Get-Content -Path $FilePath -Raw -ErrorAction Stop

	$cmds = Detect-CommandsInContent -Content $raw
	$cmds = @($cmds)
	if ($cmds.Count -eq 0 -and $pageToModules.ContainsKey($slug)) {
		# Use fallback modules' commands
		$moduleList = $pageToModules[$slug]
		foreach ($m in $moduleList) {
			if ($moduleToCmdList.ContainsKey($m)) {
				foreach ($c in $moduleToCmdList[$m]) { if ($cmds -notcontains $c) { $cmds += $c } }
			}
		}
	}

	if ($cmds.Count -eq 0) { return $false }

	# Build section
	# Dedupe while preserving order
	$seenCmds = @{}
	$orderedCmds = @()
	foreach ($c in $cmds) { if (-not $seenCmds.ContainsKey($c)) { $seenCmds[$c] = $true; $orderedCmds += $c } }

	$bullets = @()
	foreach ($c in $orderedCmds) {
		if ($commandToSlug.ContainsKey($c)) {
			$bullets += ("- [[{0}|{1}]]" -f $commandToSlug[$c], $c)
		}
	}
	if ($bullets.Count -eq 0) { return $false }

	$lines = $raw -split "`r?`n"
	$headerIndex = -1
	for ($i=0; $i -lt $lines.Length; $i++) {
		if ($lines[$i] -match '^##\s+Related commands\s*$') { $headerIndex = $i; break }
	}

	$sectionLines = @('## Related commands') + $bullets
	if ($headerIndex -ge 0) {
		# Replace until next header of same or higher level
		$end = $lines.Length
		for ($j=$headerIndex+1; $j -lt $lines.Length; $j++) {
			if ($lines[$j] -match '^##\s+') { $end = $j; break }
		}
		$before = if ($headerIndex -gt 0) { $lines[0..($headerIndex-1)] } else { @() }
		$after  = if ($end -lt $lines.Length) { $lines[$end..($lines.Length-1)] } else { @() }
		$newContent = @()
		$newContent += $before
		if ($newContent.Count -gt 0 -and $newContent[-1] -ne '') { $newContent += '' }
		$newContent += $sectionLines
		$newContent += ''
		$newContent += $after
		$text = ($newContent -join "`r`n")
		if ($text -ne $raw) { Set-Content -Path $FilePath -Value $text -NoNewline -Encoding UTF8; return $true } else { return $false }
	} else {
		# Append at end
		$append = @()
		if ($lines.Length -gt 0 -and $lines[-1].Trim() -ne '') { $append += '' }
		$append += $sectionLines
		$text = ($lines + $append) -join "`r`n"
		Set-Content -Path $FilePath -Value $text -NoNewline -Encoding UTF8
		return $true
	}
}

$files = Get-ChildItem -Path $docsRoot -Recurse -Filter *.md -File | Sort-Object FullName
$changed = 0
foreach ($f in $files) {
	$slug = Get-RelativeSlug -FullPath $f.FullName
	if ($slug -like 'reference/*') { if ($ExcludeReference) { continue } }
	if ($slug -eq 'index') { continue }
	if (Upsert-RelatedCommands -FilePath $f.FullName) { $changed++; Write-Host "Updated: $slug" -ForegroundColor Green } else { Write-Host "No changes: $slug" -ForegroundColor DarkGray }
}

Write-Host "'Related commands' processing complete. Files updated: $changed" -ForegroundColor Green
