Param(
    [string]$Path,
    [switch]$ExcludeReference
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$docsRoot = if ($Path) { Resolve-Path $Path } else { Join-Path $repoRoot 'docs' }

Write-Host "Adding/Updating 'See also' sections under: $docsRoot" -ForegroundColor Cyan

function Get-TitleForDoc {
    param([string]$FilePath)
    try {
        $lines = Get-Content -Path $FilePath -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match '^\s*#\s+(.+)$') { return $Matches[1].Trim() }
            if ($line -match '^\s*##\s+(.+)$') { return $Matches[1].Trim() }
        }
        $name = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        return ($name -replace '-', ' ')
    } catch { return [System.IO.Path]::GetFileNameWithoutExtension($FilePath) }
}

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

function Build-SeeAlsoLinks {
    param([string]$CurrentFile)

    $rel = Get-RelativeSlug -FullPath $CurrentFile

    if ($ExcludeReference -and $rel -like 'reference/*') { return @() }

    $dir = Split-Path -Path $CurrentFile -Parent
    $isUsage = ($dir -like (Join-Path $docsRoot 'usage*'))
    $links = @()

    if ($isUsage) {
        $siblings = Get-ChildItem -Path $dir -Filter *.md -File | Where-Object { $_.FullName -ne $CurrentFile }
        foreach ($s in $siblings) {
            $slug = Get-RelativeSlug -FullPath $s.FullName
            $title = Get-TitleForDoc -FilePath $s.FullName
            $links += "- [[${slug}|${title}]]"
        }
        # Add links back to main areas
        $links += "- [[index|Home]]"
        $links += "- [[reference/index|API Reference]]"
    } else {
        # Root-level or other folders: link to key entry points
        if ($rel -ne 'index') { $links += "- [[index|Home]]" }
        $usageDir = Join-Path $docsRoot 'usage'
        if (Test-Path $usageDir) {
            # Link to a few representative usage pages
            $usagePages = Get-ChildItem -Path $usageDir -Filter *.md -File | Sort-Object Name | Select-Object -First 4
            foreach ($u in $usagePages) {
                $slug = Get-RelativeSlug -FullPath $u.FullName
                $title = Get-TitleForDoc -FilePath $u.FullName
                $links += "- [[${slug}|${title}]]"
            }
        }
        $links += "- [[reference/index|API Reference]]"
    }

    # Deduplicate while preserving order
    $seen = @{}
    $final = @()
    foreach ($l in $links) {
        if (-not $seen.ContainsKey($l)) { $seen[$l] = $true; $final += $l }
    }

    return $final
}

function Upsert-SeeAlsoSection {
    param(
        [string]$FilePath
    )

    $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
    $lines = $content -split "`r?`n"

    $seeAlsoHeaderIndex = -1
    for ($i=0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match '^##\s+See also\s*$') { $seeAlsoHeaderIndex = $i; break }
    }

    $newLinks = Build-SeeAlsoLinks -CurrentFile $FilePath
    if (-not $newLinks -or $newLinks.Count -eq 0) { return $false }

    $sectionLines = @('## See also') + $newLinks

    if ($seeAlsoHeaderIndex -ge 0) {
        # Replace until next header of same or higher level
        $end = $lines.Length
        for ($j=$seeAlsoHeaderIndex+1; $j -lt $lines.Length; $j++) {
            if ($lines[$j] -match '^##\s+') { $end = $j; break }
        }
        $before = if ($seeAlsoHeaderIndex -gt 0) { $lines[0..($seeAlsoHeaderIndex-1)] } else { @() }
        $after = if ($end -lt $lines.Length) { $lines[$end..($lines.Length-1)] } else { @() }
        $newContent = @()
        $newContent += $before
        if ($newContent.Count -gt 0 -and $newContent[-1] -ne '') { $newContent += '' }
        $newContent += $sectionLines
        $newContent += ''
        $newContent += $after
        $text = ($newContent -join "`r`n")
        if ($text -ne $content) {
            Set-Content -Path $FilePath -Value $text -NoNewline -Encoding UTF8
            return $true
        }
        return $false
    } else {
        # Append at end with spacing
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
    if ($slug -eq 'index') { continue }
    if ($ExcludeReference -and $slug -like 'reference/*') { continue }
    if (Upsert-SeeAlsoSection -FilePath $f.FullName) {
        $changed++
        Write-Host "Updated: $slug" -ForegroundColor Green
    } else {
        Write-Host "No changes: $slug" -ForegroundColor DarkGray
    }
}

Write-Host "'See also' processing complete. Files updated: $changed" -ForegroundColor Green
