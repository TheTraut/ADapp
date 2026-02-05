Param(
    [string]$Path,
    [switch]$VerboseOutput
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$docsRoot = if ($Path) { Resolve-Path $Path } else { Join-Path $repoRoot 'docs' }

Write-Host "Converting Markdown links to Obsidian wiki links under: $docsRoot" -ForegroundColor Cyan

function Is-ExternalUrl {
    param([string]$Url)
    try {
        if ([string]::IsNullOrWhiteSpace($Url)) { return $false }
        if ($Url.StartsWith('#')) { return $true } # in-file anchors: leave unchanged
        $uri = $null
        if ([System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
            return $true
        }
        return $false
    } catch { return $true }
}

function Get-RootRelativePath {
    param(
        [string]$CurrentFile,
        [string]$TargetPath
    )

    $currentDir = Split-Path -Path $CurrentFile -Parent
    # Strip query string if present
    $noQuery = $TargetPath -split '\?' | Select-Object -First 1
    # Separate anchor
    $parts = $noQuery -split '#', 2
    $pathPart = $parts[0]
    $anchorPart = if ($parts.Count -gt 1) { $parts[1] } else { $null }

    # If target path is empty (e.g., just #anchor), bail
    if ([string]::IsNullOrWhiteSpace($pathPart)) { return $null }

    # Normalize to full path
    try {
        $combined = Join-Path $currentDir $pathPart
        $fullTarget = [System.IO.Path]::GetFullPath($combined)
    } catch {
        return $null
    }

    $rootFull = (Resolve-Path $docsRoot).Path
    if (-not ($fullTarget -like "$rootFull*")) { return $null }

    $relative = $fullTarget.Substring($rootFull.Length)
    $relative = $relative -replace '^[\\/]+',''
    $relative = $relative -replace '\\','/'
    $relativeNoExt = if ($relative.EndsWith('.md', [System.StringComparison]::OrdinalIgnoreCase)) {
        [System.IO.Path]::ChangeExtension($relative, $null)
    } else { $relative }
    $relativeNoExt = $relativeNoExt.TrimEnd('.')

    if ($anchorPart) { return "$relativeNoExt#$anchorPart" }
    return $relativeNoExt
}

function Convert-LinksInContent {
    param(
        [string]$Content,
        [string]$FilePath
    )

    # Convert image links: ![alt](path/to/img.png) -> ![[path/to/img.png]] (relative inside docs)
    $imagePattern = '!?\[(?<alt>[^\]]*)\]\((?<url>[^\)]+)\)'
    $Content = [regex]::Replace($Content, $imagePattern, {
        param($m)
        $isImage = $m.Value.StartsWith('!')
        if (-not $isImage) { return $m.Value }
        $url = $m.Groups['url'].Value.Trim()
        if (Is-ExternalUrl -Url $url) { return $m.Value }
        $rel = Get-RootRelativePath -CurrentFile $FilePath -TargetPath $url
        if (-not $rel) { return $m.Value }
        return "![[${rel}]]"
    })

    # Convert standard links: [text](path/to/doc.md#h) -> [[path/to/doc#h|text]]
    $linkPattern = '(?<!\!)\[(?<text>[^\]]+)\]\((?<url>[^\)]+)\)'
    $Content = [regex]::Replace($Content, $linkPattern, {
        param($m)
        $text = $m.Groups['text'].Value
        $url  = $m.Groups['url'].Value.Trim()
        if (Is-ExternalUrl -Url $url) { return $m.Value }
        # In-file anchors only (e.g., #section) -> keep as-is; Obsidian can handle standard anchor links but we avoid guessing heading text
        if ($url.StartsWith('#')) { return $m.Value }
        $rel = Get-RootRelativePath -CurrentFile $FilePath -TargetPath $url
        if (-not $rel) { return $m.Value }
        # Prefer keeping the display text to avoid changing authoring intent
        return "[[${rel}|${text}]]"
    })

    # Fix trailing dots left from extension removal inside wiki links (e.g., [[setup.|Setup]] -> [[setup|Setup]])
    $Content = [regex]::Replace($Content, '\[\[(?<path>[^\|\]]+)\.\|(?<alias>[^\]]+)\]\]', {
        param($m)
        return "[[" + $m.Groups['path'].Value + '|' + $m.Groups['alias'].Value + "]]"
    })

    return $Content
}

$files = Get-ChildItem -Path $docsRoot -Recurse -Filter *.md -File | Sort-Object FullName
foreach ($f in $files) {
    $raw = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
    $new = Convert-LinksInContent -Content $raw -FilePath $f.FullName
    if ($new -ne $raw) {
        if ($VerboseOutput) { Write-Host "Updated links in: $($f.FullName)" -ForegroundColor Green }
        Set-Content -Path $f.FullName -Value $new -NoNewline -Encoding UTF8
    } else {
        if ($VerboseOutput) { Write-Host "No changes: $($f.FullName)" -ForegroundColor DarkGray }
    }
}

Write-Host "Obsidian link conversion complete." -ForegroundColor Green


