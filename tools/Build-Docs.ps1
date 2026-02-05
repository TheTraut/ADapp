Param(
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$modulesPath = Join-Path $repoRoot 'Modules'
$docsRoot = if ($OutputRoot) { Resolve-Path $OutputRoot } else { Join-Path $repoRoot 'docs\\reference' }

Write-Host "Generating API reference under: $docsRoot" -ForegroundColor Cyan

try {
    if (-not (Get-Module -ListAvailable -Name PlatyPS)) {
        Write-Host "PlatyPS not found; installing..." -ForegroundColor Yellow
        & (Join-Path $PSScriptRoot 'Install-DevTools.ps1')
    }
    Import-Module PlatyPS -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Could not ensure PlatyPS is available: $_"
    exit 1
}

if (-not (Test-Path $modulesPath)) {
    Write-Error "Modules folder not found at $modulesPath"
    exit 1
}

$moduleFiles = Get-ChildItem -Path $modulesPath -Filter '*.psm1' -File | Sort-Object Name

foreach ($file in $moduleFiles) {
    $moduleName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $outDir = Join-Path $docsRoot $moduleName
    if (-not (Test-Path $outDir)) { $null = New-Item -ItemType Directory -Path $outDir -Force }

    Write-Host "Importing module: $moduleName" -ForegroundColor Green
    try {
        Import-Module -Name $file.FullName -Force -Global -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "Failed to import $($moduleName) from $($file.FullName): $_"
        continue
    }

    $cmds = Get-Command -Module $moduleName -ErrorAction SilentlyContinue
    if (-not $cmds) {
        Write-Warning "No exported commands found for module: $moduleName"
        continue
    }

    Write-Host "  Commands: $($cmds.Count)" -ForegroundColor DarkGray

    try {
        New-MarkdownHelp -Command ($cmds.Name) -OutputFolder $outDir -Force -AlphabeticParamsOrder | Out-Null
    } catch {
        Write-Warning "New-MarkdownHelp failed for $($moduleName): $_"
    }
}

Write-Host "API reference generation complete." -ForegroundColor Green

# Post-process docs to Obsidian wiki links for consistency across the vault
try {
    $docsFolder = Join-Path $repoRoot 'docs'
    Write-Host "Converting docs to Obsidian wiki links under: $docsFolder" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'Convert-To-ObsidianLinks.ps1') -Path $docsFolder | Out-Null
} catch {
    Write-Warning "Failed to convert links to Obsidian format: $_"
}

# Insert or update 'See also' sections across docs for better navigation
try {
    Write-Host "Adding 'See also' sections across docs..." -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'Add-SeeAlso.ps1') -Path $docsFolder -ExcludeReference | Out-Null
} catch {
    Write-Warning "Failed to add 'See also' sections: $_"
}

# Link to function descriptions (API reference) via 'Related commands' sections
try {
    Write-Host "Linking docs to API reference commands..." -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'Link-ReferenceCommands.ps1') -Path $docsFolder -ExcludeReference | Out-Null
} catch {
    Write-Warning "Failed to add 'Related commands' sections: $_"
}
