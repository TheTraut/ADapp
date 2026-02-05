Param()

Write-Host "Installing developer tools (PlatyPS, PSScriptAnalyzer)..." -ForegroundColor Cyan

# Ensure TLS 1.2 for PowerShell Gallery
try {
    $curr = [Net.ServicePointManager]::SecurityProtocol
    $tls12 = [Net.SecurityProtocolType]::Tls12
    if (($curr -band $tls12) -ne $tls12) {
        [Net.ServicePointManager]::SecurityProtocol = $curr -bor $tls12
        Write-Host "Enabled TLS 1.2 for PowerShell Gallery." -ForegroundColor DarkGray
    }
} catch {
    Write-Warning "Could not set TLS 1.2: $_"
}

# Ensure NuGet package provider is available
try {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Host "Installing NuGet package provider..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Warning "Failed to install NuGet provider: $_"
}

# Ensure PSGallery repository is registered and trusted
try {
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $repo) {
        Write-Host "Registering PowerShell Gallery..." -ForegroundColor Yellow
        Register-PSRepository -Name 'PSGallery' -SourceLocation 'https://www.powershellgallery.com/api/v2' -ScriptSourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted -ErrorAction Stop
    } elseif ($repo.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }
} catch {
    Write-Warning "Failed to register PSGallery: $_"
}

# Try to update PowerShellGet to a newer version (optional but helps reliability)
try {
    if (-not (Get-Module -ListAvailable -Name PowerShellGet | Where-Object { $_.Version -ge [Version]'2.2.5' })) {
        Write-Host "Updating PowerShellGet (may require restarting session)..." -ForegroundColor Yellow
        Install-Module -Name PowerShellGet -Scope CurrentUser -Force -AllowClobber -ErrorAction SilentlyContinue
    }
} catch {
    Write-Warning "Skipping PowerShellGet update: $_"
}

$modules = @(
    @{ Name = 'PlatyPS'; MinimumVersion = '0.14.2' },
    @{ Name = 'PSScriptAnalyzer'; MinimumVersion = '1.21.0' }
)

foreach ($m in $modules) {
    try {
        if (-not (Get-Module -ListAvailable -Name $m.Name)) {
            Write-Host "Installing $($m.Name)..." -ForegroundColor Yellow
            Install-Module -Name $($m.Name) -Scope CurrentUser -Force -AllowClobber -MinimumVersion $($m.MinimumVersion) -Repository PSGallery -ErrorAction Stop
        }
        Import-Module -Name $($m.Name) -ErrorAction Stop | Out-Null
        Write-Host "$($m.Name) is ready." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to install or import $($m.Name): $_"
        Write-Host "Attempting fallback via Save-Module..." -ForegroundColor Yellow
        $cacheRoot = Join-Path $env:LOCALAPPDATA 'ADapp\\ModuleCache'
        try {
            if (-not (Test-Path $cacheRoot)) { $null = New-Item -ItemType Directory -Path $cacheRoot -Force }
            Save-Module -Name $($m.Name) -Path $cacheRoot -MinimumVersion $($m.MinimumVersion) -Repository PSGallery -Force -ErrorAction Stop
            $moduleDir = Get-ChildItem -Path (Join-Path $cacheRoot $($m.Name)) -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($moduleDir) {
                Import-Module -Name $moduleDir.FullName -ErrorAction Stop | Out-Null
                Write-Host "$($m.Name) loaded from cache: $($moduleDir.FullName)" -ForegroundColor Green
            } else {
                throw "Fallback Save-Module succeeded but no module directory found."
            }
        } catch {
            Write-Host "Troubleshooting steps:" -ForegroundColor Cyan
            Write-Host "  1) Ensure internet/proxy access to https://www.powershellgallery.com/api/v2" -ForegroundColor DarkGray
            Write-Host "  2) Run: [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" -ForegroundColor DarkGray
            Write-Host "  3) Run: Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force" -ForegroundColor DarkGray
            Write-Host "  4) Run: Register-PSRepository -Name PSGallery -SourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted" -ForegroundColor DarkGray
            throw
        }
    }
}

Write-Host "Developer tools installation completed." -ForegroundColor Green
