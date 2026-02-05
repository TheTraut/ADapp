#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for the Settings module.
#>

Describe 'Load-Settings' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..\Modules\Settings.psm1'
        Import-Module $modulePath -Force
    }
    Context 'When settings.json exists' {
        BeforeAll {
            $testPath = Join-Path $TestDrive 'TestApp'
            New-Item -ItemType Directory -Path $testPath -Force | Out-Null
            $programDataTest = Join-Path $TestDrive 'ProgramData'
            New-Item -ItemType Directory -Path (Join-Path $programDataTest 'ADapp\Data') -Force | Out-Null
            $env:ProgramData = $programDataTest

            $testSettings = @{
                Application = @{ Title = 'Test App'; Version = '1.0.0' }
                Data = @{ PreferredSharedPath = '' }
                Connections = @{ VNCPath = 'C:\Test\vnc.exe'; VNCPassword = '' }
                Search = @{ MaxResults = 500 }
            }
            $configDir = Join-Path $testPath 'config'
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
            $testSettings | ConvertTo-Json -Depth 5 | Out-File (Join-Path $configDir 'settings.json') -Encoding UTF8
        }
        AfterAll {
            $env:ProgramData = [Environment]::GetFolderPath('CommonApplicationData')
        }

        It 'Should load settings from file' {
            $result = Load-Settings -ScriptPath $testPath
            $result | Should Not BeNullOrEmpty
            $result.Application.Title | Should Be 'Test App'
        }

        It 'Should backfill missing sections with defaults' {
            $result = Load-Settings -ScriptPath $testPath
            $result.Logging | Should Not BeNullOrEmpty
            $result.Logging.MaxLogFiles | Should BeGreaterThan 0
        }
    }

    Context 'When settings.json does not exist' {
        BeforeAll {
            $emptyPath = Join-Path $TestDrive 'EmptyApp'
            New-Item -ItemType Directory -Path $emptyPath -Force | Out-Null
            $programDataTest = Join-Path $TestDrive 'ProgramData'
            New-Item -ItemType Directory -Path (Join-Path $programDataTest 'ADapp\Data') -Force | Out-Null
            $env:ProgramData = $programDataTest
        }
        AfterAll {
            $env:ProgramData = [Environment]::GetFolderPath('CommonApplicationData')
        }

        It 'Should seed local settings and not create app-dir config' {
            $result = Load-Settings -ScriptPath $emptyPath
            $result | Should Not BeNullOrEmpty
            Test-Path (Join-Path $emptyPath 'config\settings.json') | Should Be $false
            Test-Path (Join-Path $env:ProgramData 'ADapp\Data\settings.json') | Should Be $true
        }

        It 'Should return valid default settings' {
            $result = Load-Settings -ScriptPath $emptyPath
            $result.Application.Title | Should Not BeNullOrEmpty
            $result.Connections | Should Not BeNullOrEmpty
        }
    }
}

Describe 'Settings Validation' {
    BeforeAll {
        $testPath = Join-Path $TestDrive 'ValidationApp'
        New-Item -ItemType Directory -Path $testPath -Force | Out-Null
        $programDataTest = Join-Path $TestDrive 'ProgramData'
        New-Item -ItemType Directory -Path (Join-Path $programDataTest 'ADapp\Data') -Force | Out-Null
        $env:ProgramData = $programDataTest
    }
    AfterAll {
        $env:ProgramData = [Environment]::GetFolderPath('CommonApplicationData')
    }

    Context 'Timeout validation' {
        It 'Should enforce minimum timeout values' {
            $badSettings = @{
                Application = @{ Title = 'Test' }
                Data = @{ PreferredSharedPath = '' }
                Connections = @{ RDPTimeout = 1; VNCTimeout = 2 }
            }
            $configDir = Join-Path $testPath 'config'
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
            $badSettings | ConvertTo-Json -Depth 5 | Out-File (Join-Path $configDir 'settings.json') -Encoding UTF8

            $result = Load-Settings -ScriptPath $testPath
            $result.Connections.RDPTimeout | Should BeGreaterThan 4
            $result.Connections.VNCTimeout | Should BeGreaterThan 4
        }
    }

    Context 'Search settings validation' {
        It 'Should enforce MaxSearchHistory bounds' {
            $badSettings = @{
                Application = @{ Title = 'Test' }
                Data = @{ PreferredSharedPath = '' }
                Search = @{ MaxSearchHistory = 1 }
            }
            $configDir = Join-Path $testPath 'config'
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
            $badSettings | ConvertTo-Json -Depth 5 | Out-File (Join-Path $configDir 'settings.json') -Encoding UTF8

            $result = Load-Settings -ScriptPath $testPath
            $result.Search.MaxSearchHistory | Should BeGreaterThan 4
        }
    }
}
