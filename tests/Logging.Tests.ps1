#Requires -Module Pester

<#
.SYNOPSIS
    Pester tests for the Logging module.
#>

Describe 'Redact-SensitiveData' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..\Modules\Logging.psm1'
        Import-Module $modulePath -Force
    }
    It 'Should redact password patterns' {
        $input = 'password=mysecret123'
        $result = Redact-SensitiveData -Text $input
        $result | Should Not Match 'mysecret123'
        $result | Should Match '\[REDACTED\]'
    }
    
    It 'Should redact API key patterns' {
        $input = 'apikey=abc123xyz'
        $result = Redact-SensitiveData -Text $input
        $result | Should Not Match 'abc123xyz'
    }
    
    It 'Should redact email addresses' {
        $input = 'Contact: user@example.com for help'
        $result = Redact-SensitiveData -Text $input
        $result | Should Not Match 'user@example\.com'
        $result | Should Match '\[REDACTED_EMAIL\]'
    }
    
    It 'Should redact bearer tokens' {
        $input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        $result = Redact-SensitiveData -Text $input
        $result | Should Not Match 'eyJhbGci'
    }
    
    It 'Should preserve non-sensitive text' {
        $input = 'This is a normal log message without secrets'
        $result = Redact-SensitiveData -Text $input
        $result | Should Be $input
    }
}

Describe 'Test-ShouldSuppressOutput' {
    It 'Should return false for null input' {
        $result = Test-ShouldSuppressOutput -InputObject $null
        $result | Should Be $false
    }
    
    It 'Should return false for strings' {
        $result = Test-ShouldSuppressOutput -InputObject 'test string'
        $result | Should Be $false
    }
    
    It 'Should return false for numbers' {
        $result = Test-ShouldSuppressOutput -InputObject 42
        $result | Should Be $false
    }
}

Describe 'Invoke-SilentCommand' {
    It 'Should execute script block and return result' {
        $result = Invoke-SilentCommand -ScriptBlock { 1 + 1 }
        $result | Should Be 2
    }
    
    It 'Should suppress verbose output' {
        $result = Invoke-SilentCommand -ScriptBlock { 
            Write-Verbose "This should be suppressed" -Verbose
            return 'done'
        }
        $result | Should Be 'done'
    }
}
