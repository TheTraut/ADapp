# Contributing to ADapp

Thank you for your interest in contributing to ADapp! This document provides guidelines and best practices for contributing.

## Getting Started

1. **Clone the repository**
   ```powershell
   git clone <repository-url>
   cd ADapp
   ```

2. **Install development tools**
   ```powershell
   .\tools\Install-DevTools.ps1
   ```

3. **Run the build script** to verify your setup
   ```powershell
   .\scripts\Build.ps1 -Task Analyze
   ```

## Development Workflow

### Before Making Changes

1. Create a feature branch from `main`
2. Review existing code style in the module you're modifying
3. Check `docs/dev/style-guide.md` for coding conventions

### Making Changes

1. **Run analysis frequently**
   ```powershell
   .\scripts\Build.ps1 -Task Analyze
   ```

2. **Test your changes**
   ```powershell
   .\scripts\Build.ps1 -Task Test
   ```

3. **Validate configuration** if you modified settings
   ```powershell
   .\scripts\Build.ps1 -Task Validate
   ```

### Code Quality Standards

- **No errors** from PSScriptAnalyzer
- **Warnings** should be addressed or have documented justification
- **All exported functions** must have comment-based help
- **Secrets** must never be committed (use `%ProgramData%\ADapp\config\settings.local.json`)

## Project Structure

```
ADapp/
├── ADapp.ps1              # Main application entry point
├── Modules/               # PowerShell modules
│   ├── ADSearch.psm1      # AD search functionality
│   ├── Logging.psm1       # Logging and auditing
│   ├── Settings.psm1      # Configuration management
│   ├── Theme.psm1         # UI theming
│   ├── UI.psm1            # UI helpers
│   └── ...                # Other modules
├── tests/                 # Pester tests
├── tools/                 # Development utilities
├── docs/                  # Documentation
├── src/                   # C# launcher source
├── config/settings.json          # Default configuration (tracked)
├── %ProgramData%/ADapp/config/settings.local.json # Local overrides
├── scripts/               # Build/install/uninstall scripts
└── tools/PSScriptAnalyzerSettings.psd1  # Linter config
```

## Module Guidelines

### Creating a New Module

1. Create `Modules/YourModule.psm1`
2. Add module-level documentation at the top
3. Use `Export-ModuleMember` to explicitly export public functions
4. Add Pester tests in `tests/YourModule.Tests.ps1`

### Function Documentation

All exported functions should have comment-based help:

```powershell
<#
.SYNOPSIS
    Brief one-line description.
.DESCRIPTION
    Detailed description of what the function does.
.PARAMETER Name
    Description of each parameter.
.EXAMPLE
    Example-Function -Name "value"
    Description of what this example does.
.OUTPUTS
    Type. Description of output.
#>
function Example-Function {
    param([string]$Name)
    # ...
}
```

## Configuration

### Adding New Settings

1. Add the setting to `config/settings.json` with a sensible default
2. Add schema definition to `config/settings.schema.json`
3. Update `Load-Settings` in `Modules/Settings.psm1` to validate/backfill
4. Update documentation in `docs/setup.md`

### Sensitive Settings

**Never commit secrets.** Use one of:
- `%ProgramData%\ADapp\config\settings.local.json` (local machine)
- Environment variables (e.g., `ADAPP_CONNECTIONS_VNCPASSWORD`)

## Testing

### Running Tests

```powershell
# All tests
.\scripts\Build.ps1 -Task Test

# Specific test file
Invoke-Pester -Path .\tests\Settings.Tests.ps1
```

### Writing Tests

- Test files go in `tests/` directory
- Name format: `ModuleName.Tests.ps1`
- Use `BeforeAll` to import the module being tested
- Test both success and failure cases

## Pull Request Process

1. Update `CHANGELOG.md` with your changes
2. Ensure all tests pass
3. Ensure PSScriptAnalyzer shows no errors
4. Update documentation if needed
5. Request review

## Questions?

- Check existing documentation in `docs/`
- Review similar code in the codebase
- Open an issue for discussion

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
