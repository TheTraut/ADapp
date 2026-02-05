# Development Style Guide

## PowerShell Coding

- Prefer descriptive, full-word names for functions and variables
- Export a clear public surface from each module; keep helpers internal
- Use early returns to keep control flow shallow
- Avoid unnecessary try/catch; handle only when you can add value

## Comment-based Help (Required)

Include help above every function:

```powershell
<#!
.SYNOPSIS
Short one-line description.
.DESCRIPTION
Expanded description with important behavior and caveats.
.PARAMETER Name
Describe each parameter, default, and expected format.
.INPUTS
Input types.
.OUTPUTS
Output types.
.EXAMPLE
Example usage.
.NOTES
Ownership, links, or rationale.
#>
function Verb-Noun { }
```

## Logging

- Use `Write-Log` for structured, sanitized logging
- Use `Write-LogEvent` for machine-parsable events; add `CorrelationId` when chaining operations
- Use `Invoke-Safe` for user-initiated actions that should surface friendly errors

## Lint & Analyze

- Install tools once: `tools/Install-DevTools.ps1`
- Analyze the repo: `tools/Run-Analysis.ps1`
- Fix surfaced issues before submitting changes

## Docs Generation

- Generate API reference: `tools/Build-Docs.ps1`
- Keep module exports accurate so reference pages reflect the true public API

## Configuration and Secrets

- **Never commit secrets** to `config/settings.json`
- Use `%ProgramData%\ADapp\config\settings.local.json` for machine-specific secrets
- Environment variables (`ADAPP_CONNECTIONS_VNCPASSWORD`) can override settings
- See `config/settings.local.json.example` for the template

## Documentation Linking (Obsidian)

- Use Obsidian wiki links for internal docs: `[[path/to/page|Link text]]`
- Omit the `.md` extension; paths are relative to the `docs/` root (e.g., `[[usage/search]]`)
- Link to headings with: `[[path/to/page#Heading|Link text]]`
- Embed images with: `![[assets/img-name.png]]` (place assets under `docs/assets/` when possible)
- External URLs should remain standard Markdown links: `[Text](https://example.com)`

## See also
- [[index|Home]]
- [[usage/bitlocker|BitLocker]]
- [[usage/computers|Computers]]
- [[usage/favorites-history|Favorites & History]]
- [[usage/groups|Groups]]
- [[reference/index|API Reference]]

## Related commands
- [[reference/Logging/Write-Log|Write-Log]]
- [[reference/Logging/Write-LogEvent|Write-LogEvent]]
- [[reference/Logging/Invoke-Safe|Invoke-Safe]]
