# Change Log

## Version 1.0.19 - AD object group management and favorites resilience

### Group Management and AD Objects
- Expanded `Attribute Editor...` to support any AD object type, not only users/computers
- Expanded `Manage Groups` to support any AD object that can be a group member (users, computers, groups, contacts, etc.)
- Added generic AD-object group membership operations in `Modules/SecurityGroups.psm1`:
  - `Get-ADObjectSecurityGroups`
  - `Add-ADObjectToSecurityGroup`
  - `Remove-ADObjectFromSecurityGroup`
- Updated group membership refresh logic to support distinguished-name based objects in the main UI

### Favorites and Data Reliability
- Hardened favorites loading with fallback reads when module-scope reads return empty data
- Added JSON repair logic for corrupted/concatenated favorites JSON and automatic rewrite to clean JSON
- Added atomic temp-file writes for JSON and JSONL persistence in `Modules/DataSync.psm1` to reduce corruption risk during concurrent writes

### Group Dialog UX
- Reworked `Show-GroupManagementDialog` to focus on currently selected memberships plus explicit `Add...` search flow
- Increased dialog size, improved list behavior, and fixed checked-state refresh edge cases

## Version 1.0.18 - Configuration, PDQ pathing, and installer improvements

### UI/UX
- Enforced a minimum window size to prevent layout breakage
- Added a detailed results panel and improved list sorting
- Enhanced ListView sorting and persisted sort settings
- Fixed search history menu initialization
- Added computer shutdown and restart actions to the UI
- Ensured consistent menu text color across themes

### Settings and Configuration
- Switched to shared-first settings loading and preserved unknown keys when saving
- Removed hard-coded AD/PDQ defaults and added a configurable domain controller list
- Added configurable AD base OUs and support for multiple base OUs per object type
- Removed legacy settings keys and defaults

### Active Directory and Search
- Improved AD location matching and filtering logic
- Enhanced favorites management and advanced search handling
- Refactored the `ADSearch` module for robustness and added help stubs

### PDQ Integration
- Standardized PDQ executable path resolution by storing explicit executable paths
- Added PDQ license check and gracefully stop PDQ apps before operations
- Iterated on InstallPath approach; finalized on explicit PDQ pathing

### Shared Data and Sync
- Refactored shared data sync to use the preferred share as the source of truth
- Refreshed menus automatically after sync when files change

### Install/Uninstall and Packaging
- Improved `scripts/Install.ps1` to handle `Resolve-Path` arrays and other edge cases
- Extended uninstall options and refined `scripts/Uninstall.ps1`
- Added `scripts/Package-Release.ps1` and `QUICKSTART.md`; updated `README.md`

### Repository and Tooling
- Updated `.gitignore`
- Temporarily removed GitHub Actions CI workflow

## Version 1.0.17 - Codebase Cleanup, Security, and Developer Experience

### Security
- Removed secrets from `config/settings.json`; added `%ProgramData%\ADapp\config\settings.local.json` override pattern for machine-specific secrets
- Added environment variable override support (`ADAPP_CONNECTIONS_VNCPASSWORD`) for automation scenarios

### Code Quality
- Fixed all ScriptAnalyzer unused variable warnings across the codebase
- Removed duplicate auto-generated help comment blocks from all modules
- Extracted theme logic into new `Modules/Theme.psm1` module (~200 lines cleaner ADapp.ps1)
- Fixed incorrect filename in LockedMonitor.Launcher error message
- Added proper help comments to key functions
- Updated PSScriptAnalyzer settings to reduce noise (exported functions only for help check)
- Rewrote and cleaned up modules: Favorites, SearchHistory, BitLockerRecovery, LockedAccounts, UserManagement, ComputerManagement

### Developer Experience
- Added `.editorconfig` for consistent formatting across editors
- Added `scripts/Build.ps1` build script with tasks: Analyze, Build, Validate, Test
- Added `config/settings.schema.json` for JSON schema validation in editors
- Added Pester test suite (`tests/`) for Settings, Theme, and Logging modules
- Added version info and error handling to C# launchers
- C# launchers now use object initializers and proper exit codes
- Added `scripts/Install.ps1` setup script for easy installation
- Added `CONTRIBUTING.md` with development guidelines
- Added GitHub Actions CI workflow (`.github/workflows/ci.yml`)

### Documentation
- Updated `docs/setup.md` with new configuration layering and secrets handling
- Updated `docs/dev/style-guide.md` with configuration and secrets guidelines
- Removed duplicated "User Location Tracking" section in README
- Added `config/settings.local.json.example` template
- Added module-level documentation headers to all modules

### Repository
- Improved `.gitattributes` for consistent line endings across platforms
- Added `config/settings.local.json` and `config/settings.secret.json` to `.gitignore`
- Deleted orphaned `Modules/PDQInventory.psm1_temp` file

## Version 1.0.16 - UI Improvements and User Tracking Overhaul
- **Major Change:** Completely migrated user location tracking from legacy index system to PDQ Inventory-based tracking
- Updated all user location functionality to use PDQ data for more accurate and real-time information
- Enhanced Location Info panel to display PDQ-sourced user and computer relationships
- Improved cross-referencing between users and computers using PDQ Inventory data
- Cleaned up File menu by removing redundant "Settings" submenu and making "Edit Settings" a direct menu item
- Fixed advanced search panel visibility issue where checkbox was checked on startup but panel wasn't displayed until toggled
- Improved initial state handling for advanced search to properly show panel when enabled by default in settings
- Enhanced control initialization sequence to ensure proper UI state on application startup
- Added "Open Data Folder" button to General settings tab for easy access to application data directory
- Added "Open Logs Folder" button to Logging settings tab for convenient access to log files
- Improved settings dialog usability with quick folder access buttons

## Version 1.0.15 - Bug Fixes and Improvements
- Fixed critical bug where Connection menu was not appearing due to incorrect menu creation
- Fixed AD Sync button null reference and corrected remote invocation; added robust settings resolution with validation for ADSyncDC and ADSyncScriptPath
- Fixed settings path references for VNC and AD sync functionality to use correct nested JSON structure
- Added comprehensive logging and debugging to VNC connection functionality
- Improved error handling and user feedback for VNC connections
- Enhanced menu structure and organization

## Version 1.0.14 - Runtime Configuration
- Added `settings.json` for central configuration of default values
- Added Settings menu with Edit Settings dialog to modify configuration at runtime
- Implemented GUI dialog to edit and save settings to JSON file
- Moved hard-coded values into configuration file
- Extended configuration with UI, appearance, logging and search settings
- Added tabbed settings interface with multiple categories

## Version 1.0.13
- Implemented caching system for centralized database access to improve query performance
- Added computer online status caching to reduce network traffic and speed up UI responsiveness
- Optimized AD computer search with bulk retrieval and intelligent caching of results
- Implemented parallel processing for database updates using PowerShell jobs
- Reduced CPU and memory usage for large AD environments
- Improved overall application responsiveness with optimized data retrieval
- Reduced timeout periods and optimized network operations for faster performance

## Version 1.0.12
- Consolidated User Location menu items for improved organization
- Added centralized CSV database for offline user location tracking
- New functions to view and update the centralized database
- Added ability to view current workstation CSV files from the centralized interface
- Removed legacy indexing to improve performance and usability
- Added compatibility wrapper for Get-IndexedUsersForComputer to maintain functionality in Location Info panel
- Enhanced automatic database updates to include live user sessions from quser when viewing computer details
- Improved Location Info panel to show detailed timestamps and actions (logon/logoff/lock/unlock) from centralized database

## Version 1.0.11
- Added ability to double-click a computer name in the Location Info panel to open the computer's details as if searched
- Added context menu option to view CSV when right-clicking on a computer in the Location Info panel
- Added comprehensive search and filtering options for CSV data viewer
- 
## Version 1.0.10
- Added enhanced user search functionality to support searching by first and last name in either order
- Improved name search capabilities in Advanced Search to find users regardless of name order input
- Updated search functions to intelligently parse search input as potential first and last names

## Version 1.0.9
- Added BitLocker recovery password retrieval functionality
- Created new BitLockerRecovery module for handling BitLocker operations
- Added BitLocker Recovery menu option in the AD menu
- Added dialog for viewing and copying BitLocker recovery passwords
- Updated documentation to include BitLocker recovery feature

## Version 1.0.7
- Fixed sequencing issue where Write-Log was called before the Logging module was loaded
- Improved module loading order to ensure Logging module is loaded first
- Enhanced error handling for module loading

## Version 1.0.6
- Fixed issue with Get-ADUser and other ActiveDirectory cmdlets not being recognized
- Added stub functions for ActiveDirectory cmdlets to handle cases when the module isn't available
- Improved error handling in ADSearch module to prevent script termination when ActiveDirectory module is missing
- Enhanced module loading resilience for environments without RSAT tools installed

## Version 1.0.5
- Fixed issue with Search-ADObjectsAdvanced function not being recognized
- Added fallback function implementation for more robust search functionality
- Improved module loading with better error handling

## Version 1.0.4
- Added support for displaying distribution groups in the manage groups dialog
- Added "Group Type" column in the group management interface
- Modified the group list view to show group type information
- Updated internal group retrieval functions to include all group types
- Fixed issue where distribution groups were not being displayed

## Version 1.0.3
- Enter key now will act as if clicking the search button.

## Version 1.0.2
- Added automatic updating of user location index when a computer is selected in the UI
- Organized AD menu by creating a Group Management submenu with Manage Groups and Manage Group Members items
- Improved display of computer properties by implementing the Update-BasicInfoPanel function
- Fixed issue with retrieving and displaying computer properties in the UI
- Enhanced the user location lookup functionality for better user tracking

## Version 1.0.1
- Fixed group management dialog freezing when non-group objects are selected
- Improved group detection logic in the Manage Group Members functionality
- Enhanced error handling in group membership operations
- Added proper refresh of group display after changes
- Fixed progress bar and status label visibility issues

## Version 1.0.0
- Initial release of refactored application
- Modular architecture with improved error handling
- Enhanced user interface and search capabilities
- Added advanced search options
- Implemented favorites and search history
- Added group management functionality
- Added computer management tools
- Improved logging and error handling
- Added user location index features
- Added support for UNC paths

### Features
- **Search Functionality**
  - Basic and advanced search options
  - Support for wildcard searches
  - Location-based filtering
  - Status filtering (Enabled/Disabled)
  - Date range filtering
  - Exact match option
  - Include inactive objects option

- **User Interface**
  - Modern Windows Forms interface
  - Proper application icon display
  - Status bar with progress indicators
  - Detailed object information display
  - Color-coded results based on status
  - Advanced search panel with collapsible options

- **Group Management**
  - View and manage group memberships
  - Add/remove users and computers from groups
  - Group member display with details
  - Automatic refresh after changes
  - Error handling and validation

- **Computer Management**
  - Remote desktop connection
  - VNC connection support
  - Computer management console access
  - File explorer access
  - Power management (shutdown/restart)
  - Online/offline status indication

- **User Management**
  - Password reset functionality
  - Account enable/disable
  - Account unlock
  - User location tracking
  - Group membership management

- **Data Management**
  - Favorites system for common searches
  - Search history tracking
  - User location index
  - Index backup and repair
  - Advanced update options

- **Logging and Error Handling**
  - Comprehensive logging system
  - Error handling throughout the application
  - Transcript logging for debugging
  - Status updates and progress indicators
  - User-friendly error messages

- **Technical Improvements**
  - Modular PowerShell architecture
  - Proper UNC path support
  - TLS 1.2 security protocol enforcement
  - Progress bar and status label improvements
  - Memory management optimizations

### Bug Fixes
- Fixed application icon display issues
- Resolved wildcard search functionality
- Fixed group management dialog freezing
- Corrected progress bar visibility issues
- Fixed status label update problems
- Resolved UNC path execution issues
- Fixed group membership refresh issues
- Corrected location filtering in searches
- Fixed cursor property errors
- Resolved PowerShell comment style issues

### Known Issues
- None currently documented

### Dependencies
- PowerShell 5.1 or later
- Active Directory module
- Windows Forms assemblies
- VNC viewer (optional, for remote access)

