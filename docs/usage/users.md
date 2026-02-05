# Users

## View Details

- Select a user to populate the details panel (Field/Value list)
- Key fields include enabled status, last logon, and password last set

## Common Actions

- Reset Password: Use context menu or relevant UI action
- Enable/Disable Account: Toggle account status
- Unlock Account: Clear account lockout
- Manage Group Memberships: Add or remove user from groups

## Tips

- Use sorting to quickly identify users by status or date columns
- Add common queries (e.g., department, location) to Favorites for reuse

## Locked Accounts Monitor

- Launch via `Search` â†’ `Locked Accounts` â†’ `Monitor Locked`.
- Standalone window with auto-refresh and adjustable intervals (15sâ€“5m).
- Tracks lockout events over time; choose range (1hâ€“30d or Custom).
- Right-click or use buttons to Unlock or Reset Password (option to require change at next logon).

## See also
- [[usage/bitlocker|BitLocker]]
- [[usage/computers|Computers]]
- [[usage/favorites-history|Favorites & History]]
- [[usage/groups|Groups]]
- [[usage/search|Search]]
- [[usage/user-location|User Location]]
- [[index|Home]]
- [[reference/index|API Reference]]

## Related commands
- [[reference/UserManagement/Get-LoggedInUsers|Get-LoggedInUsers]]
- [[reference/UserManagement/Get-UserDetails|Get-UserDetails]]
- [[reference/QUserQuery/Get-CombinedComputerUserData|Get-CombinedComputerUserData]]
- [[reference/QUserQuery/Get-CombinedUserLocationData|Get-CombinedUserLocationData]]
- [[reference/QUserQuery/Get-QUserComputersForUser|Get-QUserComputersForUser]]
- [[reference/QUserQuery/Get-QUserHistoricalSessions|Get-QUserHistoricalSessions]]
- [[reference/QUserQuery/Get-QUserInfo|Get-QUserInfo]]
- [[reference/QUserQuery/Get-QUserInfoWithCache|Get-QUserInfoWithCache]]
- [[reference/QUserQuery/Get-QUserSessionsForComputer|Get-QUserSessionsForComputer]]
- [[reference/QUserQuery/Initialize-QUserCache|Initialize-QUserCache]]
- [[reference/QUserQuery/Update-QUserCache|Update-QUserCache]]