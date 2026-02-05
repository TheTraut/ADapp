# User Location

## Centralized Database

- Consolidates `UserLogon.csv` files from workstations into a centralized view
- Allows searching by username, workstation, and time range

## Real-time Lookup

- If CSV data is missing, the tool can query logged-on users via WMI/QUser

## Update Process

1. Open Tools â†’ User Location
2. Trigger database update from all accessible workstations
3. Review merged results and filter as needed

## View Raw CSV

- Right-click computers in the Location Info panel to view their `UserLogon.csv` files

## See also
- [[usage/bitlocker|BitLocker]]
- [[usage/computers|Computers]]
- [[usage/favorites-history|Favorites & History]]
- [[usage/groups|Groups]]
- [[usage/search|Search]]
- [[usage/users|Users]]
- [[index|Home]]
- [[reference/index|API Reference]]

## Related commands
- [[reference/UserLocationIndex/Get-IndexedUsersForComputer|Get-IndexedUsersForComputer]]
- [[reference/UserManagement/Get-LoggedInUsers|Get-LoggedInUsers]]
- [[reference/UserLocationIndex/Get-UserLocation|Get-UserLocation]]
- [[reference/UserLocationIndex/Get-UserLocationForUsername|Get-UserLocationForUsername]]
- [[reference/UserLocationIndex/Get-UserLocationFromCentralizedDB|Get-UserLocationFromCentralizedDB]]
- [[reference/UserLocationIndex/Get-UserLocationIndexAge|Get-UserLocationIndexAge]]
- [[reference/UserLocationIndex/Get-UserLocationIndexLastUpdate|Get-UserLocationIndexLastUpdate]]
- [[reference/UserLocationIndex/Initialize-CentralizedUserLogonCSV|Initialize-CentralizedUserLogonCSV]]
- [[reference/UserLocationIndex/Initialize-UserLocationIndex|Initialize-UserLocationIndex]]
- [[reference/UserLocationIndex/Set-UserLocationIndexLastUpdate|Set-UserLocationIndexLastUpdate]]
- [[reference/UserLocationIndex/Show-CentralizedUserLogonCSV|Show-CentralizedUserLogonCSV]]
- [[reference/UserLocationIndex/Show-ComputerUserLogonCSV|Show-ComputerUserLogonCSV]]
- [[reference/UserLocationIndex/Show-UserLocationIndex|Show-UserLocationIndex]]
- [[reference/UserLocationIndex/Test-ComputerOnline|Test-ComputerOnline]]
- [[reference/UserLocationIndex/Update-CentralizedUserLogonCSV|Update-CentralizedUserLogonCSV]]
- [[reference/UserLocationIndex/Update-UserLocationIndex|Update-UserLocationIndex]]