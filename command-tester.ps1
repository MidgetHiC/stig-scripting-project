$infPath = "$env:TEMP\password_policy.inf"
$dbPath = "$env:TEMP\$(Get-Random).sdb"
if (Test-Path $dbPath) { Remove-Item $dbPath -Force }

$infContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
PasswordComplexity = 1
'@ | Out-File -FilePath $infPath -Encoding Unicode

secedit /validate $infPath /quiet
cmd /c "secedit /configure /db $dbPath /cfg $infPath /verbose"
gpupdate /force

$infPath = "$env:TEMP\secpol_modified.inf"
$dbPath = "$env:TEMP\$(Get-Random).sdb"
if (Test-Path $dbPath) { Remove-Item $dbPath -Force }

$infContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeNetworkLogonRight = Administrators,Remote Desktop Users
'@ | Out-File -FilePath $infPath -Encoding Unicode

secedit /validate $infPath /quiet
cmd /c "secedit /configure /db $dbPath /cfg $infPath /verbose"
