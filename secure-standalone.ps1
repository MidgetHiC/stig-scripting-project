
param(
    [Parameter(Mandatory = $false)]
    [bool]$cleargpos = $true,
    [Parameter(Mandatory = $false)]
    [bool]$installupdates = $true,
    [Parameter(Mandatory = $false)]
    [bool]$windows = $true,
    [Parameter(Mandatory = $false)]
    [bool]$mitigations = $true
)

######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

$paramscheck = $cleargpos, $installupdates, $windows, $defender, $firewall, $mitigations, $nessusPID, $sosoptional

# run a warning if no options are set to true
if ($paramscheck | Where-Object { $_ -eq $false } | Select-Object -Count -EQ $params.Count) {
    Write-Error "No Options Were Selected. Exiting..."
    Exit
}

# if any parameters are set to true take a restore point
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$scriptName = $MyInvocation.MyCommand.Name
if ($paramscheck | Where-Object { $_ } | Select-Object) {
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
    else {
        Write-Output "Not enough disk space to create a restore point. Current free space: $(($freespace/1GB)) GB"
    }
}

# Install Local Group Policy if Not Already Installed
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    Start-Job -Name InstallGPOPackages -ScriptBlock {
        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientTools*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }

        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientExtensions*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }
    }
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

if ($cleargpos -eq $true) {
    Write-Host "Removing Existing Local GPOs" -ForegroundColor Green
    #Remove and Refresh Local Policies
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
    secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
    gpupdate /force | Out-Null
}
else {
    Write-Output "The Clear Existing GPOs Section Was Skipped..."
}

if ($installupdates -eq $true) {
    Write-Host "Installing the Latest Windows Updates" -ForegroundColor Green
    #Install PowerShell Modules
    Copy-Item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
    #Unblock New PowerShell Modules
    Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
    #Install PSWindowsUpdate
    Import-Module -Name PSWindowsUpdate -Force -Global 

    #Install Latest Windows Updates
    Start-Job -Name "Windows Updates" -ScriptBlock {
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot
    }
}
else {
    Write-Output "The Install Update Section Was Skipped..."
}

if ($windows -eq $true) {
    Write-Host "Implementing the Windows 10/11 STIGs" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\DoD\Windows"

    Write-Host "Implementing simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green
    Write-Host "https://github.com/simeononsecurity/Windows-Audit-Policy" -ForegroundColor Green 

    New-Item -Force -ItemType "Directory" "C:\temp"
    Copy-Item $PSScriptRoot\files\auditing\auditbaseline.csv C:\temp\auditbaseline.csv 

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
}
else {
    Write-Output "The Windows Desktop Section Was Skipped..."
}

if ($mitigations -eq $true) {
    Write-Host "Implementing the General Vulnerability Mitigations" -ForegroundColor Green
    Start-Job -Name "Mitigations" -ScriptBlock {
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
        BCDEDIT /set "{current}" nx OptOut
        Set-Processmitigation -System -Enable DEP
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Type "DWORD" -Value 0 -Force
    
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
}
else {
    Write-Output "The General Mitigations Section Was Skipped..."
}

Write-Host "Checking Backgrounded Processes"; Get-Job

Write-Host "Performing Group Policy Update"
$timeoutSeconds = 180
$gpupdateJob = Start-Job -ScriptBlock { Gpupdate /force }
$gpupdateResult = Receive-Job -Job $gpupdateJob -Wait -Timeout $timeoutSeconds
if ($gpupdateResult -eq $null) {
    Write-Host "Group Policy Update timed out after $timeoutSeconds seconds."
} else {
    Write-Host "Group Policy Update completed."
}

Write-Warning "A reboot is required for all changes to take effect"
