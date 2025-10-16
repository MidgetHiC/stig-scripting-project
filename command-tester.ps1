#Disable PowerShell 2.0
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -Remove -NoRestart
if ((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State -eq "Disabled" -or (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State -eq "Absent") {
    Write-Host "PASSED"
} Else {
    Write-Host "FAILED"
}

Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -Remove -NoRestart
if ((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq "Disabled" -or (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq "Absent") {
    Write-Host "PASSED"
} Else {
    Write-Host "FAILED"
}