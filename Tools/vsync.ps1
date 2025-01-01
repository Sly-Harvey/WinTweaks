param (
    [string]$filePath,  # Path to the .nip file
    [int]$value     # Vsync Value
)

# Load the XML from the .nip file
[xml]$xml = Get-Content -Path $filePath

# Ensure the Settings node exists under the Profile
$settingsNode = $xml.ArrayOfProfile.Profile.Settings
if ($settingsNode -eq $null) {
    Write-Error "Settings node not found. The structure might not match the expected format."
    exit
}

# Locate the Vsync node where SettingID = "11041231"
$vsyncSetting = $settingsNode.ProfileSetting | Where-Object { $_.SettingID -eq "11041231" }
#$vsyncSetting = $settingsNode.ProfileSetting | Where-Object { $_.SettingNameInfo -eq "Vertical Sync" }

if (-not $vsyncSetting) {
    Write-Host "Vsync setting not found. No changes made."
} else {
    $vsyncSetting.SettingValue = $value.ToString()
    
    $xml.Save($filePath)

    Write-Host "Vsync SettingValue updated to $value successfully."
}