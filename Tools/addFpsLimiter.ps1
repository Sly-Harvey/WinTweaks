param (
    [string]$filePath,  # Path to the .nip file
    [int]$FPS,     # Default FPS value if not passed
    [switch]$Add,       # Flag to add the setting
    [switch]$Delete     # Flag to delete the setting
)

# Load the XML from the .nip file
[xml]$xml = Get-Content -Path $filePath

# Ensure the Settings node exists under the Profile
$settingsNode = $xml.ArrayOfProfile.Profile.Settings
if ($settingsNode -eq $null) {
    Write-Error "Settings node not found. The structure might not match the expected format."
    exit
}

# Handle the -Add argument
if ($Add) {
    if (-not $FPS) {
        Write-Host "ERROR: No FPS value specified for  Frame Rate Limiter."
    }

    # Check if the Frame Rate Limiter already exists
    $existingSetting = $settingsNode.ProfileSetting | Where-Object { $_.SettingID -eq "277041154" }

    if ($existingSetting) {
        Write-Host "Frame Rate Limiter setting already exists. No changes made."
    } else {
        # Create a new ProfileSetting node for "Frame Rate Limiter"
        $profileSetting = $xml.CreateElement("ProfileSetting")

        # Add SettingNameInfo element
        $settingNameInfo = $xml.CreateElement("SettingNameInfo")
        $settingNameInfo.InnerText = "Frame Rate Limiter"
        $null = $profileSetting.AppendChild($settingNameInfo)

        # Add SettingID element
        $settingID = $xml.CreateElement("SettingID")
        $settingID.InnerText = "277041154"
        $null = $profileSetting.AppendChild($settingID)

        # Add SettingValue element using the passed $FPS argument
        $settingValue = $xml.CreateElement("SettingValue")
        $settingValue.InnerText = $FPS.ToString()
        $null = $profileSetting.AppendChild($settingValue)

        # Add ValueType element
        $valueType = $xml.CreateElement("ValueType")
        $valueType.InnerText = "Dword"
        $null = $profileSetting.AppendChild($valueType)

        # Append the new ProfileSetting to the Settings node
        $null = $settingsNode.AppendChild($profileSetting)

        # Save the updated XML back to the file
        $xml.Save($filePath)

        Write-Host "Frame Rate Limiter set to $FPS and added successfully."
    }
}

# Handle the -Delete argument
if ($Delete) {
    # Find the ProfileSetting with SettingNameInfo = "Frame Rate Limiter"
    $settingToDelete = @($settingsNode.ProfileSetting | Where-Object { $_.SettingID -eq "277041154" })

    if ($settingToDelete -and $settingToDelete.Count -gt 0) {
        # Remove the first matching ProfileSetting node
        $settingsNode.RemoveChild($settingToDelete[0]) > $null

        # Save the updated XML back to the file
        $xml.Save($filePath)

        Write-Host "Frame Rate Limiter setting deleted successfully."
    } elseif ($settingToDelete.Count -eq 0) {
        Write-Host "Frame Rate Limiter setting not found. No changes made."
    }
}

# If neither -Add nor -Delete are specified, print usage information
if (-not ($Add -or $Delete)) {
    Write-Host "Usage:"
    Write-Host "    -Add         : Add the Frame Rate Limiter setting with specified FPS value."
    Write-Host "    -Delete      : Delete the Frame Rate Limiter setting."
    Write-Host "    -FPS <value> : Specify the FPS value for the Frame Rate Limiter (default is 60)."
    Write-Host "    -filePath <path> : Specify the file path for the nip file that you wish to modify."
}