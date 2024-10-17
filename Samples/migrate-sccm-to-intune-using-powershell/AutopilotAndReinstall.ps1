# Author: Marius Vika
# Version: 1.0
# Date: 06.05.2024
 
<# 
Description:
This script checks if the device is registered in Autopilot and updates the group tag if needed.
The script also registers the device in Autopilot if it is not already registered.
The script logs messages to a log file and uploads the log file to Azure Blob Storage.
#>
 
# Parameters 
$groupTag = "<YourGroupTag>"
$tenantId = "<YourTenantId>"
$clientId = "<YourClientId>"
$clientSecret = "<YourClientSecret>"
$storageUri = "https://<YourStorageAccount>.blob.core.windows.net"
$sasToken = "<YourSasToken>"
 
# Error tracker
$hasError = $false
 
# Get the serial number of the device
$serialNumber = (Get-CimInstance win32_bios).SerialNumber
 
# Get the current logged on user
$currentUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName)
 
# Log file path with serial number
$logFile = "C:\temp\sccm2intune\prepareautopilot\$serialNumber.log"
 
# Function to write messages to a log file
function Write-LogMessage {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logMessage
}
 
# Ensure the log file path exists
$logDir = Split-Path -Path $logFile -Parent
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}
 
# Function to get an access token
function Get-AccessToken {
    param (
        [string]$tenantId,
        [string]$clientId,
        [string]$clientSecret,
        [string]$scope
    )
    $body = @{
        client_id     = $clientId
        scope         = $scope
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    try {
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        return $response.access_token
    }
    catch {
        $hasError = $true
        Write-LogMessage "Failed to acquire access token: $_"
        throw $_
    }
}
 
# Function to get all Autopilot devices with pagination
function Get-AllAutopilotDevices {
    param (
        [string]$accessToken,
        [string]$graphEndpoint
    )
    $allDevices = @()
    $url = $graphEndpoint
    do {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $url -Headers @{
                Authorization = "Bearer $accessToken"
                ContentType   = "application/json"
            }
            $allDevices += $response.value
            $url = $response."@odata.nextLink"
        }
        catch {
            $hasError = $true
            Write-LogMessage "Failed to retrieve Autopilot devices: $_"
            throw $_
        }
    } while ($null -ne $url)
    return $allDevices
}
 
# Write log file to Azure Blob Storage
function Write-ToBlob {
    param (
        [string]$logFile,
        [string]$storageUri,
        [string]$sasToken
    )
    try {
        Write-LogMessage "Uploading log file to Azure Blob Storage..."
 
        # Get the File-Name without path
        $name = (Get-Item $logFile).Name
 
        # The target URL with SAS Token
        $uri = "$storageUri/prepareautopilot/$name" + "?$sasToken"
 
        # Define required Headers
        $headers = @{
            'x-ms-blob-type' = 'BlockBlob'
        }
 
        # Upload File
        Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -InFile $logFile
 
        Write-LogMessage "Log file uploaded successfully."
    }
    catch {
        $hasError = $true
        $errMsg = $_.Exception.Message
        Write-LogMessage "Error uploading log file: $errMsg"
        Write-Error $errMsg
    }
}
 
Try {
    Write-LogMessage "----------------------------------------------------------"
    Write-LogMessage "Log for Autopilot registration check and update script triggered"
    Write-LogMessage "Script started."
    Write-LogMessage "##############################"
    Write-LogMessage "Serial Number: $serialNumber"
    Write-LogMessage "Current Logged On User: $currentUser"
    Write-LogMessage "Autopilot Group Tag: $groupTag"
    Write-LogMessage "##############################"
 
    # Get access token
    Write-LogMessage "Getting access token..."
    $accessToken = Get-AccessToken -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret -scope "https://graph.microsoft.com/.default"
    $graphEndpoint = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"
 
    # Get all devices
    Write-LogMessage "Getting all Autopilot devices..."
    $allDevices = Get-AllAutopilotDevices -accessToken $accessToken -graphEndpoint $graphEndpoint
    Write-LogMessage "Total devices: $($allDevices.Count)"
 
    $isRegistered = $false
    $deviceId = $null
    $currentGroupTag = $null
 
    # Check if the device is registered in Autopilot
    Write-LogMessage "Checking if the device is registered in Autopilot..."
    foreach ($device in $allDevices) {
        if ($device.serialNumber -eq $serialNumber) {
            $isRegistered = $true
            $deviceId = $device.id
            $currentGroupTag = $device.groupTag
            break
        }
    }
 
    if ($isRegistered) {
        Write-LogMessage "Device is registered in Autopilot."
 
        if ($currentGroupTag -ne $groupTag) {
            Write-LogMessage "Group tag is incorrect. Group tag was $currentGroupTag. Updating group tag to $groupTag."
 
            $updateBody = @{
                groupTag = $groupTag
            } | ConvertTo-Json
 
            try {
                Invoke-RestMethod -Method Post -Uri "$graphEndpoint/$deviceId/updateDeviceProperties" -Body $updateBody -ContentType "application/json" -Headers @{
                    Authorization = "Bearer $accessToken"
                    ContentType   = "application/json"
                }
                Write-LogMessage "Group tag updated successfully."
            }
            catch {
                $hasError = $true
                Write-LogMessage "Failed to update group tag: $_"
                throw $_
            }
        }
        else {
            Write-LogMessage "Group tag is correct."
        }
    }
    else {
        Write-LogMessage "Device not registered in Autopilot. Registering device with group tag $groupTag..."
 
        try {
            # Install the Get-WindowsAutopilotInfo script
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
            Write-LogMessage "Installing NuGet"
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Force
            Write-LogMessage "Installing script Get-WindowsAutopilotInfo"
            Install-Script -Name Get-WindowsAutopilotInfo -Force
            Write-LogMessage "Done installing script Get-WindowsAutopilotInfo"
            #$ProgressPreference = 'SilentlyContinue'
 
            # Run the Get-WindowsAutopilotInfo script to upload the hardware hash
            try {
                Write-LogMessage "Attempting to register device in Autopilot"
                Get-WindowsAutoPilotInfo -Online -groupTag $groupTag -TenantId $tenantId -AppId $clientId -AppSecret $clientSecret

                Write-LogMessage "The Device successfully registered in Autopilot with group tag $groupTag.!"
            }
            catch {
                Write-LogMessage "Upload failed"
            }
        }
        catch {
            $hasError = $true
            $errMsg = $_.Exception.Message
            Write-LogMessage "Error during Get-WindowsAutoPilotInfo: $errMsg"
            Write-Error $errMsg
        }
    }
}
catch {
    $hasError = $true
    $errMsg = $_.Exception.Message
    Write-LogMessage "Error: $errMsg"
    Write-Error $errMsg
    Write-LogMessage "----------------------------------------------------------"
}
 
# Write log file to Azure Blob Storage
Write-ToBlob -logFile $logFile -storageUri $storageUri -sasToken $sasToken
 
Write-LogMessage "Autopilot registration check and update (if needed) completed."
Write-LogMessage "Script ended."
Write-LogMessage "----------------------------------------------------------"
Write-LogMessage ""
 


# Reset device when finished with Autopilot checks

$namespaceName = "root\cimv2\mdm\dmmap"
$className = "MDM_RemoteWipe"
$methodName = "doWipeMethod"
 
$session = New-CimSession
 
$params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
$param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create("param", "", "String", "In")
$params.Add($param)
 
$instance = Get-CimInstance -Namespace $namespaceName -ClassName $className -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
$session.InvokeMethod($namespaceName, $instance, $methodName, $params)

# Set exit code based on error tracker
if ($hasError) {
    Write-LogMessage "Script ended with errors."
    exit 1
} else {
    Write-LogMessage "Script ended successfully."
    exit 0
}