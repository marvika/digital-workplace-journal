# Install and import the necessary modules
Install-Module -Name Microsoft.Graph.Intune -Force -Scope CurrentUser
Import-Module Microsoft.Graph.Intune

# Connect to Microsoft Graph
Connect-MgGraph

# Define the script ID for the deployed Intune script
$scriptID = 'your-script-id'  # Replace with your actual script ID

# Retrieve the results of the script
$result = (Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/deviceManagementScripts/$scriptID/deviceRunStates?$expand=managedDevice").value

# Filter for successful results (errorCode = 0)
$success = $result | Where-Object -Property errorCode -EQ 0

# Parse the result messages and extract the hardware information
$parsedResults = $success | ForEach-Object {
    $hardwareInfo = [PSCustomObject]@{
        lastStateUpdateDateTime = $_.lastStateUpdateDateTime
        ComputerName            = ''
        Manufacturer            = ''
        Model                   = ''
        Processor               = ''
        TotalMemoryGB           = ''
    }
    
    # Try parsing the resultMessage JSON
    try {
        $json = $_.resultMessage | ConvertFrom-Json
        $hardwareInfo.ComputerName  = $json.ComputerName
        $hardwareInfo.Manufacturer  = $json.Manufacturer
        $hardwareInfo.Model         = $json.Model
        $hardwareInfo.Processor     = $json.Processor
        $hardwareInfo.TotalMemoryGB = $json.TotalMemoryGB
    }
    catch {
        Write-Warning "Failed to parse JSON for $_.lastStateUpdateDateTime"
    }
    
    # Return the parsed hardware information object
    $hardwareInfo
}

# Display the parsed results in a formatted table
$parsedResults | Format-Table lastStateUpdateDateTime, ComputerName, Manufacturer, Model, Processor, TotalMemoryGB -AutoSize

# Export the parsed results to a CSV file
$csvFilePath = "./ExportedHardwareInfo.csv"  # Replace with your desired file path
$parsedResults | Export-Csv -Path $csvFilePath -NoTypeInformation

Write-Host "Parsed hardware information has been exported to $csvFilePath"
