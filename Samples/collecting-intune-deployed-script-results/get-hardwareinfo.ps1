# Retrieve system information using WMI
$systemInfo = Get-WmiObject -Class Win32_ComputerSystem
$processorInfo = Get-WmiObject -Class Win32_Processor

# Extract relevant properties
$manufacturer = $systemInfo.Manufacturer
$model = $systemInfo.Model
$processor = $processorInfo.Name
$totalMemoryGB = [math]::round($systemInfo.TotalPhysicalMemory / 1GB, 2)

# Organize the data into a hash table
$hardwareInfo = @{
    ComputerName     = $env:COMPUTERNAME
    Manufacturer     = $manufacturer
    Model            = $model
    Processor        = $processor
    TotalMemoryGB    = $totalMemoryGB
}

# Convert the hardware information to JSON format for easy parsing
$hardwareInfoJson = $hardwareInfo | ConvertTo-Json

# Output the JSON string
Write-Output $hardwareInfoJson