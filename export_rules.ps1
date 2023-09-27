# Define required modules
$modules = @('Az.Accounts', 'Az.SecurityInsights', 'Az.Resources')

# Check if modules exist and install if needed
foreach ($module in $modules) {
    if (!(Get-Module -ListAvailable $module)) {
        Write-Host "Installing $module module" -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -AllowClobber -Force
    }
}

# Import modules
foreach ($module in $modules) {
    Write-Host "Importing $module module" -ForegroundColor Yellow
    Import-Module $module -ErrorAction Stop
}

# Login to Azure
if(!(Get-AzContext)) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
}

# Display all subscriptions for the logged in user
Get-AzSubscription | Select-Object Name, Id | Format-Table

# Select the subscription to use
if(!$subscriptionId) {
    $subscriptionId = Read-Host -Prompt 'Enter the subscription ID (leave blank to select first subscription id)'
}
if ($subscriptionId -eq '') {
    $subscriptionId = Get-AzSubscription | Select-Object -First 1 -ExpandProperty Id
}
Set-AzContext -SubscriptionId $subscriptionId

# List all sentinel resources
$sentinelWorkspaces = Get-AzResource -ResourceType Microsoft.OperationalInsights/workspaces | Select-Object Name, ResourceGroupName, Location
$sentinelWorkspaces | Format-Table

# Select the sentinel workspace to use
if(!$workspaceName) {
    $workspaceName = Read-Host -Prompt 'Enter the workspace name (leave blank to select first workspace name)'
}
if ($workspaceName -eq '') {
    $workspaceName = $sentinelWorkspaces | Select-Object -First 1 -ExpandProperty Name
}

# Select the resource group to use
$sentinelWorkspaces | Where-Object Name -eq $workspaceName | Select-Object -ExpandProperty ResourceGroupName | Format-Table
if(!$resourceGroupName) {
    $resourceGroupName = Read-Host -Prompt 'Enter the resource group name (leave blank to select first resource group name)'
}
if ($resourceGroupName -eq '') {
    $resourceGroupName = $sentinelWorkspaces | Where-Object Name -eq $workspaceName | Select-Object -First 1 -ExpandProperty ResourceGroupName
}

# Set API version
$apiVersion = '2023-06-01-preview'

# Invoke API request to get alerts
$alerts = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"

$alerts = $alerts.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value' | Where-Object { $_.kind -in @('Scheduled', 'NRT') }

# Output number of  rules found
Write-Host "$($alerts.count) Rules found"

$apiVersion = '2023-02-01'
# Loop through aleert rules and export as arm templates
foreach ($alert in $alerts) {
    Write-Host "Processing rule $($alert.properties.displayName)"
    $alertIDshort = $alert.id.Split('/')[-1]
    $resourceGroupName = $alert.id.Split('/')[4]
    $arm = new-object -TypeName PSObject
    $arm | Add-Member -NotePropertyName '$schema' -NotePropertyValue 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    $arm | Add-Member -NotePropertyName 'contentVersion' -NotePropertyValue '1.0.0.0'
    $arm | Add-Member -NotePropertyName 'parameters' -NotePropertyValue @{
        'workspace' = @{
            'type' = 'String'
            'defaultValue' = $workspaceName
        };
        'resourceGroupName' = @{
            'type' = 'String'
            'defaultValue' = $resourceGroupName
        };
        'analytic-id' = @{
            'type' = 'string'
            'defaultValue' = $alertIDshort
            'minLength' = 1
            'metadata' = @{
                'description' = 'Unique id for the scheduled alert rule'
            }
        }
    }
    $alert | Add-Member -NotePropertyName 'apiVersion' -NotePropertyValue $apiVersion
    #$alertID = $alert.id -split '/'
    #$alert.id = ($alertID[0..4] + $alertID[-4..-1]) -join '/'
    $alert.type = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
    $alert.name = $workspaceName + '/Microsoft.SecurityInsights/' + $alertIDshort
    $alert.PSObject.Properties.Remove('etag')
    $alert.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $resources = @($alert)
    $arm | Add-Member -NotePropertyName 'resources' -NotePropertyValue $resources
    $arm | ConvertTo-Json -Depth 99 | Out-File -FilePath "Detections\$($alertIDshort).json"
}

