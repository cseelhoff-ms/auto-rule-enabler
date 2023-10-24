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
Connect-AzAccount -ErrorAction Stop | Out-Null

# Display all subscriptions for the logged in user
Get-AzSubscription | Select-Object Name, Id | Format-Table

# if there is only 1 subscription, select it, otherwise prompt the user to select a subscription
if ((Get-AzSubscription).Count -eq 1) {
    $subscriptionId = Get-AzSubscription | Select-Object -First 1 -ExpandProperty Id
} else {
    $subscriptionId = Read-Host -Prompt 'Enter the subscription ID:'
    Set-AzContext -SubscriptionId $subscriptionId
}

#get az resource for all solutions with the name starting with SecurityInsights(
$securityInsightsSolutions = Get-AzResource -ResourceType Microsoft.OperationsManagement/solutions | Where-Object { $_.Name -like 'SecurityInsights(*' } | Select-Object -ExpandProperty Name | ForEach-Object { $_.Substring(17, $_.length -18) }

# get all workspaces that are installed with sentinel
$workspaces = Get-AzResource -ResourceType Microsoft.OperationalInsights/workspaces
$sentinelWorkspaces = $workspaces | Where-Object { $_.Name -in $securityInsightsSolutions }
$sentinelWorkspaces | Select-Object Name, ResourceGroupName, Location | Format-Table

# if there is only 1 workspace, select it, otherwise prompt the user to select a workspace
if ($sentinelWorkspaces.Count -eq 1) {
    $workspaceName = $sentinelWorkspaces | Select-Object -First 1 -ExpandProperty Name
} else {
    $workspaceName = Read-Host -Prompt 'Enter the workspace name:'
}

$resourceGroupName = $sentinelWorkspaces | Where-Object Name -eq $workspaceName | Select-Object -ExpandProperty ResourceGroupName

# Set API version
$apiVersion = '2023-06-01-preview'

# Invoke API request to get alerts
$alerts = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"

$alerts = $alerts.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value' | Where-Object { $_.kind -in @('Scheduled', 'NRT') }

# Output number of  rules found
Write-Host "$($alerts.count) Rules found"

$apiVersion = '2023-02-01'
# Loop through alert rules and export as arm templates
foreach ($alert in $alerts) {
    Write-Host "Processing rule $($alert.properties.displayName)"
    $alertIDshort = $alert.id.Split('/')[-1]
    #$resourceGroupName = $alert.id.Split('/')[4]
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
    #$alert.name = $workspaceName + '/Microsoft.SecurityInsights/' + $alertIDshort
    $alert.name = $alertIDshort
    $alert.PSObject.Properties.Remove('etag')
    $alert.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $resources = @($alert)
    $arm | Add-Member -NotePropertyName 'resources' -NotePropertyValue $resources
    $arm | ConvertTo-Json -Depth 99 | Out-File -FilePath "Detections\$($alertIDshort).json"
}

