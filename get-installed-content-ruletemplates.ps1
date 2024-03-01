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
    $subscriptionId = Read-Host -Prompt 'Enter the subscription ID'
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
    $workspaceName = Read-Host -Prompt 'Enter the workspace name'
}

$resourceGroupName = $sentinelWorkspaces | Where-Object Name -eq $workspaceName | Select-Object -ExpandProperty ResourceGroupName

# Get a list of installed content hub objects
$apiVersion = '2023-04-01-preview'
$installedContentJSON = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$apiVersion"
$installedContent = $installedContentJSON.Content | ConvertFrom-Json | Select-Object -ExpandProperty value

$apiVersion = '2023-04-01-preview'
$results = New-Object System.Collections.ArrayList
foreach($content in $installedContent) {
    if ($content.properties.installedVersion -eq $null) {
        continue
    }
    $contentName = $content.properties.displayName
    Write-Host "Checking $contentName"
    foreach($dependency in $content.properties.dependencies.criteria) {
        if($dependency.kind -eq 'AnalyticsRule') {
            $contentId = $dependency.contentId
            $kind = $dependency.kind
            Write-Host $kind
            $ruleTemplate = Invoke-AzRestMethod -Method GET -path ("/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates/$contentId" + '?api-version=' + $apiVersion)
            $ruleDisplayName = $ruleTemplate.Content | ConvertFrom-Json | Select-Object -ExpandProperty properties | Select-Object -ExpandProperty displayName
            $results.add([PSCustomObject]@{
                DisplayName = $contentName
                contentId = $contentId
                kind = $kind
                RuleName = $ruleDisplayName
            })
        }
    }
}
$results | Export-Csv -Path 'installed-content-ruletemplates.csv' -NoTypeInformation
