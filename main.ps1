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
$apiVersion = '2023-07-01-preview'

# Invoke API request to get templates
$templates = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$apiVersion"

# Filter templates to get rule templates
$ruleTemplates = $templates.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value' | Where-Object { $_.properties.contentKind -eq 'AnalyticsRule' }

# Get existing rules
$alertRulesJson =  Invoke-AzRestMethod -Method GET -path  "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
$alertRules = $alertRulesJson.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value'

# Output number of analytic rules found
Write-Host "$($ruleTemplates.count) Analytic Rules found"

# Loop through rule templates and create rules
foreach ($ruleTemplate in $ruleTemplates) {
    $templateRuleDisplayName = $ruleTemplate.properties.displayName
    Write-Host "Processing rule: $templateRuleDisplayName"
    # Verify if the rule already exists
    $ruleTemplateContentId = $ruleTemplate.properties.contentId
    $matchingRules =  $alertRules | Where-Object { $_.properties.alertRuleTemplateName -eq $ruleTemplateContentId }
    if (($matchingRules | Measure-Object | Select-Object -ExpandProperty Count) -gt 0) {
        Write-Host "Rule already exists`n" -ForegroundColor Yellow
        continue
    }    
    $ruleTemplateDetails = Invoke-AzRestMethod -Method GET -path ($ruleTemplate.id + '?api-version=' + $apiVersion)
    $newRule = $ruleTemplateDetails.Content | ConvertFrom-Json | Select-Object -ExpandProperty properties | Select-Object -ExpandProperty mainTemplate | Select-Object -ExpandProperty resources | Select-Object -First 1
    # Create and enable rule
    Write-Host "Creating and Enabling rule $templateRuleDisplayName... " -NoNewline
    $newRule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $ruleTemplateContentId
    $newRule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $ruleTemplate.version
    #$newRule.properties | Add-Member -NotePropertyName enabled -NotePropertyValue $true
    #$newRule.properties.enabled = $true
    $apiPath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleTemplateContentId)?api-version=$apiVersion"
    $payload = $newRule | ConvertTo-Json -Depth 99
    #$payload | Out-File "payload-$($ruleTemplateContentId).json"
    $result = Invoke-AzRestMethod -Method PUT -path $apiPath -Payload $payload
    if ($result.StatusCode -in 200, 201) {
        Write-Host "Done`n" -ForegroundColor Green
    } else {
        Write-Host ($result.Content + "`n") -ForegroundColor Red
    }
}
