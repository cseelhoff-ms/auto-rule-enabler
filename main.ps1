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
    Import-Module $module -ErrorAction Stop
}

# Login to Azure
Connect-AzAccount -ErrorAction Stop | Out-Null

# Display all subscriptions for the logged in user
Get-AzSubscription | Select-Object Name, Id | Format-Table

# Select the subscription to use
$subscriptionId = Read-Host -Prompt 'Enter the subscription ID (leave blank to select first subscription id)'
if ($subscriptionId -eq '') {
    $subscriptionId = Get-AzSubscription | Select-Object -First 1 -ExpandProperty Id
}
Set-AzContext -SubscriptionId $subscriptionId

# List all sentinel resources
$sentinelWorkspaces = Get-AzResource -ResourceType Microsoft.OperationalInsights/workspaces | Select-Object Name, ResourceGroupName, Location
$sentinelWorkspaces | Format-Table

# Select the sentinel workspace to use
$workspaceName = Read-Host -Prompt 'Enter the workspace name (leave blank to select first workspace name)'
if ($workspaceName -eq '') {
    $workspaceName = $sentinelWorkspaces | Select-Object -First 1 -ExpandProperty Name
}
$resourceGroupName = $sentinelWorkspaces | Where-Object Name -eq $workspaceName | Select-Object -ExpandProperty ResourceGroupName

# Set API version
$apiVersion = '2023-06-01-preview'

# Invoke API request to get templates
$templates = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$apiVersion"

# Filter templates to get rule templates
$ruleTemplates = $templates.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value' | Where-Object { $_.properties.contentKind -eq 'AnalyticsRule' }

# Output number of analytic rules found
Write-Host "$($ruleTemplates.count) Analytic Rules found"

# Loop through rule templates and create rules
foreach ($ruleTemplate in $ruleTemplates) {
    $ruleId = $ruleTemplate.properties.contentId
    $rule = $ruleTemplate.properties.mainTemplate.resources | Where-Object type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates' | Select-Object -First 1
    $ruleName = $rule.properties.displayName

    # Verify if the rule already exists
    $apiPath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleId)?api-version=$apiVersion"
    $result = Invoke-AzRestMethod -Method GET -path $apiPath
    if ($result.StatusCode -ne 404) {
        Write-Host "Rule $ruleName already exists" -ForegroundColor Yellow
        continue
    }

    # Create and enable rule
    Write-Host "Creating and Enabling rule $ruleName... " -NoNewline
    $rule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $ruleId
    $rule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $ruleTemplate.version
    $rule.properties.enabled = $true
    $payload = $rule | ConvertTo-Json -Depth 99
    $result = Invoke-AzRestMethod -Method PUT -path $apiPath -Payload $payload
    if ($result.StatusCode -in 200, 201) {
        Write-Host "Done" -ForegroundColor Green
    } else {
        Write-Host $result.Content -ForegroundColor Red
    }
}
