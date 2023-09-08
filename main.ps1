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
$subscriptionid = Read-Host -Prompt 'Enter the subscription ID (leave blank to select first subscription id)'
if ($subscriptionid -eq '') {
    $subscriptionid = (Get-AzSubscription)[0].Id
}
Set-AzContext -SubscriptionId $subscriptionid

# List all sentinel resources
$sentinelWorkspaces = Get-AzResource -ResourceType Microsoft.OperationalInsights/workspaces | Select-Object Name, ResourceGroupName, Location
$sentinelWorkspaces | Format-Table

# Select the sentinel workspace to use
$workspaceName = Read-Host -Prompt 'Enter the workspace name (leave blank to select first workspace name)'
if ($workspaceName -eq '') {
    $workspaceName = $sentinelWorkspaces[0].Name
}
$resourceGroupName = ($sentinelWorkspaces | Where-Object Name -eq $workspaceName).ResourceGroupName

# Get access token
$token = Get-AzAccessToken

# Set headers for API request
$headers = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}

# Set API version
$apiVersion = '2023-06-01-preview'

# Set API URI
$URI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$apiVersion"

# Invoke API request to get templates
$response = Invoke-RestMethod -Uri $URI -Method GET -Headers $headers
$templates = $response.value

# Filter templates to get rule templates
$ruleTemplates = $templates | Where-Object { $_.properties.contentKind -eq 'AnalyticsRule' }

# Output number of analytic rules found
Write-Host "$($ruleTemplates.count) Analytic Rules found"

# Loop through rule templates and create rules
foreach ($ruleTemplate in $ruleTemplates) {
    $ruleId = $ruleTemplate.Properties.contentId
    $rule = $ruleTemplate.properties.mainTemplate.resources | Where-Object type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates'
    $rule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $ruleId
    $rule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $template.version
    $rule.properties.enabled = $true
    $payload = $rule | ConvertTo-Json -Depth 99

    # Verify if the rule already exists
    $apiPath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleId)?api-version=$apiVersion"
    $result = Invoke-AzRestMethod -Method GET -path $apiPath
    if ($result.StatusCode -ne 404) {
        Write-Host "Rule $($rule.properties.displayName) already exists" -ForegroundColor Yellow
        continue
    }

    # Create and enable rule
    Write-Host "Creating and Enabling rule $($rule.properties.displayName)... " -NoNewline
    $result = Invoke-AzRestMethod -Method PUT -path $apiPath -Payload $payload
    if ($result.StatusCode -in 200, 201) {
        Write-Host "Done" -ForegroundColor Green
    } else {
        Write-Host "Error: $($result.Content)" -ForegroundColor Red
    }
}
