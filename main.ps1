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

# Set API version
$apiVersion = '2022-10-01'

# Get the list of tables in the workspace
$tablesUri = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/tables?api-version=$apiVersion"
$tablesResponse = Invoke-AzRestMethod -Method GET -Path $tablesUri | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty value

# Iterate through each table
$totalTables = $tablesResponse.Count

# Notify the user how many tables are not set to 365 days and prompt the user if they would like to update the retention period
$non365Tables = $tablesResponse | Where-Object { $_.properties.totalRetentionInDays -ne 365 }
if ($non365Tables.Count -eq 0) {
    Write-Host "All tables have totalRetentionInDays set to 365. No action required." -ForegroundColor Green
} else {
    $updateRetention = Read-Host -Prompt "There are $($non365Tables.Count) tables with totalRetentionInDays not set to 365. Would you like to update the retention period? (Y/N)"
    if ($updateRetention -eq 'Y') {       

        $currentTable = 0
        $jobs = @()

        foreach ($table in $tablesResponse) {
            # Extract the table name from the id
            $tableId = $table.id
            # Update the progress bar
            $currentTable++
            $progress = @{
                Activity = "Updating tables"
                Status = "Processing table $currentTable of $totalTables"
                PercentComplete = ($currentTable / $totalTables) * 100
            }
            Write-Progress @progress

            # Check if totalRetentionInDays is already 365
            if ($table.properties.totalRetentionInDays -eq 365) {
                Write-Host "Table $tableId already has totalRetentionInDays set to 365. Skipping..."
                continue
            }

            # Set the totalRetentionInDays to 365
            $tableUri = $tableId + "?api-version=$apiVersion"
            $tableProperties = @{
                properties = @{
                    totalRetentionInDays = 365
                }
            }
            Write-Host "Setting totalRetentionInDays to 365 for table $tableId"
            $jobs += Start-Job -ScriptBlock {
                param($tableUri, $tableProperties)
                Invoke-AzRestMethod -Method PATCH -Path $tableUri -Payload ($tableProperties | ConvertTo-Json -Depth 2)
            } -ArgumentList $tableUri, $tableProperties

            # If we've reached the maximum number of concurrent jobs, wait for one to finish before starting a new one
            if ($jobs.Count -ge 10) {
                $finishedJob = $jobs | Wait-Job -Any
                $jobs = $jobs | Where-Object -Property Id -NE $finishedJob.Id
                $null = $finishedJob | Receive-Job
                $finishedJob | Remove-Job
            }
        }

        # Wait for all remaining jobs to complete
        $null = $jobs | Wait-Job | Receive-Job

        # Clean up the jobs
        $jobs | Remove-Job
    }
}

# Check if UEBA is enabled
$uebaSettings  = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/settings/Ueba?api-version=$apiVersion"
# if UEBA was not found, then prompt the user if they would like to enable UEBA
if ($uebaSettings.StatusCode -eq 404 -or $uebaSettings.StatusCode -eq 400) {
    Write-Host "UEBA is not enabled for the workspace. Please navigate to the URL: https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/EntityDataSourcesBlade/id/EntityDataSourcesBlade/workspaceName/$workspaceName/resourceGroup/$resourceGroupName/subscriptionId/$subscriptionId to enable UEBA." -ForegroundColor Yellow
    Read-Host -Prompt "Press Enter to continue"
}

$EntityAnalyticsSettings = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/settings/EntityAnalytics?api-version=$apiVersion"
$entityProviders = $EntityAnalyticsSettings.Content | ConvertFrom-Json | Select-Object -ExpandProperty properties | Select-Object -ExpandProperty entityProviders
#if $entityProviders does not contain 'ActiveDirectory' and 'AzureActiveDirectory' then prompt the user if they would like to enable UEBA
if ($entityProviders -notcontains 'AzureActiveDirectory') {
    $enableUEBA = Read-Host -Prompt 'UEBA is not enabled for Entra ID (AzureActiveDirectory). Would you like to enable it now? (Y/N)'
    if ($enableUEBA -eq 'Y') {
        $uebaSettings.Content | ConvertFrom-Json | Select-Object -ExpandProperty properties | Add-Member -NotePropertyName entityProviders -NotePropertyValue @('AzureActiveDirectory')
        $payload = $uebaSettings.Content | ConvertTo-Json -Depth 99
        $result = Invoke-AzRestMethod -Method PUT -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/settings/EntityAnalytics?api-version=$apiVersion" -Payload $payload
        if ($result.StatusCode -in 200, 201) {
            Write-Host "UEBA has been enabled for Entra ID (AzureActiveDirectory)." -ForegroundColor Green
        } else {
            Write-Host ($result.Content + "`n") -ForegroundColor Red
        }
    }
}

# Get a list of installed content hub objects
$apiVersion = '2023-04-01-preview'
$installedContentJSON = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$apiVersion"
$installedContent = $installedContentJSON.Content | ConvertFrom-Json | Select-Object -ExpandProperty value
$installedContent | Select-Object -ExpandProperty properties | Select-Object -Property contentId, displayName, installedVersion, @{Name='authorName'; Expression={$_.author.name}} | ConvertTo-Json | Out-File installed.json

#read installed.json file
$contentToInstall = Get-Content installed.json | ConvertFrom-Json
$contentToInstall | Out-GridView

# Invoke API request to get templates
$templates = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$apiVersion"

# Filter templates to get rule templates
$ruleTemplates = $templates.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value' | Where-Object { $_.properties.contentKind -eq 'AnalyticsRule' }

# Get existing rules
$alertRulesJson =  Invoke-AzRestMethod -Method GET -path  "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
$alertRules = $alertRulesJson.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value'

# Output number of analytic rules found
Write-Host "$($ruleTemplates.count) Analytic Rules found"
# Initialize job array and counter
$jobs = @()
$currentJob = 0

# Loop through rule templates and create rules
foreach ($ruleTemplate in $ruleTemplates) {
    # Start a new job for each rule template
    $jobs += Start-Job -ScriptBlock {
        param($ruleTemplate, $alertRules, $subscriptionId, $resourceGroupName, $workspaceName, $apiVersion)

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
        Write-Host "Creating rule $templateRuleDisplayName... " -NoNewline
        $newRule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $ruleTemplateContentId
        $newRule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $ruleTemplate.version
        $apiPath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleTemplateContentId)?api-version=$apiVersion"
        $payload = $newRule | ConvertTo-Json -Depth 99
        $result = Invoke-AzRestMethod -Method PUT -path $apiPath -Payload $payload
        if ($result.StatusCode -in 200, 201) {
            Write-Host "Rule $templateRuleDisplayName has been created`n" -ForegroundColor Green
        } else {
            Write-Host ($result.Content + "`n") -ForegroundColor Red
        }
        # enable the rule
        $ruleId = $result.Content | ConvertFrom-Json | Select-Object -ExpandProperty id
        $enableRule = Invoke-AzRestMethod -Method POST -path ($ruleId + '/enable?api-version=' + $apiVersion)
        if ($enableRule.StatusCode -in 200, 201) {
            Write-Host "Rule $templateRuleDisplayName has been enabled`n" -ForegroundColor Green
        } else {
            Write-Host ($enableRule.Content + "`n") -ForegroundColor Red
        }

    } -ArgumentList $ruleTemplate, $alertRules, $subscriptionId, $resourceGroupName, $workspaceName, $apiVersion

    # Update the progress bar
    $currentJob++
    $progress = @{
        Activity = "Creating and enabling rules"
        Status = "Processing rule $currentJob of $($ruleTemplates.Count)"
        PercentComplete = ($currentJob / $ruleTemplates.Count) * 100
    }
    Write-Progress @progress

    # If we've reached the maximum number of concurrent jobs, wait for one to finish before starting a new one
    if ($jobs.Count -ge 10) {
        $finishedJob = $jobs | Wait-Job -Any
        $jobs = $jobs | Where-Object -Property Id -NE $finishedJob.Id
        $null = $finishedJob | Receive-Job
        $finishedJob | Remove-Job
    }
}

# Wait for all remaining jobs to complete
$null = $jobs | Wait-Job | Receive-Job

# Clean up the jobs
$jobs | Remove-Job

