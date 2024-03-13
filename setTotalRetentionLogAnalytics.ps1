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

$desiredRetention = Read-Host -Prompt "Enter the desired total retention (interactive retention plus archive retention) period in days (default is 365)" -Default 365

# Notify the user how many tables are not set to 365 days and prompt the user if they would like to update the retention period
$non365Tables = $tablesResponse | Where-Object { $_.properties.totalRetentionInDays -ne $desiredRetention }
if ($non365Tables.Count -eq 0) {
    Write-Host "All tables have totalRetentionInDays set to $desiredRetention. No action required." -ForegroundColor Green
} else {
    $updateRetention = Read-Host -Prompt "There are $($non365Tables.Count) tables with totalRetentionInDays not set to $desiredRetention. Would you like to update the retention period? (Y/N)"
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
            if ($table.properties.totalRetentionInDays -eq $desiredRetention) {
                Write-Host "Table $tableId already has totalRetentionInDays set to $desiredRetention. Skipping..."
                continue
            }

            # Set the totalRetentionInDays to 365
            $tableUri = $tableId + "?api-version=$apiVersion"
            $tableProperties = @{
                properties = @{
                    totalRetentionInDays = $desiredRetention
                }
            }
            Write-Host "Setting totalRetentionInDays to $desiredRetention for table $tableId"
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
