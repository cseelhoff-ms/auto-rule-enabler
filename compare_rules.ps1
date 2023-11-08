# Set API version
$exportSentinelRulesAsJson = $false
$apiVersion = '2023-06-01-preview'

function Get-AccessToken {
    param(
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$tenantId,
        [Parameter(Mandatory=$true)]
        [string]$scope
    )
    $bodyDeviceCode = (
        "client_id=$clientId" +
        "&scope=$scope"
    )
    $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"
    $deviceCodeResponse = Invoke-RestMethod -Method Post -Uri $uri -Body $bodyDeviceCode
    Write-Host($deviceCodeResponse.message)
    $secondsUntilVerificationExpires = $deviceCodeResponse.expires_in
    $secondsBetweenVerificationChecks = $deviceCodeResponse.interval
    $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    $device_code = $deviceCodeResponse.device_code
    $bodyToken = (
        "tenant=$tenantId" +
        "&grant_type=$grant_type" +
        "&client_id=$clientId" +
        "&device_code=$device_code"
    )
    while($secondsUntilVerificationExpires -gt 0) {
        Start-Sleep -Seconds $secondsBetweenVerificationChecks
        $secondsUntilVerificationExpires -= $secondsBetweenVerificationChecks
        try {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $uri -Body $bodyToken
            $accessToken = $tokenResponse.access_token
            break
        } catch {
            $errorDetails = $_.ErrorDetails
            $errorMessage = $errorDetails.Message | ConvertFrom-Json | Select-Object -ExpandProperty error
            if($errorMessage -eq "authorization_pending") {
                Write-Host "authorization_pending"
                continue
            } else {
                Write-Error $errorDetails.Message
                break
            }
        }
    }
    return $accessToken
}

function Get-ExpirationTime {
    param(
        [Parameter(Mandatory=$true)]
        [string]$accessToken
    )
    $tokenheader = $accessToken.Split(".")[0].Replace('-', '+').Replace('_', '/')
    $tokenheader = $accessToken.Split(".")[0].Replace('-', '+').Replace('_', '/')
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    $tokenPayload = $accessToken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArrayJson = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokenArrayObject = $tokenArrayJson | ConvertFrom-Json
    return $tokenArrayObject.exp
}

if($expires -lt ((New-TimeSpan -Start (Get-Date '1970-01-01 00:00:00') -End ((Get-Date).ToUniversalTime())).TotalSeconds) + 600) {
    Add-Type -AssemblyName System.Web
    $clientId = "e1ab09b4-7b37-46ee-b1cf-1c07469b26d2"
    $tenantId = "00ac9db9-508a-473b-aded-53250025bd24"

    $scope = [System.Web.HttpUtility]::UrlEncode("https://management.azure.com/user_impersonation")
    $accessToken = Get-AccessToken -clientId $clientId -tenantId $tenantId -scope $scope    
    $azureManagementHeaders = @{"Authorization" = "Bearer $accessToken"}
    $expires = Get-ExpirationTime -accessToken $accessToken

    #$scope = [System.Web.HttpUtility]::UrlEncode("https://api.securitycenter.windows.com/Alert.Read")
    #$accessToken = Get-AccessToken -clientId $clientId -tenantId $tenantId -scope $scope    
    #$securityCenterHeaders = @{"Authorization" = "Bearer $accessToken"}
}

if($null -eq $resourceGroupName) {
    # Display all subscriptions for the logged in user
    $uri = "https://management.azure.com/subscriptions?api-version=2023-07-01"
    $subscriptions = Invoke-RestMethod -Method GET -Uri $uri -Headers $azureManagementHeaders
    $subscriptions = $subscriptions.value
    $subscriptions | Select-Object displayName, subscriptionId | Format-Table

    # if there is only 1 subscription, select it, otherwise prompt the user to select a subscription
    if ((Get-AzSubscription).Count -eq 1) {
        $subscriptionId = $subscriptions | Select-Object -First 1 -ExpandProperty subscriptionId
    } else {
        $subscriptionId = Read-Host -Prompt 'Enter the subscription ID:'
    }

    #get az resource for all solutions with the name starting with SecurityInsights(
    $uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.OperationsManagement/solutions?api-version=2015-11-01-preview"
    $securityInsightsSolutions = Invoke-RestMethod -Method GET -Uri $uri -Headers $azureManagementHeaders 
    $securityInsightsSolutions = $securityInsightsSolutions.value | Where-Object { $_.Name -like 'SecurityInsights(*' } | Select-Object -ExpandProperty Name | ForEach-Object { $_.Substring(17, $_.length -18) }

    # get all workspaces that are installed with sentinel
    $uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
    $workspaces = Invoke-RestMethod -Method GET -Uri $uri -Headers $azureManagementHeaders
    $workspaces = $workspaces.value
    $sentinelWorkspaces = $workspaces | Where-Object { $_.Name -in $securityInsightsSolutions }
    $sentinelWorkspaces | Select-Object name, location | Format-Table

    # if there is only 1 workspace, select it, otherwise prompt the user to select a workspace
    if ($sentinelWorkspaces.Count -eq 1) {
        $workspaceName = $sentinelWorkspaces | Select-Object -First 1 -ExpandProperty Name
    } else {
        $workspaceName = Read-Host -Prompt 'Enter the workspace name:'
    }
    $sentinelWorkspacesId = $sentinelWorkspaces | Where-Object Name -eq $workspaceName | Select-Object -ExpandProperty id
    $resourceGroupName = ($sentinelWorkspacesId | Select-String -Pattern "/resourceGroups/([^/]+)").Matches.Groups[1].Value
}

# Invoke API request to get alerts
$uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"
$alerts = Invoke-RestMethod -Method GET -Uri $uri -Headers $azureManagementHeaders
$alerts = $alerts.value | Where-Object { $_.kind -in @('Scheduled', 'NRT') }

# Output number of  rules found
Write-Host "$($alerts.count) Rules found"

# Loop through alert rules and export as arm templates
$formattedAlerts = @{}
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
    #$alert | Add-Member -NotePropertyName 'apiVersion' -NotePropertyValue $apiVersion
    #$alertID = $alert.id -split '/'
    #$alert.id = ($alertID[0..4] + $alertID[-4..-1]) -join '/'
    $alert.type = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
    #$alert.name = $workspaceName + '/Microsoft.SecurityInsights/' + $alertIDshort
    $alert.name = $alertIDshort
    $alert.PSObject.Properties.Remove('etag')
    $alert.properties.PSObject.Properties.Remove('lastModifiedUtc')
    $resources = @($alert)
    $arm | Add-Member -NotePropertyName 'resources' -NotePropertyValue $resources
    $formattedAlerts.Add($alertIDshort, $resources)
    if($exportSentinelRulesAsJson) {
        $arm | ConvertTo-Json -Depth 99 | Out-File -FilePath "detections\$($alertIDshort).json"
    }
}

#loop through each json in detections folder, and compare to the formatted alerts
$detections = Get-ChildItem -Path detections -Filter *.json

function Compare-PSObjects {
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$Object1,
        [Parameter(Mandatory=$true)]
        [PSObject]$Object2
    )

    $differences = @()

    # Compare properties of Object1 to Object2
    #create an empty hashtable to store all unique properties of object1 and object2
    $properties = @{}
    foreach ($property in $Object1.PSObject.Properties) {
        $propertyName = $property.Name
        if($propertyName.Trim() -in @('LongLength', 'Rank', 'SyncRoot', 'IsReadOnly', 'IsFixedSize', 'IsSynchronized', '')) {
            continue
        }
        $properties.Add($propertyName, $null)
    }
    foreach ($property in $Object2.PSObject.Properties) {
        $propertyName = $property.Name
        if($propertyName.Trim() -in @('LongLength', 'Rank', 'SyncRoot', 'IsReadOnly', 'IsFixedSize', 'IsSynchronized', '') -or $properties.ContainsKey($propertyName)) {
            continue
        }
        $properties.Add($propertyName, $null)
    }
    #loop through each property and compare
    foreach ($property in $properties.Keys) {
        $propertyValue1 = $Object1.$property
        $propertyValue2 = $Object2.$property

        if ($propertyValue1 -is [PSObject] -and $propertyValue2 -is [PSObject]) {
            # Recursively compare nested PSObjects
            $nestedDifferences = Compare-PSObjects $propertyValue1 $propertyValue2
            if ($nestedDifferences.Count -gt 0) {
                foreach($nestedDifference in $nestedDifferences) {
                    $nestedDifference.Property = "$property.$($nestedDifference.Property)"
                }
                $differences += $nestedDifferences
            }
        } elseif ($propertyValue1 -is [System.Collections.IList] -and $propertyValue2 -is [System.Collections.IList]) {
            # Compare lists
            if ($propertyValue1.Count -ne $propertyValue2.Count) {
                # Add property name and values to list of differences
                $difference = [PSCustomObject]@{
                    Property = $property
                    Value1 = $propertyValue1
                    Value2 = $propertyValue2
                }
                $differences += $difference
            } else {
                for ($i = 0; $i -lt $propertyValue1.Count; $i++) {
                    $nestedDifferences = Compare-PSObjects $propertyValue1[$i] $propertyValue2[$i]
                    if ($nestedDifferences.Count -gt 0) {
                        $differences += $nestedDifferences | ForEach-Object { "$property[$i].$_" }
                    }
                }
            }
        } elseif ($propertyValue1 -ne $propertyValue2) {
            # Add property name and values to list of differences
            $difference = [PSCustomObject]@{
                Property = $property
                Value1 = $propertyValue1
                Value2 = $propertyValue2
            }
            $differences += $difference
        }
    }
    return $differences
}


$rulesWithDifferences = @{}
foreach ($detection in $detections) {
    $detectionName = $detection.Name.Split('.')[0]
    if ($formattedAlerts.ContainsKey($detectionName)) {
        $formattedAlert = $formattedAlerts[$detectionName]
        $detectionContent = Get-Content $detection.FullName | ConvertFrom-Json | Select-Object -ExpandProperty resources
        $differences = Compare-PSObjects $formattedAlert $detectionContent
        if ($differences.Count -gt 0) {
            #$differences | Format-Table
            #Write-Host "There are differences between the objects: $detectionName" -ForegroundColor Yellow
            $arrayOfDifferences = New-Object System.Collections.ArrayList
            foreach ($difference in $differences) {
                $null = $arrayOfDifferences.Add([PSCustomObject]@{
                    ruleName = $detectionName
                    property = $difference.Property
                    sentinel = $difference.Value1
                    repo = $difference.Value2
                })
            }
            $rulesWithDifferences.Add($detectionName, $arrayOfDifferences)
            #$detectionName
            #$arrayOfDifferences | Format-Table
        } else {
            #Write-Host "The objects are identical for: $detectionName"
        }
    } else {
        #Write-Host "The object does not exist in the repo: $detectionName" -ForegroundColor Yellow
        $arrayOfDifferences = New-Object System.Collections.ArrayList
        $null = $arrayOfDifferences.Add(
        [PSCustomObject]@{
            ruleName = $detectionName
            property = '(NEW)'
            sentinel = '(null)'
            repo = '(NEW)'
        })
        $rulesWithDifferences.Add($detectionName, $arrayOfDifferences)
        #$detectionName
        #$arrayOfDifferences | Format-Table
    }
}

$rulesWithDifferences.Values | Format-Table
$uri = 'https://prod-85.eastus.logic.azure.com:443/workflows/5d28dc4c29c04cea85032c20659b5c33/triggers/manual/paths/invoke?api-version=2016-10-01'

foreach($ruleName in $rulesWithDifferences.Keys) {
    #$ruleName
    $ruleDifferences = $rulesWithDifferences[$ruleName]
    $ruleDifferences | Format-Table
    $newRule = Get-Content "Detections/$($ruleName).json" -Raw | ConvertFrom-Json
    $resource = $newRule.resources[0]
    $query = (((((($resource.properties.query | convertto-json -depth 99) -replace '"', '') -replace "'", '')) -creplace '\\n', "`n") -replace '\\', '')-creplace "`n", "\n`n"
    #$query = 'test'
    Write-Host $query
    Read-Host -Prompt "Press Enter to update this rule in Sentinel"
    $body = @{
        'ruleID' = $resource.id
        'ruleName' = $ruleName
        'ruleDifferences' = $ruleDifferences
        'resource' = $resource
        'displayName' = $resource.properties.displayName
        'query' = $query
    } | ConvertTo-Json
    #$body | out-file body.json
    $null = Invoke-RestMethod -Method Put -Uri $uri -Body $body -Headers $azureManagementHeaders -ContentType "application/json"
    
}


