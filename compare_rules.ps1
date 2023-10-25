if($expires -lt ((New-TimeSpan -Start (Get-Date '1970-01-01 00:00:00') -End ((Get-Date).ToUniversalTime())).TotalSeconds) + 600) {
    $clientId = "e1ab09b4-7b37-46ee-b1cf-1c07469b26d2"
    $tenantId = "00ac9db9-508a-473b-aded-53250025bd24"

    Add-Type -AssemblyName System.Web
    $scope = [System.Web.HttpUtility]::UrlEncode("https://api.securitycenter.windows.com/Alert.Read")

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
    $tokenheader = $accessToken.Split(".")[0].Replace('-', '+').Replace('_', '/')
    $tokenheader = $accessToken.Split(".")[0].Replace('-', '+').Replace('_', '/')
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }
    $tokenPayload = $accessToken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $ta = $tokenArray | ConvertFrom-Json
    $expires = $ta.exp
}

if($null -eq $resourceGroupName) {
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
}

# Invoke API request to get alerts
$alerts = Invoke-AzRestMethod -Method GET -path "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"

$alerts = $alerts.Content | ConvertFrom-Json | Select-Object -ExpandProperty 'value' | Where-Object { $_.kind -in @('Scheduled', 'NRT') }

# Output number of  rules found
Write-Host "$($alerts.count) Rules found"

$apiVersion = '2023-02-01'
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
    #$arm | ConvertTo-Json -Depth 99 | Out-File -FilePath "Detections\$($alertIDshort).json"
}

#loop through each json in detections folder, and compare to the formatted alerts
$detections = Get-ChildItem -Path Detections -Filter *.json

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
        #if ($differences.Count -eq 1) {
        #    if ($differences[0].Property -eq 'properties.sentinelEntitiesMappings') {
        #        continue
        #    }
        #}
        if ($differences.Count -gt 0) {
            #$differences | Format-Table
            #Write-Host "There are differences between the objects: $detectionName" -ForegroundColor Yellow
            $arrayOfDifferences = New-Object System.Collections.ArrayList
            foreach ($difference in $differences) {
                $null = $arrayOfDifferences.Add([PSCustomObject]@{
                    property = $difference.Property
                    sentinel = $difference.Value1
                    repo = $difference.Value2
                })
            }
            $rulesWithDifferences.Add($detectionName, $arrayOfDifferences)
            $detectionName
            $arrayOfDifferences | Format-Table
        } else {
            #Write-Host "The objects are identical for: $detectionName"
        }
    } else {
        #Write-Host "The object does not exist in the repo: $detectionName" -ForegroundColor Yellow
        #Read-Host -Prompt "Press Enter to continue"
        $arrayOfDifferences = New-Object System.Collections.ArrayList
        $null = $arrayOfDifferences.Add(
        [PSCustomObject]@{
            property = '(NEW)'
            sentinel = '(null)'
            repo = '(NEW)'
        })
        $rulesWithDifferences.Add($detectionName, $arrayOfDifferences)
        $detectionName
        $arrayOfDifferences | Format-Table
    }
}



$headers = @{"Authorization" = "Bearer $accessToken"}
$uri = 'https://prod-85.eastus.logic.azure.com:443/workflows/5d28dc4c29c04cea85032c20659b5c33/triggers/manual/paths/invoke?api-version=2016-10-01'

foreach($ruleName in $rulesWithDifferences.Keys) {
    $ruleName
    $ruleDifferences = $rulesWithDifferences[$ruleName]
    $ruleDifferences | Format-Table
    $newRule = Get-Content "Detections/$($ruleName).json" -Raw | ConvertFrom-Json
    $resource = $newRule.resources[0]
    $body = @{
        'ruleID' = $resource.id
        'ruleName' = $ruleName
        'ruleDifferences' = $ruleDifferences
        'resource' = $resource
    } | ConvertTo-Json -Depth 99
    #$body | out-file body.json
    Invoke-RestMethod -Method Put -Uri $uri -Body $body -Headers $headers -ContentType "application/json"
    #Read-Host -Prompt "Press Enter to continue"
}


