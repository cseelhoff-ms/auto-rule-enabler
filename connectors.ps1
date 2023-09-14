#https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-07-01-preview
$apiPath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-07-01-preview"
$result = Invoke-AzRestMethod -Method GET -path $apiPath
$connectors = ($result.Content | ConvertFrom-Json).value
$arrayListTables = New-Object System.Collections.ArrayList
foreach($connID in $connectors) {
    $apiPath = "$($connID.id)?api-version=2023-07-01-preview"
    $result = Invoke-AzRestMethod -Method GET -path $apiPath
    $c0 = $result.Content | ConvertFrom-Json
    write-host "Processing connector $($c0.name)"
    foreach($c1 in $c0.properties.connectorUiConfig.dataTypes) {
        $null = $c1 | Add-Member -NotePropertyName dataConnector -NotePropertyValue $c0.name
        $null = $arrayListTables.Add($c1)
    }
}
$arrayListTables | Out-GridView
