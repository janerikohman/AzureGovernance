<#
.SYNOPSIS
    Lists RBAC role assignments per resource in an Azure resource group as JSON.

.PARAMETER ResourceGroupName
    The name of the resource group to analyze.

.PARAMETER SubscriptionId
    Optional. The subscription ID. If not specified, uses the current context.

.PARAMETER IncludeInherited
    Include role assignments inherited from resource group and subscription scope.

.EXAMPLE
    .\Get-ResourceGroupRbac.ps1 -ResourceGroupName "my-rg"
    .\Get-ResourceGroupRbac.ps1 -ResourceGroupName "my-rg" -IncludeInherited | Out-File report.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInherited
)

# Data plane role patterns
$DataPlaneRolePatterns = @(
    'Storage Blob Data *',
    'Storage Queue Data *',
    'Storage Table Data *',
    'Storage File Data *',
    'Key Vault Administrator',
    'Key Vault Certificates Officer',
    'Key Vault Crypto Officer',
    'Key Vault Crypto Service Encryption User',
    'Key Vault Crypto User',
    'Key Vault Reader',
    'Key Vault Secrets Officer',
    'Key Vault Secrets User',
    'Cosmos DB Account Reader Role',
    'Cosmos DB Operator',
    'CosmosBackupOperator',
    'Cosmos DB Built-in Data *',
    'Azure Service Bus Data *',
    'Azure Event Hubs Data *',
    'Cognitive Services *User',
    'Cognitive Services OpenAI User',
    'Cognitive Services OpenAI Contributor',
    'Azure AI Developer',
    'Azure AI Inference Deployment Operator',
    'Search Index Data *',
    'App Configuration Data *',
    'SignalR *',
    'Web PubSub Service *',
    'IoT Hub Data *',
    'Azure Digital Twins Data *',
    'Grafana *',
    'FHIR Data *',
    'Attestation Reader'
)

function Test-IsDataPlaneRole {
    param([string]$RoleName)
    foreach ($pattern in $DataPlaneRolePatterns) {
        if ($RoleName -like $pattern) { return $true }
    }
    return $false
}

# Set subscription context if specified
if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue | Out-Null
}

$context = Get-AzContext
if (-not $context) {
    throw "Not logged in to Azure. Run Connect-AzAccount first."
}

# Verify resource group exists
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    throw "Resource group '$ResourceGroupName' not found."
}

# Get all resources
$resources = Get-AzResource -ResourceGroupName $ResourceGroupName
$reportData = @()

foreach ($resource in $resources) {
    $resourceReport = @{
        resourceName = $resource.Name
        resourceType = $resource.ResourceType
        resourceId   = $resource.ResourceId
        controlPlane = @{}
        dataPlane    = @{}
    }
    
    # Get role assignments
    $assignments = Get-AzRoleAssignment -Scope $resource.ResourceId -ErrorAction SilentlyContinue
    
    if (-not $IncludeInherited) {
        $assignments = $assignments | Where-Object { $_.Scope -eq $resource.ResourceId }
    }
    
    foreach ($assignment in $assignments) {
        $roleName = $assignment.RoleDefinitionName
        $isDataPlane = Test-IsDataPlaneRole -RoleName $roleName
        
        $assignmentInfo = @{
            principalId   = $assignment.ObjectId
            principalType = $assignment.ObjectType
            displayName   = if ($assignment.DisplayName) { $assignment.DisplayName } else { $assignment.ObjectId }
            signInName    = $assignment.SignInName
            scope         = $assignment.Scope
            isInherited   = ($assignment.Scope -ne $resource.ResourceId)
        }
        
        $targetCollection = if ($isDataPlane) { 'dataPlane' } else { 'controlPlane' }
        
        if (-not $resourceReport[$targetCollection].ContainsKey($roleName)) {
            $resourceReport[$targetCollection][$roleName] = @()
        }
        $resourceReport[$targetCollection][$roleName] += $assignmentInfo
    }
    
    $reportData += $resourceReport
}

# Output JSON
$output = @{
    metadata = @{
        subscriptionId    = $context.Subscription.Id
        subscriptionName  = $context.Subscription.Name
        resourceGroup     = $ResourceGroupName
        generatedAt       = (Get-Date -Format "o")
        includeInherited  = $IncludeInherited.IsPresent
        resourceCount     = $resources.Count
    }
    resources = $reportData
}

$output | ConvertTo-Json -Depth 10
