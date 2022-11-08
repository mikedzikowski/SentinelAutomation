
[CmdletBinding()]
param
(
    [Parameter(mandatory=$true)]
    [string]
    $IncidentUrl,

    [Parameter(mandatory=$true)]
    [string]
    $Subscription,

    [Parameter(mandatory=$true)]
    [string]
    $SentinelRg,

    [Parameter(mandatory=$true)]
    [string]
    $SentinelWorkspace,

    [Parameter(mandatory=$true)]
    [string]
    $Title,

    [Parameter(mandatory=$true)]
    [string]
    $Description,

    [Parameter(mandatory=$true)]
    [string]
    $KeyVault
)

# Connect using a Managed Service Identity
try
{
    $AzureContext = (Connect-AzAccount -Identity -Environment 'AzureUSGovernment').context
}
catch
{
    Write-Output "There is no system-assigned user identity. Aborting.";
    exit
}

#Variables
#$TenantId = (Get-AzKeyVaultSecret -VaultName $KeyVault -Name "TenantId").SecretValue
#$ClientId = (Get-AzKeyVaultSecret -VaultName $KeyVault -Name "ClientId").SecretValue
#$ClientSecret = (Get-AzKeyVaultSecret -VaultName $KeyVault -Name "ClientSecret").SecretValue
$TenantId = "00000000-0000-0000-0000-000000000000"
$ClientId = "00000000-0000-0000-0000-000000000000"
$ClientSecret = "00000000-0000-0000-0000-000000000000"
$Resource = "https://management.azure.com/"
$RequestAccessTokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$Headers = $null

$body = "grant_type=client_credentials&client_id=$ClientId&client_secret=$ClientSecret&resource=$Resource"

$Token = Invoke-RestMethod -Method Post -Uri $RequestAccessTokenUri -Body $body -ContentType 'application/x-www-form-urlencoded'

$putBody = @{
  'properties'= @{
    'description' = $Description
    'title' = $Title
    'incidentUrl' = $IncidentUrl
    'status' = 'New'
	'severity' = 'Informational'
  }
}

$commentBody = @{
	'properties'= @{
	'message' = "An incident has been forwarded from your Azure US Government Cloud. To view the incident in MAG please visit: $($IncidentUrl)"
	}
}

$putBody = ConvertTo-Json -InputObject $putBody
$commentBody = ConvertTo-Json -InputObject $commentBody

$headers = @{
    'Authorization' = "Bearer $($Token.access_token)"
    'Content-Type'  = 'application/json'
}

# All incidents
$IncidentNumber = "https://management.azure.com/subscriptions/$($Subscription)/resourceGroups/$($SentinelRg)/providers/Microsoft.OperationalInsights/workspaces/$($SentinelWorkspace)/providers/Microsoft.SecurityInsights/incidents/?api-version=2021-10-01"
$number = [int]((Invoke-RestMethod -Method GET -URI $incidentNumber -Headers $Headers).value | Select-Object -first 1).id.split('/')[-1] + 1

# New Incident
$URL = "https://management.azure.com/subscriptions/$($Subscription)/resourceGroups/$($SentinelRg)/providers/Microsoft.OperationalInsights/workspaces/$($SentinelWorkspace)/providers/Microsoft.SecurityInsights/incidents/$($number)?api-version=2022-07-01-preview"
Invoke-RestMethod -Method PUT -Uri $URL -Headers $Headers -Body $putBody -ContentType 'application/json' -Verbose

# Add comment
$commentURL = "https://management.azure.com/subscriptions/$($Subscription)/resourceGroups/$($SentinelRg)/providers/Microsoft.OperationalInsights/workspaces/$($SentinelWorkspace)/providers/Microsoft.SecurityInsights/incidents/$($number)/comments/1?api-version=2022-07-01-preview"
Invoke-RestMethod -Method PUT -Uri $commentURL -Headers $Headers -Body $commentBody -ContentType 'application/json' -Verbose