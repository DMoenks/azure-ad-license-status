# Temporarily needs DelegatedPermissionGrant.ReadWrite.All

param ([Parameter(Mandatory=$true)]
		[string]$applicationID,
		[Parameter(Mandatory=$true)]
		[string]$senderAddress)

# Retrieve object ID for Microsoft Graph service principal
$resourceId = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/serviceprincipals?$filter=appId eq ''00000003-0000-0000-c000-000000000000''&$select=id').value.id
# Retrieve object ID for custom application registration service principal
$clientId = (Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/serviceprincipals?$filter=appId eq ''{0}''&$select=id' -f $applicationID)).value.id
# Retrieve object ID for report delivery user account
$principalId = (Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users?$filter=mail eq ''{0}''&$select=id' -f $senderAddress)).value.id

$grant = @{
	clientId = $clientId
	consentType = "Principal"
	principalId = $principalId
	resourceId = $resourceId
	scope = "Mail.Send"
}
 
Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Body $grant -ContentType 'application/json'