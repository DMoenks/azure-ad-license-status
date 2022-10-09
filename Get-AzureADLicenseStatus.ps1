<#
.SYNOPSIS
Create an Azure AD license report for operative tasks based on license consumption and assignments
.DESCRIPTION
This script is meant to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of
group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any
conflicting license assignments per user account.
This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a
licensing service provider.

SKU IDs and names are in accordance with https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
.PARAMETER directoryID
Specifies the directory to connect to
.PARAMETER applicationID
Specifies the application in target directory to authenticate with
.PARAMETER subscriptionID
Specifies the subscription in target directory to access
.PARAMETER keyVaultName
Specifies the key vault in target subscription to access
.PARAMETER certificateName
Specifies the certificate in target key vault to to use for authentication
.PARAMETER senderAddress
Specifies the sender address to be used for report delivery
.PARAMETER normalRecipientsAddresses
Specifies the recipient addresses to be used for report delivery
.PARAMETER criticalRecipientsAddresses
Specifies the additional recipient addresses to be used for report delivery in critical cases
.PARAMETER licenseIgnoreThreshold
Specifies the minimum enabled license threshold for SKUs to be taken into account for the report
.PARAMETER licensePercentageThreshold_normalSKUs
Specifies the minimum available license amount threshold for SKUs to be included in the report
.PARAMETER licenseTotalThreshold_normalSKUs
Specifies the minimum available license percentage threshold for SKUs to be included in the report
.PARAMETER licensePercentageThreshold_importantSKUs
Specifies the minimum available license amount threshold for SKUs to be included in the report
.PARAMETER licenseTotalThreshold_importantSKUs
Specifies the minimum available license percentage threshold for SKUs to be included in the report
.PARAMETER warningPercentageThreshold
Specifies the warning percentage threshold to be used during report creation
.PARAMETER criticalPercentageThreshold
Specifies the critical percentage threshold to be used during report creation
.PARAMETER importantSKUs
.PARAMETER interchangeableSKUs_specified
.PARAMETER advancedCheckups
Specifies if advanced license checkups should be run
ATTENTION: Advanced checkups require additional access permissions and will increase the scripts runtime
#>

param ([Parameter(Mandatory=$true)]
        [string]$directoryID,
        [Parameter(Mandatory=$true)]
        [string]$applicationID,
        [Parameter(Mandatory=$true)]
        [string]$subscriptionID,
        [Parameter(Mandatory=$true)]
        [string]$keyVaultName,
        [Parameter(Mandatory=$true)]
        [string]$certificateName,
        [Parameter(Mandatory=$true)]
        [string]$senderAddress,
        [Parameter(Mandatory=$true)]
        [string[]]$normalRecipientsAddresses,
        [string[]]$criticalRecipientsAddresses,
        [int]$licenseIgnoreThreshold = 10,
        [int]$licensePercentageThreshold_normalSKUs = 5,
        [int]$licenseTotalThreshold_normalSKUs = 10,
        [int]$licensePercentageThreshold_importantSKUs = 5,
        [int]$licenseTotalThreshold_importantSKUs = 50,
        [int]$warningPercentageThreshold = 80,
        [int]$criticalPercentageThreshold = 20,
        [string[]]$importantSKUs = @('18181a46-0d4e-45cd-891e-60aabd171b4e',
                                    '6fd2c87f-b296-42f0-b197-1e91e994b900'),
        [string[]]$interchangeableSKUs_specified = @('4b585984-651b-448a-9e53-3b10f069cf7f',
                                                    '18181a46-0d4e-45cd-891e-60aabd171b4e',
                                                    '6fd2c87f-b296-42f0-b197-1e91e994b900',
                                                    'c7df2760-2c81-4ef7-b578-5b5392b571df'),
        [switch]$advancedCheckups)

#region: CSS configuration
$style = @"
<style>
table, th, td {
    border: none;
    border-collapse: collapse;
}
th, td {
    padding: 5px;
    text-align: left;
    vertical-align: top;
}
.gray {
    border-left: 4pt solid darkslategray;
    padding-left: 4pt;
    background-color: lightslategray
}
.green {
    border-left: 4pt solid darkgreen;
    padding-left: 4pt;
    background-color: lightgreen
}
.yellow {
    border-left: 4pt solid darkgoldenrod;
    padding-left: 4pt;
    background-color: lightgoldenrodyellow
}
.red {
    border-left: 4pt solid darkred;
    padding-left: 4pt;
    background-color: lightcoral
}
</style>
"@
#endregion

#region: Functions
$outputs = [System.Text.StringBuilder]::new()
function Add-Output
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output
    )
    $outputs.AppendLine($Output) | Out-Null
}

$results = @{}
function Add-Result
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, ParameterSetName='Advanced')]
        [Parameter(Mandatory=$true, ParameterSetName='SKU')]
        [ValidateNotNullOrEmpty()]
        [guid]$SKUID,
        [Parameter(Mandatory=$true, ParameterSetName='Advanced')]
        [ValidateNotNullOrEmpty()]
        [int]$EnabledCount,
        [Parameter(Mandatory=$true, ParameterSetName='Advanced')]
        [ValidateNotNullOrEmpty()]
        [int]$NeededCount,
        [Parameter(Mandatory=$true, ParameterSetName='SKU')]
        [ValidateNotNullOrEmpty()]
        [int]$AvailableCount,
        [Parameter(Mandatory=$true, ParameterSetName='SKU')]
        [ValidateNotNullOrEmpty()]
        [int]$MinimumCount,
        [Parameter(Mandatory=$true, ParameterSetName='User')]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,
        [Parameter(Mandatory=$true, ParameterSetName='User')]
        [ValidateSet('Interchangeable','Optimizable','Removable')]
        [string]$ConflictType,
        [Parameter(Mandatory=$true, ParameterSetName='User')]
        [ValidateNotNullOrEmpty()]
        [guid[]]$ConflictSKUs
    )
    $results.Add($Type, $Result)
}

function Get-SKUName
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]    
        [guid]$SKUID
    )
    if ($null -ne ($skuName = ($skuTranslate |
                                Where-Object{$_.GUID -eq $SKU}).Product_Display_Name |
                                Select-Object -Unique))
    {
        $skuName = [cultureinfo]::new('en-US').TextInfo.ToTitleCase($skuName.ToLower())
    }
    else
    {
        $skuName = $SKU
    }
    return $skuName
}
#endregion

#region: Certificate
Connect-AzAccount -Identity -Subscription $subscriptionID | Out-Null
$azCertSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $certificateName -AsPlainText
$azCertSecretByte = [Convert]::FromBase64String($azCertSecret)
$x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($azCertSecretByte)
Disconnect-AzAccount
#endregion

Connect-MgGraph -Certificate $x509Cert -TenantId $directoryID -ClientId $applicationID | Out-Null

#region: SKUs
# Get SKU IDs and names
$skuTranslate = [string]::new([char[]]((Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -UseBasicParsing).Content)) | ConvertFrom-Csv
# Get SKUs
$SKUs = [System.Collections.Generic.List[hashtable]]::new()
$URI = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,prepaidUnits,consumedUnits,servicePlans'
while ($null -ne $URI)
{
    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
    $SKUs.AddRange([hashtable[]]($data.value))
    $URI = $data['@odata.nextLink']
}
# Calculate SKU usage
$resultsSKU = @{}
foreach ($SKU in $SKUs | Where-Object{$_.prepaidUnits.enabled -gt $licenseIgnoreThreshold})
{
    $availableCount = $SKU.prepaidUnits.enabled - $SKU.consumedUnits
    $totalCount = $SKU.prepaidUnits.enabled
    if ($SKU.skuId -in $importantSKUs)
    {
        $minimumCount = (@([System.Math]::Ceiling($totalCount * $licensePercentageThreshold_importantSKUs / 100), $licenseTotalThreshold_importantSKUs) | Measure-Object -Minimum).Minimum
    }
    else
    {
        $minimumCount = (@([System.Math]::Ceiling($totalCount * $licensePercentageThreshold_normalSKUs / 100), $licenseTotalThreshold_normalSKUs) | Measure-Object -Minimum).Minimum
    }
    if ($availableCount -lt $minimumCount)
    {
        $resultsSKU.Add($SKU.skuId, @{})
        $resultsSKU[$SKU.skuId].Add('availableCount', $availableCount)
        $resultsSKU[$SKU.skuId].Add('minimumCount', $minimumCount)
    }
}
$interchangeableSKUs_calculatedOrganization_replaces = @{}
$interchangeableSKUs_calculatedOrganization_replacedBy = @{}
foreach ($referenceSKU in $SKUs)
{
    foreach ($differenceSKU in $SKUs | Where-Object{$_.skuId -ne $referenceSKU.skuId})
    {
        if ($null -ne ($referenceServicePlans = $referenceSKU.servicePlans | Where-Object{$_.appliesTo -eq 'User'}) -and
            $null -ne ($differenceServicePlans = $differenceSKU.servicePlans | Where-Object{$_.appliesTo -eq 'User'}))
        {
            if ($null -ne ($comparisonSKU = Compare-Object $referenceServicePlans.servicePlanId $differenceServicePlans.servicePlanId -IncludeEqual) -and
                ($comparisonSKU.SideIndicator | Select-Object -Unique) -contains '==' -and
                ($comparisonSKU.SideIndicator | Select-Object -Unique) -notcontains '=>')
            {
                if (-not $interchangeableSKUs_calculatedOrganization_replaces.ContainsKey($referenceSKU.skuId))
                {
                    $interchangeableSKUs_calculatedOrganization_replaces.Add($referenceSKU.skuId, [System.Collections.Generic.List[string]]::new())
                }
                $interchangeableSKUs_calculatedOrganization_replaces[$referenceSKU.skuId].Add($differenceSKU.skuId)
                if (-not $interchangeableSKUs_calculatedOrganization_replacedBy.ContainsKey($differenceSKU.skuId))
                {
                    $interchangeableSKUs_calculatedOrganization_replacedBy.Add($differenceSKU.skuId, [System.Collections.Generic.List[string]]::new())
                }
                $interchangeableSKUs_calculatedOrganization_replacedBy[$differenceSKU.skuId].Add($referenceSKU.skuId)
            }
        }
    }
}
#endregion

#region: Users
# Get users
$users = [System.Collections.Generic.List[hashtable]]::new()
$URI = 'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,licenseAssignmentStates&$top=500'
while ($null -ne $URI)
{
    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
    $users.AddRange([hashtable[]]($data.value))
    $URI = $data['@odata.nextLink']
}
# Analyze users
$resultsUsers = @{}
foreach ($user in $users)
{
    if ($user.licenseAssignmentStates.count -gt 0)
    {
        $userSKUs = ($user.licenseAssignmentStates | Where-Object{$_.state -eq 'Active' -or $_.error -in @('CountViolation', 'MutuallyExclusiveViolation')}).skuId
        foreach ($countViolation in ($user.licenseAssignmentStates |
                                    Where-Object{$_.error -eq 'CountViolation'}).skuId |
                                    Select-Object -Unique)
        {
            $resultsSKU[$countViolation]['availableCount'] -= 1
        }
        # Identify interchangeable SKUs, based on earlier specifications
        if ($null -ne $userSKUs)
        {
            $comparisonInterchangeable = (Compare-Object $userSKUs $interchangeableSKUs_specified -ExcludeDifferent -IncludeEqual).InputObject
        }
        # Identify optimizable SKUs, based on organization-level calculations
        if ($null -ne ($comparison_replaceableOrganization = $userSKUs |
                        Where-Object{$_ -in $interchangeableSKUs_calculatedOrganization_replacedBy.Keys} |
                        ForEach-Object{$interchangeableSKUs_calculatedOrganization_replacedBy[$_]}))
        {
            $comparisonOptimizable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableOrganization -ExcludeDifferent -IncludeEqual |
                                        ForEach-Object{$interchangeableSKUs_calculatedOrganization_replaces[$_.InputObject]} |
                                        Where-Object{$_ -in $userSKUs} |
                                        Select-Object -Unique
        }
        # Identify removable SKUs, based on user-level calculations
        $skuid_enabledPlans = @{}
        foreach ($skuid in $user.licenseAssignmentStates.skuid | Select-Object -Unique)
        {
            if (-not $skuid_enabledPlans.ContainsKey($skuid))
            {
                $skuid_enabledPlans.Add($skuid, [System.Collections.Generic.List[string]]::new())
            }
            foreach ($assignment in $user.licenseAssignmentStates | Where-Object{$_.skuid -eq $skuid})
            {
                $skuid_enabledPlans[$skuid].AddRange([string[]]@((($SKUs | Where-Object{$_.skuid -eq $skuid}).servicePlans | Where-Object{$_.servicePlanId -notin $assignment.disabledplans -and $_.appliesTo -eq 'User'}).servicePlanId))
            }
        }
        $interchangeableSKUs_calculatedUser_replaces = @{}
        $interchangeableSKUs_calculatedUser_replacedBy = @{}
        foreach ($referenceSKU in $skuid_enabledPlans.Keys)
        {
            foreach ($differenceSKU in $skuid_enabledPlans.Keys | Where-Object{$_ -ne $referenceSKU})
            {
                if ($null -ne ($referenceServicePlans = $skuid_enabledPlans[$referenceSKU]) -and
                    $null -ne ($differenceServicePlans = $skuid_enabledPlans[$differenceSKU]))
                {
                    if ($null -ne ($comparisonSKU = Compare-Object $referenceServicePlans $differenceServicePlans -IncludeEqual) -and
                        ($comparisonSKU.SideIndicator | Select-Object -Unique) -contains '==' -and
                        ($comparisonSKU.SideIndicator | Select-Object -Unique) -notcontains '=>')
                    {
                        if (-not $interchangeableSKUs_calculatedUser_replaces.ContainsKey($referenceSKU))
                        {
                            $interchangeableSKUs_calculatedUser_replaces.Add($referenceSKU, [System.Collections.Generic.List[string]]::new())
                        }
                        $interchangeableSKUs_calculatedUser_replaces[$referenceSKU].Add($differenceSKU)
                        if (-not $interchangeableSKUs_calculatedUser_replacedBy.ContainsKey($differenceSKU))
                        {
                            $interchangeableSKUs_calculatedUser_replacedBy.Add($differenceSKU, [System.Collections.Generic.List[string]]::new())
                        }
                        $interchangeableSKUs_calculatedUser_replacedBy[$differenceSKU].Add($referenceSKU)
                    }
                }
            }
        }
        if ($null -ne ($comparison_replaceableUser = $userSKUs |
            Where-Object{$_ -in $interchangeableSKUs_calculatedUser_replacedBy.Keys} |
            ForEach-Object{$interchangeableSKUs_calculatedUser_replacedBy[$_]}))
        {
            $comparisonRemovable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableUser -ExcludeDifferent -IncludeEqual |
                                    ForEach-Object{$interchangeableSKUs_calculatedUser_replaces[$_.InputObject]} |
                                    Where-Object{$_ -in $userSKUs} |
                                    Select-Object -Unique
        }
        # Add intermediate results to total results
        if ($comparisonInterchangeable.Count -gt 1 -or
            $null -ne $comparisonOptimizable -or
            $null -ne $comparisonRemovable)
        {
            $resultsUsers.Add($user.userPrincipalName, @{})
            if ($comparisonInterchangeable.Count -gt 1)
            {
                $resultsUsers[$user.userPrincipalName].Add('Interchangeable', $comparisonInterchangeable)
            }
            if ($null -ne $comparisonOptimizable)
            {
                $resultsUsers[$user.userPrincipalName].Add('Optimizable', $comparisonOptimizable)
            }
            if ($null -ne $comparisonRemovable)
            {
                $resultsUsers[$user.userPrincipalName].Add('Removable', $comparisonRemovable)
            }
        }
    }
}
#endregion

#region: Advanced
if ($advancedCheckups.IsPresent)
{
    $AADP1Users = [System.Collections.Generic.List[string]]::new()
    $AADP2Users = [System.Collections.Generic.List[string]]::new()
    $ATPUsers = [System.Collections.Generic.List[string]]::new()
    # Retrieve groups, used for multiple checkups
    $groups = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/groups?$select=id,groupTypes'
    while ($null -ne $URI)
    {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $groups.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    # Azure AD P1 based on dynamic groups
    $dynamicGroupMembers = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($group in $groups | Where-Object{$_.groupTypes -contains 'DynamicMembership'})
    {
        $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/members?$select=id' -f $group.id
        while ($null -ne $URI)
        {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $dynamicGroupMembers.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
    }
    $AADP1Users.AddRange(($dynamicGroupMembers.id | Select-Object -Unique))
    # Azure AD P1 based on group-based application assignments and applications using application proxy
    $applications = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo'
    while ($null -ne $URI)
    {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $applications.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    $applicationGroups = ($applications | Where-Object{$_.accountEnabled -eq $true -and $_.appRoleAssignmentRequired -eq $true -and $_.servicePrincipalType -eq 'Application'}).appRoleAssignedTo | Where-Object{$_.principalType -eq 'Group'}
    $applicationGroupMembers = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($group in $applicationGroups)
    {
        $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/members?$select=id' -f $group.principalId
        while ($null -ne $URI)
        {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $applicationGroupMembers.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
    }
    $AADP1Users.AddRange(($applicationGroupMembers.id | Select-Object -Unique))
    # Azure AD P1 based on MFA-enabled users
    $conditionalAccessPolicies = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=conditions'
    while ($null -ne $URI)
    {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $conditionalAccessPolicies.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    $conditionalAccessUsers = [System.Collections.Generic.List[string]]::new()
    foreach ($conditionalAccessPolicy in $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled'})
    {
        if ($conditionalAccessPolicy.conditions.users.includeUsers -eq 'All')
        {
            $conditionalAccessUsers.AddRange((Compare-Object -ReferenceObject $users.id -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeUsers | Where-Object{$_.SideIndicator -eq '<='}))
        }
        else
        {
            $conditionalAccessUsers.AddRange((Compare-Object -ReferenceObject $conditionalAccessPolicy.conditions.users.includeUsers -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeUsers | Where-Object{$_.SideIndicator -eq '<='}))
        }
        if ($conditionalAccessPolicy.conditions.users.includeGroups -eq 'All')
        {
            $conditionalAccessGroups = Compare-Object -ReferenceObject $groups.id -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeGroups | Where-Object{$_.SideIndicator -eq '<='}
        }
        else
        {
            $conditionalAccessGroups = Compare-Object -ReferenceObject $conditionalAccessPolicy.conditions.users.includeGroups -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeGroups | Where-Object{$_.SideIndicator -eq '<='}
        }
        foreach ($group in $conditionalAccessGroups)
        {
            $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/members?$select=id' -f $group
            while ($null -ne $URI)
            {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $conditionalAccessUsers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
        }
    }
    $AADP1Users.AddRange(($conditionalAccessUsers.id | Select-Object -Unique))
    # Azure AD P2 based on PIM-managed users
    $eligibleRoleMembers = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,scheduleInfo'
    while ($null -ne $URI)
    {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $eligibleRoleMembers.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    $AADP2Users.AddRange((($eligibleRoleMembers |
                            Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and
                                ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or
                                $_.scheduleInfo.expiration.type -eq 'noExpiration')}).principalId |
                            Select-Object -Unique))
    # Defender for Office 365 P1/P2 based on user and shared mailboxes
    #TODO: Missing user ID from mailbox
    $orgDomain = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains').value.verifiedDomains | Where-Object{$_.isInitial -eq $true}
    Connect-ExchangeOnline -AppId $applicationID -Certificate $x509Cert -Organization $orgDomain.name -CommandName Get-EXOMailbox
    $ATPUsers.AddRange((Get-EXOMailbox -Filter 'RecipientTypeDetails -eq "SharedMailbox" -or RecipientTypeDetails -eq "UserMailbox"' -ResultSize Unlimited).'MissingIDAttribute')
    Disconnect-ExchangeOnline
    # Results
    #TODO: Missing better count calculations
    if ($AADP1Users.Count -gt 0)
    {
        Add-Result -Type Advanced -Result @{
            '078d2b04-f1bd-4111-bbd4-b4b1b354cef4' = @{
                'enabledCount' = $availableCount;
                'neededCount' = ($AADP1Users | Select-Object -Unique).Count
            }
        }
    }
    if ($AADP2Users.Count -gt 0)
    {
        Add-Result -Type Advanced -Result @{
            '84a661c4-e949-4bd2-a560-ed7766fcaf2b' = @{
                'enabledCount' = $availableCount;
                'neededCount' = ($AADP2Users | Select-Object -Unique).Count
            }
        }
    }
    if ($ATPUsers.Count -gt 0)
    {
        if ($SKUs.skuId -contains '3dd6cf57-d688-4eed-ba52-9e40b5468c3e')
        {
            Add-Result -Type Advanced -Result @{
                '3dd6cf57-d688-4eed-ba52-9e40b5468c3e' = @{
                    'enabledCount' = $availableCount;
                    'neededCount' = ($ATPUsers | Select-Object -Unique).Count
                }
            }
        }
        else
        {
            Add-Result -Type Advanced -Result @{
                '4ef96642-f096-40de-a3e9-d83fb2f90211' = @{
                    'enabledCount' = $availableCount;
                    'neededCount' = ($ATPUsers | Select-Object -Unique).Count
                }
            }
        }
    }
}
#endregion

#region: Report
# Report SKUs
if ($resultsSKU.Keys.Count -gt 0 -or
    $resultsUsers.Keys.Count -gt 0)
{
    Add-Output -Output $style
    $critical = $false
    # Output licenses with issues
    if ($resultsSKU.Keys.Count -gt 0)
    {
        Add-Output -Output '<p class=gray>Basic checkup - Products</p> `
                            <p>Please check license counts for the following products and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p> `
                            <p><table><tr><th>License type</th><th>Available count</th><th>Minimum count</th><th>Difference</th></tr>'
        foreach ($SKU in $resultsSKU.Keys)
        {
            $differenceCount = $resultsSKU[$SKU]['availableCount'] - $resultsSKU[$SKU]['minimumCount']
            Add-Output -Output "<tr> `
                                <td>$(Get-SKUName -SKUID $SKU)</td> `
                                <td>$($resultsSKU[$SKU]['availableCount'])</td> `
                                <td>$($resultsSKU[$SKU]['minimumCount'])</td>"
            if ($resultsSKU[$SKU]['availableCount'] / $resultsSKU[$SKU]['minimumCount'] * 100 -ge $warningPercentageThreshold)
            {
                Add-Output -Output "<td class=green>$differenceCount</td>"
            }
            elseif ($resultsSKU[$SKU]['availableCount'] / $resultsSKU[$SKU]['minimumCount'] * 100 -le $criticalPercentageThreshold)
            {
                $critical = $true
                Add-Output -Output "<td class=red>$differenceCount</td>"
            }
            else
            {
                Add-Output -Output "<td class=yellow>$differenceCount</td>"
            }
            Add-Output -Output '</tr>'
        }
        Add-Output -Output "</table></p> `
                            <p>The following criteria were used during the checkup:<ul><li>Check products with >$licenseIgnoreThreshold total licenses</li> `
                            <li>Report normal products having both <$licenseTotalThreshold_normalSKUs licenses and <$licensePercentageThreshold_normalSKUs% of their total licenses available</li> `
                            <li>Report important products having both <$licenseTotalThreshold_importantSKUs licenses and <$licensePercentageThreshold_importantSKUs% of their total licenses available</li></ul></p>"
    }
    # Output accounts with issues
    if ($resultsUsers.Keys.Count -gt 0)
    {
        Add-Output -Output '<p class=gray>Basic checkup - Users</p> `
                            <p>Please check license assignments for the following accounts and mitigate impact:</p> `
                            <p><table><tr><th>Account</th><th>Interchangeable</th><th>Optimizable</th><th>Removable</th></tr>'
        foreach ($user in $resultsUsers.Keys | Sort-Object)
        {
            Add-Output -Output "<tr> `
                                <td>$user</td> `
                                <td>$(($resultsUsers[$user]['Interchangeable'] |
                                        Where-Object{$null -ne $_} |
                                        ForEach-Object{Get-SKUName -SKUID $_} |
                                        Sort-Object) -join '<br>')</td> `
                                <td>$(($resultsUsers[$user]['Optimizable'] |
                                        Where-Object{$null -ne $_} |
                                        ForEach-Object{Get-SKUName -SKUID $_} |
                                        Sort-Object) -join '<br>')</td> `
                                <td>$(($resultsUsers[$user]['Removable'] |
                                        Where-Object{$null -ne $_} |
                                        ForEach-Object{Get-SKUName -SKUID $_} |
                                        Sort-Object) -join '<br>')</td> `
                                </tr>"
        }
        Add-Output -Output '</table></p> `
                            <p>The following criteria were used during the checkup:<ul><li>Check accounts with any number of assigned licenses</li> `
                            <li>Report theoretically exclusive licenses as <strong>interchangeable</strong>, based on specified SKUs</li> `
                            <li>Report practically inclusive licenses as <strong>optimizable</strong>, based on available SKU features</li> `
                            <li>Report actually inclusive licenses as <strong>removable</strong>, based on enabled SKU features</li></ul></p>'
    }
    if ($advancedCheckups)
    {
        Add-Output -Output '<p class=gray>Avanced checkup - Features</p> `
                            <p>Please check license counts for the following products and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p> `
                            <p><table><tr><th>License type</th><th>Available count</th><th>Minimum count</th><th>Difference</th></tr>'
        #TODO: Output for advanced checkups
        Add-Output -Output '</table></p>'
    }
    # Configure basic email settings
    $email = @{
        'message' = @{
            'subject' = 'Azure AD licenses need attention';
            'importance' = 'normal';
            'body' = @{
                'contentType' = 'HTML';
                'content' = $outputs.ToString()
            };
        }
    }
    # Add normal email recipients
    $email['message'].Add('toRecipients', [System.Collections.Generic.List[hashtable]]::new())
    foreach ($recipientAddress in $normalRecipientsAddresses)
    {
        $email['message']['toRecipients'].Add(@{
            'emailAddress' = @{
                'address' = $recipientAddress
            }
        })
    }
    # Check criticality
    if ($critical)
    {
        # Replace subject and importance
        $email['message']['subject'] = 'Azure AD licenses need urgent attention'
        $email['message']['importance'] = 'high'
        # Add critical email recipients
        $email['message'].Add('ccRecipients', [System.Collections.Generic.List[hashtable]]::new())
        foreach ($recipientAddress in $criticalRecipientsAddresses)
        {
            $email['message']['ccRecipients'].Add(@{
                'emailAddress' = @{
                    'address' = $recipientAddress
                }
            })
        }
    }
    # Initiate email delivery
    Invoke-MgGraphRequest -Method POST -Uri ('https://graph.microsoft.com/v1.0/users/{0}/sendMail' -f $senderAddress) -Body $email -ContentType 'application/json'
}
#endregion

Disconnect-MgGraph
