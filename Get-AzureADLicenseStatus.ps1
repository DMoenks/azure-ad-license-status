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
.PARAMETER warningPercentageThreshold_basic
Specifies the basic warning percentage threshold to be used during report creation
.PARAMETER criticalPercentageThreshold_basic
Specifies the basic critical percentage threshold to be used during report creation
.PARAMETER $warningPercentageThreshold_advanced
Specifies the advanced warning percentage threshold to be used during report creation
.PARAMETER criticalPercentageThreshold_advanced
Specifies the advanced critical percentage threshold to be used during report creation
.PARAMETER importantSKUs
Specifies the SKUs which are deemed important, so different thresholds are used for calculation
.PARAMETER interchangeableSKUs
Specifies a single list of SKUs which are deemed interchangeable, e.g Office 365 E1 and Office 365 E3
.PARAMETER advancedCheckups
Specifies if advanced license checkups should be run
ATTENTION: Advanced checkups require additional access permissions and might increase the checkup duration
#>

param (
    [Parameter(Mandatory=$true)]
    [guid]$directoryID,
    [Parameter(Mandatory=$true)]
    [guid]$applicationID,
    [Parameter(Mandatory=$true)]
    [guid]$subscriptionID,
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
    [int]$warningPercentageThreshold_basic = 80,
    [int]$criticalPercentageThreshold_basic = 20,
    [int]$warningPercentageThreshold_advanced = 99,
    [int]$criticalPercentageThreshold_advanced = 95,
    [guid[]]$importantSKUs = @(
        '18181a46-0d4e-45cd-891e-60aabd171b4e',
        '6fd2c87f-b296-42f0-b197-1e91e994b900'
    ),
    [guid[]]$interchangeableSKUs = @(
        '4b585984-651b-448a-9e53-3b10f069cf7f',
        '18181a46-0d4e-45cd-891e-60aabd171b4e',
        '6fd2c87f-b296-42f0-b197-1e91e994b900',
        'c7df2760-2c81-4ef7-b578-5b5392b571df'
    ),
    [switch]$advancedCheckups
)

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
function Add-Output {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output
    )
    $outputs.AppendLine($Output) | Out-Null
}

$results = @{}
function Add-Result {
    param (
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
    if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
        $results.Add($PSCmdlet.ParameterSetName, @{})
    }
    switch ($PSCmdlet.ParameterSetName) {
        'Advanced' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($SKUID)) {
                $results[$PSCmdlet.ParameterSetName].Add($SKUID, @{
                    'enabledCount' = $EnabledCount;
                    'neededCount' = $NeededCount
                })
            }
        }
        'SKU' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($SKUID)) {
                $results[$PSCmdlet.ParameterSetName].Add($SKUID, @{
                    'availableCount' = $AvailableCount;
                    'minimumCount' = $MinimumCount
                })
            }
        }
        'User' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($UserPrincipalName)) {
                $results[$PSCmdlet.ParameterSetName].Add($UserPrincipalName, @{})
            }
            if (-not $results[$PSCmdlet.ParameterSetName][$UserPrincipalName].ContainsKey($ConflictType)) {
                $results[$PSCmdlet.ParameterSetName][$UserPrincipalName].Add($ConflictType, $ConflictSKUs)
            }
        }
    }
}

$groups = [System.Collections.Generic.List[hashtable]]::new()
function Get-GroupMembers {
    [OutputType([string])]
    param (
        [guid[]]$GroupIDs,
        [switch]$TransitiveMembers
    )
    if ($TransitiveMembers.IsPresent) {
        $memberProperty = 'transitiveMembers'
    }
    else {
        $memberProperty = 'members'
    }
    foreach ($groupID in $GroupIDs) {
        if ($null -eq $groups[$groupID][$memberProperty]) {
            $groupMembers = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/{1}?$select=id' -f $groupID, $memberProperty
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $groupMembers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            $groups[$groupID].Add($memberProperty, $groupMembers)
        }
    }
    return ($groups | Where-Object{$_.id -in $GroupIDs})[$memberProperty].id
}

$skuTranslate = [string]::new([char[]]((Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -UseBasicParsing).Content)) | ConvertFrom-Csv
function Get-SKUName {
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]    
        [guid]$SKUID
    )
    if ($null -ne ($skuName = ($skuTranslate |
    Where-Object{$_.GUID -eq $SKUID}).Product_Display_Name |
    Select-Object -Unique)) {
        $skuName = [cultureinfo]::new('en-US').TextInfo.ToTitleCase($skuName.ToLower())
    }
    else {
        $skuName = $SKUID
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
# Get SKUs
$SKUs = [System.Collections.Generic.List[hashtable]]::new()
$URI = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,prepaidUnits,consumedUnits,servicePlans'
while ($null -ne $URI) {
    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
    $SKUs.AddRange([hashtable[]]($data.value))
    $URI = $data['@odata.nextLink']
}
# Calculate SKU usage
foreach ($SKU in $SKUs | Where-Object{$_.prepaidUnits.enabled -gt $licenseIgnoreThreshold}) {
    $totalCount = $SKU.prepaidUnits.enabled
    $availableCount = $SKU.prepaidUnits.enabled - $SKU.consumedUnits
    if ($SKU.skuId -in $importantSKUs) {
        $percentageThreshold = $licensePercentageThreshold_importantSKUs
        $totalThreshold = $licenseTotalThreshold_importantSKUs
    }
    else {
        $percentageThreshold = $licensePercentageThreshold_normalSKUs
        $totalThreshold = $licenseTotalThreshold_normalSKUs
    }
    $minimumCount = (@([System.Math]::Ceiling($totalCount * $percentageThreshold / 100), $totalThreshold) | Measure-Object -Minimum).Minimum
    if ($availableCount -lt $minimumCount) {
        Add-Result -SKUID $SKU.skuId -AvailableCount $availableCount -MinimumCount $minimumCount
    }
}
$superiorSKUs_organization = @{}
foreach ($referenceSKU in $SKUs) {
    foreach ($differenceSKU in $SKUs | Where-Object{$_.skuId -ne $referenceSKU.skuId}) {
        if ($null -ne ($referenceServicePlans = $referenceSKU.servicePlans | Where-Object{$_.appliesTo -eq 'User'}) -and
        $null -ne ($differenceServicePlans = $differenceSKU.servicePlans | Where-Object{$_.appliesTo -eq 'User'})) {
            if ($null -ne ($comparisonSKU = Compare-Object $referenceServicePlans.servicePlanId $differenceServicePlans.servicePlanId -IncludeEqual) -and
            $comparisonSKU.SideIndicator -contains '==' -and
            $comparisonSKU.SideIndicator -notcontains '=>') {
                if (-not $superiorSKUs_organization.ContainsKey($differenceSKU.skuId)) {
                    $superiorSKUs_organization.Add($differenceSKU.skuId, [System.Collections.Generic.List[guid]]::new())
                }
                $superiorSKUs_organization[$differenceSKU.skuId].Add($referenceSKU.skuId)
            }
        }
    }
}
#endregion

#region: Users
# Get users
$users = [System.Collections.Generic.List[hashtable]]::new()
$URI = 'https://graph.microsoft.com/v1.0/users?$select=id,licenseAssignmentStates,userPrincipalName&$top=999'
while ($null -ne $URI) {
    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
    $users.AddRange([hashtable[]]($data.value))
    $URI = $data['@odata.nextLink']
}
# Analyze users
foreach ($user in $users) {
    if ($user.licenseAssignmentStates.count -gt 0) {
        $userSKUs = ($user.licenseAssignmentStates | Where-Object{$_.state -eq 'Active' -or $_.error -in @('CountViolation', 'MutuallyExclusiveViolation')}).skuId
        foreach ($countViolation in ($user.licenseAssignmentStates |
        Where-Object{$_.error -eq 'CountViolation'}).skuId |
        Select-Object -Unique) {
            $results['SKU'][$countViolation]['availableCount'] -= 1
        }
        # Identify interchangeable SKUs, based on earlier specifications
        if ($null -ne $userSKUs) {
            $comparisonInterchangeable = (Compare-Object $userSKUs $interchangeableSKUs -ExcludeDifferent -IncludeEqual).InputObject
        }
        # Identify optimizable SKUs, based on organization-level calculations
        if ($null -ne ($comparison_replaceableOrganization = $userSKUs |
        Where-Object{$_ -in $superiorSKUs_organization.Keys} |
        ForEach-Object{$superiorSKUs_organization[$_]})) {
            $comparisonOptimizable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableOrganization -ExcludeDifferent -IncludeEqual |
            ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_organization.Keys | Where-Object{$superiorSKUs_organization[$_] -contains $superiorSKU}} |
                                        Where-Object{$_ -in $userSKUs} |
                                        Select-Object -Unique
        }
        # Identify removable SKUs, based on user-level calculations
        $skuid_enabledPlans = @{}
        foreach ($skuid in $user.licenseAssignmentStates.skuid | Select-Object -Unique) {
            if (-not $skuid_enabledPlans.ContainsKey($skuid)) {
                $skuid_enabledPlans.Add($skuid, [System.Collections.Generic.List[guid]]::new())
            }
            foreach ($assignment in $user.licenseAssignmentStates | Where-Object{$_.skuid -eq $skuid}) {
                $skuid_enabledPlans[$skuid].AddRange([guid[]]@((($SKUs | Where-Object{$_.skuid -eq $skuid}).servicePlans | Where-Object{$_.servicePlanId -notin $assignment.disabledplans -and $_.appliesTo -eq 'User'}).servicePlanId))
            }
        }
        $superiorSKUs_user = @{}
        foreach ($referenceSKU in $skuid_enabledPlans.Keys) {
            foreach ($differenceSKU in $skuid_enabledPlans.Keys | Where-Object{$_ -ne $referenceSKU}) {
                if ($null -ne ($referenceServicePlans = $skuid_enabledPlans[$referenceSKU]) -and
                $null -ne ($differenceServicePlans = $skuid_enabledPlans[$differenceSKU])) {
                    if ($null -ne ($comparisonSKU = Compare-Object $referenceServicePlans $differenceServicePlans -IncludeEqual) -and
                    $comparisonSKU.SideIndicator -contains '==' -and
                    $comparisonSKU.SideIndicator -notcontains '=>') {
                        if (-not $superiorSKUs_user.ContainsKey($differenceSKU)) {
                            $superiorSKUs_user.Add($differenceSKU, [System.Collections.Generic.List[guid]]::new())
                        }
                        $superiorSKUs_user[$differenceSKU].Add($referenceSKU)
                    }
                }
            }
        }
        if ($null -ne ($comparison_replaceableUser = $userSKUs |
        Where-Object{$_ -in $superiorSKUs_user.Keys} |
        ForEach-Object{$superiorSKUs_user[$_]})) {
            $comparisonRemovable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableUser -ExcludeDifferent -IncludeEqual |
            ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_user.Keys | Where-Object{$superiorSKUs_user[$_] -contains $superiorSKU}} |
                                    Where-Object{$_ -in $userSKUs} |
                                    Select-Object -Unique
        }
        # Add intermediate results to total results
        if ($comparisonInterchangeable.Count -gt 1) {
            Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Interchangeable -ConflictSKUs $comparisonInterchangeable
        }
        if ($null -ne $comparisonOptimizable) {
            Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Optimizable -ConflictSKUs $comparisonOptimizable
        }
        if ($null -ne $comparisonRemovable) {
            Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Removable -ConflictSKUs $comparisonRemovable
        }
    }
}
#endregion

#region: Advanced
if ($advancedCheckups.IsPresent) {
    $AADP1Users = [System.Collections.Generic.List[guid]]::new()
    $AADP2Users = [System.Collections.Generic.List[guid]]::new()
    $ATPUsers = [System.Collections.Generic.List[guid]]::new()
    # Retrieve basic group information
    $URI = 'https://graph.microsoft.com/v1.0/groups?$select=id,groupTypes&$top=999'
    while ($null -ne $URI) {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $groups.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    # Azure AD P1 based on dynamic groups
    $dynamicGroups = $groups | Where-Object{$_.groupTypes -contains 'DynamicMembership'}
    $AADP1Users.AddRange((Get-GroupMembers -GroupIDs $dynamicGroups.id -TransitiveMembers))
    # Azure AD P1 based on group-based application assignments
    $applications = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo&$top=999'
    while ($null -ne $URI) {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $applications.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    $applicationGroups = ($applications | Where-Object{$_.accountEnabled -eq $true -and $_.appRoleAssignmentRequired -eq $true -and $_.servicePrincipalType -eq 'Application'}).appRoleAssignedTo | Where-Object{$_.principalType -eq 'Group'}
    $AADP1Users.AddRange((Get-GroupMembers -GroupIDs $applicationGroups.id -TransitiveMembers))
    # Azure AD P1 based on MFA-enabled users
    $conditionalAccessPolicies = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=conditions,state'
    while ($null -ne $URI) {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $conditionalAccessPolicies.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    foreach ($conditionalAccessPolicy in $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled'}) {
        if ($conditionalAccessPolicy.conditions.users.includeUsers -eq 'All') {
            $includeUsers = $users.id
        }
        else {
            $includeUsers = $conditionalAccessPolicy.conditions.users.includeUsers
        }
        $conditionalAccessUsers = (Compare-Object -ReferenceObject $includeUsers -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeUsers | Where-Object{$_.SideIndicator -eq '<='}).InputObject | Where-Object{$_ -ne 'GuestsOrExternalUsers'}
        $AADP1Users.AddRange([guid[]]$conditionalAccessUsers)
        if ($conditionalAccessPolicy.conditions.users.includeGroups -eq 'All') {
            $includeGroups = $groups.id
        }
        else {
            $includeGroups = $conditionalAccessPolicy.conditions.users.includeGroups
        }
        $conditionalAccessGroups = (Compare-Object -ReferenceObject $includeGroups -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeGroups | Where-Object{$_.SideIndicator -eq '<='}).InputObject
        $AADP1Users.AddRange((Get-GroupMembers -GroupIDs $conditionalAccessGroups.id -TransitiveMembers))
    }
    # Azure AD P2 based on PIM-managed users
    $eligibleRoleMembers = [System.Collections.Generic.List[hashtable]]::new()
    $URI = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,scheduleInfo'
    while ($null -ne $URI) {
        $data = Invoke-MgGraphRequest -Method GET -Uri $URI
        $eligibleRoleMembers.AddRange([hashtable[]]($data.value))
        $URI = $data['@odata.nextLink']
    }
    $AADP2Users.AddRange([guid[]](($eligibleRoleMembers |
                            Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and
                                ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or
                                $_.scheduleInfo.expiration.type -eq 'noExpiration')}).principalId))
    # Defender for Office 365 P1/P2 based on user and shared mailboxes
    #TODO: Improve calculations by checking for license requirements other than Exchange Online mailboxes :https://learn.microsoft.com/office365/servicedescriptions/office-365-advanced-threat-protection-service-description#licensing-terms
    $orgDomain = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains').value.verifiedDomains | Where-Object{$_.isInitial -eq $true}
    Connect-ExchangeOnline -AppId $applicationID -Certificate $x509Cert -Organization $orgDomain.name -CommandName Get-Mailbox
    $ATPUsers.AddRange([guid[]](Get-EXOMailbox -RecipientTypeDetails 'SharedMailbox', 'UserMailbox' -ResultSize Unlimited).ExternalDirectoryObjectId)
    Disconnect-ExchangeOnline -Confirm:$false
    # Results
    #TODO: Lacking better count calculations
    if ($AADP1Users.Count -gt 0) {
        $skuid = '078d2b04-f1bd-4111-bbd4-b4b1b354cef4'
        $AADP1Licenses = ($SKUs | Where-Object{$_.skuid -eq $skuid}).prepaidUnits.enabled
        foreach ($SKU in $superiorSKUs_organization[$skuid]) {
            $AADP1Licenses += ($SKUs | Where-Object{$_.skuid -eq $SKU}).prepaidUnits.enabled
        }
        if ($AADP1Licenses -lt ($neededCount = ($AADP1Users | Select-Object -Unique).Count)) {
            Add-Result -SKUID $skuid -EnabledCount $AADP1Licenses -NeededCount $neededCount
        }
    }
    if ($AADP2Users.Count -gt 0) {
        $skuid = '84a661c4-e949-4bd2-a560-ed7766fcaf2b'
        $AADP2Licenses = ($SKUs | Where-Object{$_.skuid -eq $skuid}).prepaidUnits.enabled
        foreach ($SKU in $superiorSKUs_organization[$skuid]) {
            $AADP2Licenses += ($SKUs | Where-Object{$_.skuid -eq $SKU}).prepaidUnits.enabled
        }
        if ($AADP2Licenses -lt ($neededCount = ($AADP2Users | Select-Object -Unique).Count)) {
            Add-Result -SKUID $skuid -EnabledCount $AADP2Licenses -NeededCount $neededCount
        }
    }
    if ($ATPUsers.Count -gt 0) {
        if ($SKUs.skuId -contains '3dd6cf57-d688-4eed-ba52-9e40b5468c3e') {
            $skuid = '3dd6cf57-d688-4eed-ba52-9e40b5468c3e'
        }
        else {
            $skuid = '4ef96642-f096-40de-a3e9-d83fb2f90211'
        }
        $ATPLicenses = ($SKUs | Where-Object{$_.skuid -eq $skuid}).prepaidUnits.enabled
        foreach ($SKU in $superiorSKUs_organization[$skuid]) {
            $ATPLicenses += ($SKUs | Where-Object{$_.skuid -eq $SKU}).prepaidUnits.enabled
        }
        if ($ATPLicenses -lt ($neededCount = ($ATPUsers | Select-Object -Unique).Count)) {
            Add-Result -SKUID $skuid -EnabledCount $ATPLicenses -NeededCount $neededCount
        }
    }
}
#endregion

#region: Report
if ($results.Values.Count -gt 0) {
    Add-Output -Output $style
    $critical = $false
    # Output licenses with issues
    if ($results['SKU'].Keys.Count -gt 0) {
        Add-Output -Output '<p class=gray>Basic checkup - Products</p>
                            <p>Please check license counts for the following product SKUs and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p>
                            <p><table><tr><th>License type</th><th>Available count</th><th>Minimum count</th><th>Difference</th></tr>'
        foreach ($SKU in $results['SKU'].Keys) {
            $differenceCount = $results['SKU'][$SKU]['availableCount'] - $results['SKU'][$SKU]['minimumCount']
            Add-Output -Output "<tr> `
                                <td>$(Get-SKUName -SKUID $SKU)</td> `
                                <td>$($results['SKU'][$SKU]['availableCount'])</td> `
                                <td>$($results['SKU'][$SKU]['minimumCount'])</td>"
                                if ($results['SKU'][$SKU]['availableCount'] / $results['SKU'][$SKU]['minimumCount'] * 100 -ge $warningPercentageThreshold_basic) {
                Add-Output -Output "<td class=green>$differenceCount</td>"
            }
            elseif ($results['SKU'][$SKU]['availableCount'] / $results['SKU'][$SKU]['minimumCount'] * 100 -le $criticalPercentageThreshold_basic) {
                $critical = $true
                Add-Output -Output "<td class=red>$differenceCount</td>"
            }
            else {
                Add-Output -Output "<td class=yellow>$differenceCount</td>"
            }
            Add-Output -Output '</tr>'
        }
        Add-Output -Output "</table></p> `
        <p>The following criteria were used during the checkup:<ul> `
                            <li>Check products with >$licenseIgnoreThreshold total licenses</li> `
                            <li>Report normal products having both <$licenseTotalThreshold_normalSKUs licenses and <$licensePercentageThreshold_normalSKUs% of their total licenses available</li> `
                            <li>Report important products having both <$licenseTotalThreshold_importantSKUs licenses and <$licensePercentageThreshold_importantSKUs% of their total licenses available</li></ul></p>"
    }
    # Output accounts with issues
    if ($results['User'].Keys.Count -gt 0) {
        Add-Output -Output '<p class=gray>Basic checkup - Users</p>
                            <p>Please check license assignments for the following user accounts and mitigate impact:</p>
                            <p><table><tr><th>Account</th><th>Interchangeable</th><th>Optimizable</th><th>Removable</th></tr>'
        foreach ($user in $results['User'].Keys | Sort-Object) {
            Add-Output -Output "<tr> `
                                <td>$user</td> `
                                <td>$(($results['User'][$user]['Interchangeable'] |
                                        Where-Object{$null -ne $_} |
                                        ForEach-Object{Get-SKUName -SKUID $_} |
                                        Sort-Object) -join '<br>')</td> `
                                <td>$(($results['User'][$user]['Optimizable'] |
                                        Where-Object{$null -ne $_} |
                                        ForEach-Object{Get-SKUName -SKUID $_} |
                                        Sort-Object) -join '<br>')</td> `
                                <td>$(($results['User'][$user]['Removable'] |
                                        Where-Object{$null -ne $_} |
                                        ForEach-Object{Get-SKUName -SKUID $_} |
                                        Sort-Object) -join '<br>')</td> `
                                </tr>"
        }
        Add-Output -Output '</table></p>
                            <p>The following criteria were used during the checkup:<ul>
                            <li>Check accounts with any number of assigned licenses</li>
                            <li>Report theoretically exclusive licenses as <strong>interchangeable</strong>, based on specified SKUs</li>
                            <li>Report practically inclusive licenses as <strong>optimizable</strong>, based on available SKU features</li>
                            <li>Report actually inclusive licenses as <strong>removable</strong>, based on enabled SKU features</li></ul></p>'
    }
    if ($results['Advanced'].Keys.Count -gt 0) {
        Add-Output -Output '<p class=gray>Advanced checkup - Features</p>
                            <p>Please check license counts for the following product SKUs and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p>
                            <p><table><tr><th>License type</th><th>Enabled count</th><th>Needed count</th><th>Difference</th></tr>'
        foreach ($SKU in $results['Advanced'].Keys) {
            $differenceCount = $results['Advanced'][$SKU]['enabledCount'] - $results['Advanced'][$SKU]['neededCount']
            Add-Output -Output "<tr> `
                                <td>$(Get-SKUName -SKUID $SKU)</td> `
                                <td>$($results['Advanced'][$SKU]['enabledCount'])</td> `
                                <td>$($results['Advanced'][$SKU]['neededCount'])</td>"
                                if ($results['Advanced'][$SKU]['enabledCount'] / $results['Advanced'][$SKU]['neededCount'] * 100 -ge $warningPercentageThreshold_advanced) {
                Add-Output -Output "<td class=green>$differenceCount</td>"
            }
            elseif ($results['Advanced'][$SKU]['enabledCount'] / $results['Advanced'][$SKU]['neededCount'] * 100 -le $criticalPercentageThreshold_advanced) {
                $critical = $true
                Add-Output -Output "<td class=red>$differenceCount</td>"
            }
            else {
                Add-Output -Output "<td class=yellow>$differenceCount</td>"
            }
            Add-Output -Output '</tr>'
        }
        Add-Output -Output '</table></p>
                            <p>The following criteria were used during the checkup:<ul>
                            <li>Check <i>Azure AD P1</i> based on group-based application assignments</li>
                            <li>Check <i>Azure AD P1</i> based on dynamic group memberships</li>
                            <li>Check <i>Azure AD P1</i> based on MFA-enabled users</li>
                            <li>Check <i>Azure AD P2</i> based on PIM-managed users</li>
                            <li>Check <i>Defender for Office 365 P1/P2</i> based on user and shared mailboxes</li></ul></p>'
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
    foreach ($recipientAddress in $normalRecipientsAddresses) {
        $email['message']['toRecipients'].Add(@{
            'emailAddress' = @{
                'address' = $recipientAddress
            }
        })
    }
    # Check criticality
    if ($critical) {
        # Replace subject and importance
        $email['message']['subject'] = 'Azure AD licenses need urgent attention'
        $email['message']['importance'] = 'high'
        # Add critical email recipients
        $email['message'].Add('ccRecipients', [System.Collections.Generic.List[hashtable]]::new())
        foreach ($recipientAddress in $criticalRecipientsAddresses) {
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
