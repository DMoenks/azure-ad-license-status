Set-StrictMode -Version 1.0

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

#region: Helper functions
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
        [ValidateRange('NonNegative')]
        [int]$EnabledCount,
        [Parameter(Mandatory=$true, ParameterSetName='Advanced')]
        [ValidateRange('NonNegative')]
        [int]$NeededCount,
        [Parameter(Mandatory=$true, ParameterSetName='SKU')]
        [ValidateRange('NonNegative')]
        [int]$AvailableCount,
        [Parameter(Mandatory=$true, ParameterSetName='SKU')]
        [ValidateRange('NonNegative')]
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
function Get-GroupMember {
    [OutputType([guid[]])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
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
        $group = $groups | Where-Object{$_.id -eq $groupID}
        if ($null -eq $group.$memberProperty) {
            $groupMembers = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/{1}?$select=id' -f $groupID, $memberProperty
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $groupMembers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            $group.Add($memberProperty, $groupMembers)
        }
    }
    Write-Output ([guid[]]@(($groups | Where-Object{$_.id -in $GroupIDs}).$memberProperty.id | Select-Object -Unique)) -NoEnumerate
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
    Write-Output $skuName
}
#endregion

function Get-AzureADLicenseStatus {
    <#
    .SYNOPSIS
    Create an Azure AD license report for operative tasks based on license consumption and assignments
    .DESCRIPTION
    This script is meant to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

    SKU IDs and names are in accordance with https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
    .PARAMETER DirectoryID
    Specifies the directory to connect to
    .PARAMETER ApplicationID
    Specifies the application in target directory to authenticate with
    .PARAMETER SubscriptionID
    Specifies the subscription in target directory to access
    .PARAMETER KeyVaultName
    Specifies the key vault in target subscription to access
    .PARAMETER CertificateName
    Specifies the certificate name in target key vault to use for authentication
    .PARAMETER Certificate
    Specifies the certificate to use for authentication
    .PARAMETER CertificateThumbprint
    Specifies the certificate thumbprint in local certificate store to use for authentication
    .PARAMETER SenderAddress
    Specifies the sender address to be used for report delivery
    .PARAMETER RecipientAddresses_normal
    Specifies the recipient addresses to be used for report delivery
    .PARAMETER RecipientAddresses_critical
    Specifies the additional recipient addresses to be used for report delivery in critical cases
    .PARAMETER SKUIgnoreThreshold
    Specifies the minimum enabled license threshold for SKUs to be taken into account for the report
    .PARAMETER SKUPercentageThreshold_normal
    Specifies the minimum available license percentage threshold for SKUs to be included in the report
    .PARAMETER SKUTotalThreshold_normal
    Specifies the minimum available license amount threshold for SKUs to be included in the report
    .PARAMETER SKUPercentageThreshold_important
    Specifies the minimum available license percentage threshold for SKUs to be included in the report
    .PARAMETER SKUTotalThreshold_important
    Specifies the minimum available license amount threshold for SKUs to be included in the report
    .PARAMETER WarningPercentageThreshold_basic
    Specifies the warning percentage threshold to be used during report creation for basic checkups
    .PARAMETER CriticalPercentageThreshold_basic
    Specifies the critical percentage threshold to be used during report creation for basic checkups
    .PARAMETER WarningPercentageThreshold_advanced
    Specifies the warning percentage threshold to be used during report creation for advanced checkups
    .PARAMETER CriticalPercentageThreshold_advanced
    Specifies the critical percentage threshold to be used during report creation for advanced checkups
    .PARAMETER ImportantSKUs
    Specifies the SKUs which are deemed important, so different thresholds are used for calculation
    .PARAMETER InterchangeableSKUs
    Specifies a single list of SKUs which are deemed interchangeable, e.g Office 365 E1 and Office 365 E3
    .PARAMETER AdvancedCheckups
    Specifies if advanced license checkups should be run
    ATTENTION: Advanced checkups require additional access permissions and might increase the checkup duration
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -CertificateThumbprint 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com','recipient_2@example.com')

    Runs a status report with default values by providing only necessary values for authentication and report delivery
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -CertificateThumbprint 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com','recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com','recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500

    Runs a status report with customized thresholds for larger organizations and additional recipients for when licenses counts reach critical levels
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -SubscriptionID '00000000-0000-0000-0000-000000000000' -KeyVaultName 'MyKeyVault' -CertificateName 'MyCertificate' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com','recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com','recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500 -ImportantSKUs @('18181a46-0d4e-45cd-891e-60aabd171b4e','6fd2c87f-b296-42f0-b197-1e91e994b900') -InterchangeableSKUs @('4b585984-651b-448a-9e53-3b10f069cf7f','18181a46-0d4e-45cd-891e-60aabd171b4e','6fd2c87f-b296-42f0-b197-1e91e994b900','c7df2760-2c81-4ef7-b578-5b5392b571df') -AdvancedCheckups

    Runs a status report by using an Azure certificate for automation purposes, specifying both important and interchangeable SKUs and activating advanced checkups
    #>

    [CmdletBinding(PositionalBinding=$false)]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [guid]$DirectoryID,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [guid]$ApplicationID,
        [Parameter(Mandatory=$true, ParameterSetName='AzureCertificate')]
        [ValidateNotNullOrEmpty()]
        [guid]$SubscriptionID,
        [Parameter(Mandatory=$true, ParameterSetName='AzureCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyVaultName,
        [Parameter(Mandatory=$true, ParameterSetName='AzureCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,
        [Parameter(Mandatory=$true, ParameterSetName='LocalCertificate')]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$true, ParameterSetName='LocalCertificateThumbprint')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SenderAddress,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RecipientAddresses_normal,
        [ValidateNotNullOrEmpty()]
        [string[]]$RecipientAddresses_critical,
        [ValidateRange('NonNegative')]
        [int]$SKUIgnoreThreshold = 10,
        [ValidateRange(0, 100)]
        [int]$SKUPercentageThreshold_normal = 5,
        [ValidateRange('NonNegative')]
        [int]$SKUTotalThreshold_normal = 10,
        [ValidateRange(0, 100)]
        [int]$SKUPercentageThreshold_important = 5,
        [ValidateRange('NonNegative')]
        [int]$SKUTotalThreshold_important = 50,
        [ValidateScript({$_ -in 1..99 -and $_ -gt $CriticalPercentageThreshold_basic})]
        [int]$WarningPercentageThreshold_basic = 80,
        [ValidateScript({$_ -in 1..99 -and $_ -lt $WarningPercentageThreshold_basic})]
        [int]$CriticalPercentageThreshold_basic = 20,
        [ValidateScript({$_ -in 1..99 -and $_ -gt $CriticalPercentageThreshold_advanced})]
        [int]$WarningPercentageThreshold_advanced = 99,
        [ValidateScript({$_ -in 1..99 -and $_ -lt $WarningPercentageThreshold_advanced})]
        [int]$CriticalPercentageThreshold_advanced = 95,
        [ValidateNotNullOrEmpty()]
        [guid[]]$ImportantSKUs = @(),
        [ValidateNotNullOrEmpty()]
        [guid[]]$InterchangeableSKUs = @(),
        [switch]$AdvancedCheckups
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'AzureCertificate' {
                Connect-AzAccount -Identity -Subscription $SubscriptionID | Out-Null
                $azCertSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -AsPlainText
                $azCertSecretByte = [Convert]::FromBase64String($azCertSecret)
                $x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($azCertSecretByte)
                Disconnect-AzAccount
                Connect-MgGraph -Certificate $x509Cert -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop | Out-Null
            }
            'LocalCertificate' {
                Connect-MgGraph -Certificate $Certificate -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop | Out-Null
            }
            'LocalCertificateThumbprint' {
                Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop | Out-Null
            }
        }
        $graphAuthentication = $true
    }
    catch {
        $graphAuthentication = $false
    }
    if ($graphAuthentication) {
        #region: SKUs
        # Get SKUs
        $SKUs = [System.Collections.Generic.List[hashtable]]::new()
        $URI = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,prepaidUnits,consumedUnits,servicePlans'
        while ($null -ne $URI) {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $SKUs.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
        # Analyze SKUs
        foreach ($SKU in $SKUs | Where-Object{$_.prepaidUnits.enabled -gt $SKUIgnoreThreshold}) {
            $totalCount = $SKU.prepaidUnits.enabled
            $availableCount = $SKU.prepaidUnits.enabled - $SKU.consumedUnits
            if ($SKU.skuId -in $ImportantSKUs) {
                $percentageThreshold = $SKUPercentageThreshold_important
                $totalThreshold = $SKUTotalThreshold_important
            }
            else {
                $percentageThreshold = $SKUPercentageThreshold_normal
                $totalThreshold = $SKUTotalThreshold_normal
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
                # Identify interchangeable SKUs, based on specifications
                if ($null -ne $userSKUs) {
                    $comparisonInterchangeable = (Compare-Object $userSKUs $InterchangeableSKUs -ExcludeDifferent -IncludeEqual).InputObject
                }
                else {
                    $comparisonInterchangeable = @()
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
                else {
                    $comparisonOptimizable = $null
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
                else {
                    $comparisonRemovable = $null
                }
                # Add results
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
        if ($AdvancedCheckups) {
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
            $AADP1Users.AddRange((Get-GroupMember -GroupIDs $dynamicGroups.id -TransitiveMembers))
            # Azure AD P1 based on group-based application assignments
            $applications = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo&$top=999'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $applications.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            $applicationGroups = ($applications | Where-Object{$_.accountEnabled -eq $true -and $_.appRoleAssignmentRequired -eq $true -and $_.servicePrincipalType -eq 'Application'}).appRoleAssignedTo | Where-Object{$_.principalType -eq 'Group'}
            $AADP1Users.AddRange((Get-GroupMember -GroupIDs $applicationGroups.principalId -TransitiveMembers))
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
                if ($null -ne ($conditionalAccessUsers = (Compare-Object -ReferenceObject $includeUsers -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeUsers | Where-Object{$_.SideIndicator -eq '<='}).InputObject | Where-Object{$_ -ne 'GuestsOrExternalUsers'})) {
                    $AADP1Users.AddRange([guid[]]@($conditionalAccessUsers))
                }
                if ($conditionalAccessPolicy.conditions.users.includeGroups -eq 'All') {
                    $includeGroups = $groups.id
                }
                else {
                    $includeGroups = $conditionalAccessPolicy.conditions.users.includeGroups
                }
                if ($null -ne ($conditionalAccessGroups = (Compare-Object -ReferenceObject $includeGroups -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeGroups | Where-Object{$_.SideIndicator -eq '<='}).InputObject)) {
                    $AADP1Users.AddRange((Get-GroupMember -GroupIDs $conditionalAccessGroups -TransitiveMembers))
                }
            }
            # Azure AD P2 based on PIM-managed users
            $eligibleRoleMembers = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,scheduleInfo'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $eligibleRoleMembers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            $AADP2Users.AddRange([guid[]]@(($eligibleRoleMembers |
                                    Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and
                                        ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or
                                        $_.scheduleInfo.expiration.type -eq 'noExpiration')}).principalId))
            # Defender for Office 365 P1/P2 based on user and shared mailboxes
            $orgDomain = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains').value.verifiedDomains | Where-Object{$_.isInitial -eq $true}
            try {
                switch ($PSCmdlet.ParameterSetName) {
                    'AzureCertificate' {
                        Connect-ExchangeOnline -AppId $ApplicationID -Certificate $x509Cert -Organization $orgDomain.name -CommandName Get-Mailbox -ErrorAction Stop
                    }
                    'LocalCertificate' {
                        Connect-ExchangeOnline -AppId $ApplicationID -Certificate $Certificate -Organization $orgDomain.name -CommandName Get-Mailbox -ErrorAction Stop
                    }
                    'LocalCertificateThumbprint' {
                        Connect-ExchangeOnline -AppId $ApplicationID -CertificateThumbprint $CertificateThumbprint -Organization $orgDomain.name -CommandName Get-Mailbox -ErrorAction Stop
                    }
                }
                $exchangeAuthentication = $true
            }
            catch {
                $exchangeAuthentication = $false
            }
            if ($exchangeAuthentication) {
                if ($null -ne ($mailboxes = Get-EXOMailbox -RecipientTypeDetails 'SharedMailbox', 'UserMailbox' -ResultSize Unlimited)) {
                    $ATPUsers.AddRange([guid[]]@($mailboxes.ExternalDirectoryObjectId))
                }
                Disconnect-ExchangeOnline -Confirm:$false
            }
            # Add results
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
            # Output basic SKU results
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
                                        if ($results['SKU'][$SKU]['availableCount'] / $results['SKU'][$SKU]['minimumCount'] * 100 -ge $WarningPercentageThreshold_basic) {
                        Add-Output -Output "<td class=green>$differenceCount</td>"
                    }
                    elseif ($results['SKU'][$SKU]['availableCount'] / $results['SKU'][$SKU]['minimumCount'] * 100 -le $CriticalPercentageThreshold_basic) {
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
                                    <li>Check products with >$SKUIgnoreThreshold total licenses</li> `
                                    <li>Report normal products having both <$SKUTotalThreshold_normal licenses and <$SKUPercentageThreshold_normal% of their total licenses available</li> `
                                    <li>Report important products having both <$SKUTotalThreshold_important licenses and <$SKUPercentageThreshold_important% of their total licenses available</li></ul></p>"
            }
            # Output basic user results
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
            # Output advanced SKU results
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
                                        if ($results['Advanced'][$SKU]['enabledCount'] / $results['Advanced'][$SKU]['neededCount'] * 100 -ge $WarningPercentageThreshold_advanced) {
                        Add-Output -Output "<td class=green>$differenceCount</td>"
                    }
                    elseif ($results['Advanced'][$SKU]['enabledCount'] / $results['Advanced'][$SKU]['neededCount'] * 100 -le $CriticalPercentageThreshold_advanced) {
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
            # Configure and send email
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
            $email['message'].Add('toRecipients', [System.Collections.Generic.List[hashtable]]::new())
            foreach ($recipientAddress in $RecipientAddresses_normal) {
                $email['message']['toRecipients'].Add(@{
                    'emailAddress' = @{
                        'address' = $recipientAddress
                    }
                })
            }
            if ($critical) {
                $email['message']['subject'] = 'Azure AD licenses need urgent attention'
                $email['message']['importance'] = 'high'
                $email['message'].Add('ccRecipients', [System.Collections.Generic.List[hashtable]]::new())
                foreach ($recipientAddress in $RecipientAddresses_critical) {
                    $email['message']['ccRecipients'].Add(@{
                        'emailAddress' = @{
                            'address' = $recipientAddress
                        }
                    })
                }
            }
            Invoke-MgGraphRequest -Method POST -Uri ('https://graph.microsoft.com/v1.0/users/{0}/sendMail' -f $SenderAddress) -Body $email -ContentType 'application/json'
        }
        #endregion

        Disconnect-MgGraph
    }
}