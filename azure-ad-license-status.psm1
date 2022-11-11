Set-StrictMode -Version 3.0

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
function Initialize-Variables {
    $script:groups = [System.Collections.Generic.List[hashtable]]::new()
    $script:outputs = [System.Text.StringBuilder]::new()
    $script:results = @{}
    $script:skuTranslate = [string]::new([char[]]((Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -UseBasicParsing).Content)) | ConvertFrom-Csv
}

function Add-Output {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output
    )

    $outputs.AppendLine($Output) | Out-Null
}

function Add-Result {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU')]
        [ValidateNotNullOrEmpty()]
        [guid]$SKUID,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$AvailableCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$MinimumCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'User')]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true, ParameterSetName = 'User')]
        [ValidateSet('Interchangeable','Optimizable','Removable')]
        [string]$ConflictType,
        [Parameter(Mandatory = $true, ParameterSetName = 'User')]
        [ValidateNotNullOrEmpty()]
        [guid[]]$ConflictSKUs,
        [Parameter(Mandatory = $true, ParameterSetName = 'Advanced')]
        [ValidateNotNullOrEmpty()]
        [string]$PlanName,
        [Parameter(Mandatory = $true, ParameterSetName = 'Advanced')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$EnabledCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'Advanced')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$NeededCount
    )

    if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
        $results.Add($PSCmdlet.ParameterSetName, @{})
    }
    switch ($PSCmdlet.ParameterSetName) {
        'Advanced' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($PlanName)) {
                $results[$PSCmdlet.ParameterSetName].Add($PlanName, @{
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

function Get-GroupMember {
    [OutputType([guid[]])]
    param (
        [Parameter(Mandatory = $true)]
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
        if (-not $group.ContainsKey($memberProperty)) {
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

function Get-SKUName {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid]$SKUID
    )

    if ($null -ne ($skuName = ($skuTranslate | Where-Object{$_.GUID -eq $SKUID}).Product_Display_Name | Select-Object -Unique)) {
        $skuName = [cultureinfo]::new('en-US').TextInfo.ToTitleCase($skuName.ToLower())
    }
    else {
        $skuName = $SKUID
    }
    Write-Output $skuName
}

function Get-LicensedUsers {
    [OutputType([guid[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid[]]$PlanIDs
    )

    Write-Output ([guid[]]@($users | Where-Object{$_.ContainsKey('enabledPlans')} | Where-Object{$null -ne (Compare-Object $_.enabledPlans $PlanIDs -ExcludeDifferent -IncludeEqual)})) -NoEnumerate
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
    Specifies the minimum enabled license threshold for SKUs to be considered for the report
    .PARAMETER SKUPercentageThreshold_normal
    Specifies the minimum available license percentage threshold for SKUs to be included in the report
    .PARAMETER SKUTotalThreshold_normal
    Specifies the minimum available license amount threshold for SKUs to be included in the report
    .PARAMETER SKUPercentageThreshold_important
    Specifies the minimum available license percentage threshold for SKUs to be included in the report
    .PARAMETER SKUTotalThreshold_important
    Specifies the minimum available license amount threshold for SKUs to be included in the report
    .PARAMETER SKUWarningThreshold_basic
    Specifies the warning percentage threshold to be used during report creation for basic checkups
    .PARAMETER SKUCriticalThreshold_basic
    Specifies the critical percentage threshold to be used during report creation for basic checkups
    .PARAMETER SKUWarningThreshold_advanced
    Specifies the warning percentage threshold to be used during report creation for advanced checkups
    .PARAMETER SKUCriticalThreshold_advanced
    Specifies the critical percentage threshold to be used during report creation for advanced checkups
    .PARAMETER ImportantSKUs
    Specifies the SKUs which are deemed important, so different thresholds are used for calculation
    .PARAMETER InterchangeableSKUs
    Specifies a list of SKUs which are deemed interchangeable, e.g Office 365 E1 and Office 365 E3
    .PARAMETER LicensingURL
    Specifies a licensing portal URL to be linked in the report, refers to Microsoft's Volume Licensing Service Center by default
    .PARAMETER AdvancedCheckups
    Specifies if advanced license checkups should be run
    ATTENTION: Advanced checkups require additional access permissions and might increase the checkup duration
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -CertificateThumbprint 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com','recipient_2@example.com')

    Prepares a status report with default values by using only necessary parameters for authentication and report delivery
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -CertificateThumbprint 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com','recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com','recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500

    Prepares a status report with customized thresholds for larger organizations and additional recipients for when license counts reach critical levels
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -SubscriptionID '00000000-0000-0000-0000-000000000000' -KeyVaultName 'MyKeyVault' -CertificateName 'MyCertificate' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com','recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com','recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500 -ImportantSKUs @('18181a46-0d4e-45cd-891e-60aabd171b4e','6fd2c87f-b296-42f0-b197-1e91e994b900') -InterchangeableSKUs @('4b585984-651b-448a-9e53-3b10f069cf7f','18181a46-0d4e-45cd-891e-60aabd171b4e','6fd2c87f-b296-42f0-b197-1e91e994b900','c7df2760-2c81-4ef7-b578-5b5392b571df') -AdvancedCheckups

    Prepares a status report by using an Azure certificate for automation purposes, specifying both important and interchangeable SKUs and activating advanced checkups
    #>

    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid]$DirectoryID,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid]$ApplicationID,
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureCertificate')]
        [ValidateNotNullOrEmpty()]
        [guid]$SubscriptionID,
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyVaultName,
        [Parameter(Mandatory = $true, ParameterSetName = 'AzureCertificate')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,
        [Parameter(Mandatory = $true, ParameterSetName = 'LocalCertificate')]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = 'LocalCertificateThumbprint')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SenderAddress,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RecipientAddresses_normal,
        [ValidateNotNullOrEmpty()]
        [string[]]$RecipientAddresses_critical,
        [ValidateNotNullOrEmpty()]
        [UInt32]$SKUIgnoreThreshold = 10,
        [ValidateRange(0, 100)]
        [UInt16]$SKUPercentageThreshold_normal = 5,
        [ValidateNotNullOrEmpty()]
        [UInt32]$SKUTotalThreshold_normal = 10,
        [ValidateRange(0, 100)]
        [UInt16]$SKUPercentageThreshold_important = 5,
        [ValidateNotNullOrEmpty()]
        [UInt32]$SKUTotalThreshold_important = 50,
        [ValidateScript({$_ -in 1..99 -and $_ -gt $SKUCriticalThreshold_basic})]
        [UInt16]$SKUWarningThreshold_basic = 80,
        [ValidateScript({$_ -in 1..99 -and $_ -lt $SKUWarningThreshold_basic})]
        [UInt16]$SKUCriticalThreshold_basic = 20,
        [ValidateScript({$_ -in 1..99 -and $_ -gt $SKUCriticalThreshold_advanced})]
        [UInt16]$SKUWarningThreshold_advanced = 99,
        [ValidateScript({$_ -in 1..99 -and $_ -lt $SKUWarningThreshold_advanced})]
        [UInt16]$SKUCriticalThreshold_advanced = 95,
        [ValidateNotNullOrEmpty()]
        [guid[]]$ImportantSKUs = @(),
        [ValidateNotNullOrEmpty()]
        [guid[]]$InterchangeableSKUs = @(),
        [ValidateNotNullOrEmpty()]
        [string]$LicensingURL = 'https://www.microsoft.com/licensing/servicecenter',
        [switch]$AdvancedCheckups
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'AzureCertificate' {
                Connect-AzAccount -Identity -Subscription $SubscriptionID
                $azureCertificateSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -AsPlainText
                $azureCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($azureCertificateSecret))
                Disconnect-AzAccount
                Connect-MgGraph -Certificate $azureCertificate -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop | Out-Null
            }
            'LocalCertificate' {
                Connect-MgGraph -Certificate $Certificate -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop | Out-Null
            }
            'LocalCertificateThumbprint' {
                Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop | Out-Null
            }
        }
        $graphAuthentication = $true
        Write-Information -MessageData 'Succeeded to authenticate with Graph' -Tags 'Authentication'
    }
    catch {
        $graphAuthentication = $false
        Write-Error -Message 'Failed to authenticate with Graph' -Category AuthenticationError
    }
    if ($graphAuthentication) {
        Initialize-Variables
        #region: SKUs
        # Get SKUs
        $organizationSKUs = [System.Collections.Generic.List[hashtable]]::new()
        $URI = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,prepaidUnits,consumedUnits,servicePlans'
        while ($null -ne $URI) {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $organizationSKUs.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
        Write-Information -MessageData "Found $($organizationSKUs.Count) SKUs" -Tags @('QueryResult')
        # Analyze SKUs
        foreach ($SKU in $organizationSKUs | Where-Object{$_.prepaidUnits.enabled -gt $SKUIgnoreThreshold}) {
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
        foreach ($referenceSKU in $organizationSKUs) {
            foreach ($differenceSKU in $organizationSKUs | Where-Object{$_.skuId -ne $referenceSKU.skuId}) {
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
        Write-Information -MessageData "Found $($superiorSKUs_organization.Count) SKU matches for organization" -Tags @('AnalysisResult')
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
        Write-Information -MessageData "Found $($users.Count) users" -Tags @('QueryResult')
        # Analyze users
        foreach ($user in $users) {
            if ($user.licenseAssignmentStates.count -gt 0) {
                if ($null -ne ($userSKUAssignments = $user.licenseAssignmentStates | Where-Object{$_.state -eq 'Active' -or $_.error -in @('CountViolation', 'MutuallyExclusiveViolation')})) {
                    $userSKUs = $userSKUAssignments.skuId
                }
                else {
                    $userSKUs = @()
                }
                if ($null -ne ($countViolations = $user.licenseAssignmentStates | Where-Object{$_.error -eq 'CountViolation'})) {
                    foreach ($countViolation in $countViolations.skuId | Select-Object -Unique) {
                        $results['SKU'][$countViolation]['availableCount'] -= 1
                    }
                }
                # Identify interchangeable SKUs, based on specifications
                $userSKUs_interchangeable = @()
                if ($null -ne $userSKUs) {
                    if ($null -ne ($comparison_interchangeable = Compare-Object $userSKUs $InterchangeableSKUs -ExcludeDifferent -IncludeEqual)) {
                        $userSKUs_interchangeable = @($comparison_interchangeable.InputObject)
                    }
                }
                # Identify optimizable SKUs, based on organization-level calculations
                $userSKUs_optimizable = [System.Collections.Generic.List[guid]]::new()
                if ($null -ne ($comparison_replaceableOrganization = $userSKUs | Where-Object{$_ -in $superiorSKUs_organization.Keys} | ForEach-Object{$superiorSKUs_organization[$_]})) {
                    # TODO: Rework into foreach loop
                    $userSKUs_optimizable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableOrganization -ExcludeDifferent -IncludeEqual | ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_organization.Keys | Where-Object{$superiorSKUs_organization[$_] -contains $superiorSKU}} | Where-Object{$_ -in $userSKUs} | Select-Object -Unique
                }
                else {
                    $userSKUs_optimizable = $null
                }
                # Identify removable SKUs, based on user-level calculations
                $skuid_enabledPlans = @{}
                foreach ($skuid in $user.licenseAssignmentStates.skuid | Select-Object -Unique) {
                    if (-not $skuid_enabledPlans.ContainsKey($skuid)) {
                        $skuid_enabledPlans.Add($skuid, [System.Collections.Generic.List[guid]]::new())
                    }
                    foreach ($assignment in $user.licenseAssignmentStates | Where-Object{$_.skuid -eq $skuid}) {
                        $skuid_enabledPlans[$skuid].AddRange([guid[]]@((($organizationSKUs | Where-Object{$_.skuid -eq $skuid}).servicePlans | Where-Object{$_.servicePlanId -notin $assignment.disabledplans -and $_.appliesTo -eq 'User'}).servicePlanId))
                    }
                }
                $user.Add('enabledPlans', $skuid_enabledPlans)
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
                if ($null -ne ($comparison_replaceableUser = $userSKUs | Where-Object{$_ -in $superiorSKUs_user.Keys} | ForEach-Object{$superiorSKUs_user[$_]})) {
                    # TODO: Rework into foreach loop
                    $userSKUs_removable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableUser -ExcludeDifferent -IncludeEqual | ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_user.Keys | Where-Object{$superiorSKUs_user[$_] -contains $superiorSKU}} | Where-Object{$_ -in $userSKUs} | Select-Object -Unique
                }
                else {
                    $userSKUs_removable = $null
                }
                # Add results
                if ($userSKUs_interchangeable.Count -gt 1) {
                    Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Interchangeable -ConflictSKUs $userSKUs_interchangeable
                    Write-Information -MessageData "Found $($userSKUs_interchangeable.Count) interchangeable SKUs for user $($user.userPrincipalName)" -Tags @('AnalysisResult')
                }
                if ($null -ne $userSKUs_optimizable) {
                    Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Optimizable -ConflictSKUs $userSKUs_optimizable
                    Write-Information -MessageData "Found $($userSKUs_optimizable.Count) optimizable SKUs for user $($user.userPrincipalName)" -Tags @('AnalysisResult')
                }
                if ($null -ne $userSKUs_removable) {
                    Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Removable -ConflictSKUs $userSKUs_removable
                    Write-Information -MessageData "Found $($userSKUs_removable.Count) removable SKUs for user $($user.userPrincipalName)" -Tags @('AnalysisResult')
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
            Write-Information -MessageData "Found $($groups.Count) groups" -Tags @('QueryResult')
            # Azure AD P1 based on external identities, if not linked to a subscription
            # https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-identities-pricing
            # Azure AD P1 based on dynamic groups
            if ($null -ne ($dynamicGroups = $groups | Where-Object{$_.groupTypes -contains 'DynamicMembership'})) {
                $AADP1Users.AddRange((Get-GroupMember -GroupIDs $dynamicGroups.id -TransitiveMembers))
            }
            # Azure AD P1 based on group-based application assignments
            $applications = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo&$top=999'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $applications.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            Write-Information -MessageData "Found $($applications.Count) service principals" -Tags @('QueryResult')
            if ($null -ne ($applicationGroups = ($applications | Where-Object{$_.accountEnabled -eq $true -and $_.appRoleAssignmentRequired -eq $true -and $_.servicePrincipalType -eq 'Application'}).appRoleAssignedTo | Where-Object{$_.principalType -eq 'Group'})) {
                $AADP1Users.AddRange((Get-GroupMember -GroupIDs $applicationGroups.principalId -TransitiveMembers))
            }
            # Azure AD P1 based on users in scope of Conditional Access
            $conditionalAccessPolicies = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=conditions,state'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $conditionalAccessPolicies.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            Write-Information -MessageData "Found $($conditionalAccessPolicies.Count) conditional access policies" -Tags @('QueryResult')
            foreach ($conditionalAccessPolicy in $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled'}) {
                if ($conditionalAccessPolicy.conditions.users.includeUsers -eq 'All') {
                    $includeUsers = $users.id
                }
                elseif ($null -ne $conditionalAccessPolicy.conditions.users.includeUsers | Where-Object{$_ -ne 'GuestsOrExternalUsers'}) {
                    $includeUsers = @($conditionalAccessPolicy.conditions.users.includeUsers | Where-Object{$_ -ne 'GuestsOrExternalUsers'})
                }
                else {
                    $includeUsers = @()
                }
                if ($null -ne ($conditionalAccessUsers = Compare-Object -ReferenceObject $includeUsers -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeUsers | Where-Object{$_.SideIndicator -eq '<='})) {
                    $AADP1Users.AddRange([guid[]]@($conditionalAccessUsers.InputObject))
                }
                if ($conditionalAccessPolicy.conditions.users.includeGroups -eq 'All') {
                    $includeGroups = $groups.id
                }
                elseif ($null -ne $conditionalAccessPolicy.conditions.users.includeGroups) {
                    $includeGroups = @($conditionalAccessPolicy.conditions.users.includeGroups)
                }
                else {
                    $includeGroups = @()
                }
                if ($null -ne ($conditionalAccessGroups = Compare-Object -ReferenceObject $includeGroups -DifferenceObject $conditionalAccessPolicy.conditions.users.excludeGroups | Where-Object{$_.SideIndicator -eq '<='})) {
                    $AADP1Users.AddRange((Get-GroupMember -GroupIDs $conditionalAccessGroups.InputObject -TransitiveMembers))
                }
            }
            # Azure AD P2 based on users in scope of Privileged Identity Management
            $eligibleRoleMembers = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,scheduleInfo'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $eligibleRoleMembers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            Write-Information -MessageData "Found $($eligibleRoleMembers.Count) eligible role assignments" -Tags @('QueryResult')
            if ($eligibleRoleMembers.Count -gt 0) {
                if ($null -ne ($actuallyEligibleRoleMembers = $eligibleRoleMembers | Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or $_.scheduleInfo.expiration.type -eq 'noExpiration')})) {
                    $AADP2Users.AddRange([guid[]]@($actuallyEligibleRoleMembers.principalId))
                }
            }
            # Defender for Office 365 P1/P2 based on https://learn.microsoft.com/office365/servicedescriptions/office-365-advanced-threat-protection-service-description#licensing-terms
            $orgDomain = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains').value.verifiedDomains | Where-Object{$_.isInitial -eq $true}
            try {
                $neededCmdlets = @('Get-Mailbox',
                                    'Get-SafeLinksRule',
                                    'Get-SafeLinksPolicy',
                                    'Get-SafeAttachmentRule',
                                    'Get-SafeAttachmentPolicy',
                                    'Get-AntiPhishRule',
                                    'Get-AntiPhishPolicy',
                                    'Get-AtpPolicyForO365')
                switch ($PSCmdlet.ParameterSetName) {
                    'AzureCertificate' {
                        Connect-ExchangeOnline -AppId $ApplicationID -Certificate $azureCertificate -Organization $orgDomain.name -CommandName $neededCmdlets -ShowBanner:$false -ErrorAction Stop
                    }
                    'LocalCertificate' {
                        Connect-ExchangeOnline -AppId $ApplicationID -Certificate $Certificate -Organization $orgDomain.name -CommandName $neededCmdlets -ShowBanner:$false -ErrorAction Stop
                    }
                    'LocalCertificateThumbprint' {
                        Connect-ExchangeOnline -AppId $ApplicationID -CertificateThumbprint $CertificateThumbprint -Organization $orgDomain.name -CommandName $neededCmdlets -ShowBanner:$false -ErrorAction Stop
                    }
                }
                $exchangeAuthentication = $true
                Write-Information -MessageData 'Succeeded to authenticate with Exchange Online' -Tags 'Authentication'
            }
            catch {
                $exchangeAuthentication = $false
                Write-Error -Message 'Failed to authenticate with Exchange Online' -Category AuthenticationError
            }
            if ($exchangeAuthentication) {
                if ($null -ne ($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'})) {
                    Write-Information -MessageData "Identified a Defender for Office P2 tenant" -Tags @('QueryResult')
                    # Mailboxes
                    if ($null -ne ($mailboxes = Get-Mailbox -RecipientTypeDetails 'SharedMailbox', 'UserMailbox' -ResultSize Unlimited)) {
                        Write-Information -MessageData "Found $($mailboxes.Count) mailboxes" -Tags @('QueryResult')
                        $ATPUsers.AddRange([guid[]]@($mailboxes.ExternalDirectoryObjectId))
                    }
                    # Safe Attachments for SharePoint/Teams
                    if ((Get-AtpPolicyForO365).EnableATPForSPOTeamsODB) {
                        Write-Information -MessageData "Identified ATP for ODB/SPO/Teams" -Tags @('QueryResult')
                        $ATPUsers.AddRange((Get-LicensedUsers -PlanIDs @('5dbe027f-2339-4123-9542-606e4d348a72','57ff2da0-773e-42df-b2af-ffb7a2317929')))
                    }
                    # Safe Links
                    $defaultSafeLinksPolicy = Get-SafeLinksPolicy | Where-Object{$_.IsBuiltInProtection -eq $true}
                    if ($defaultSafeLinksPolicy.EnableSafeLinksForOffice) {
                        Write-Information -MessageData "Identified Safe Links in default policy" -Tags @('QueryResult')
                        # Add all users licensed for Office: 43de0ff5-c92c-492b-9116-175376d08c38
                        $ATPUsers.AddRange((Get-LicensedUsers -PlanIDs @('43de0ff5-c92c-492b-9116-175376d08c38')))
                    }
                    <#
                    else {
                        foreach ($customSafeLinksPolicy in Get-SafeLinksPolicy | Where-Object{$_.IsBuiltInProtection -eq $false}) {
                            if ($customSafeLinksPolicy.EnableSafeLinksForOffice) {
                                # Add all users licensed for Office and in scope of rule
                                if (($customSafeLinksRule = Get-SafeLinksRule | Where-Object{$_.SafeLinksPolicy -eq $customSafeLinksPolicy.Identity}).State -eq 'Enabled'){
                                    $ATPUsers.AddRange([guid[]]@())
                                }
                            }
                        }
                    }
                    #>
                }
                elseif ($null -ne ($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'})) {
                    Write-Information -MessageData "Identified a Defender for Office P1 tenant" -Tags @('QueryResult')
                }
                Disconnect-ExchangeOnline -Confirm:$false
            }
            # Add results
            if ($AADP1Users.Count -gt 0) {
                if ($null -ne ($AADP1SKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '41781fb2-bc02-4b7c-bd55-b576c07bb09d'}))) {
                    $AADP1Licenses = ($AADP1SKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                }
                else {
                    $AADP1Licenses = 0
                }
                $neededCount = ($AADP1Users | Select-Object -Unique).Count
                Write-Information -MessageData "Found $neededCount needed, $AADP1Licenses enabled AADP1 licenses" -Tags @('AnalysisResult')
                if ($AADP1Licenses -lt $neededCount) {
                    Add-Result -PlanName 'Azure Active Directory Premium P1' -EnabledCount $AADP1Licenses -NeededCount $neededCount
                }
            }
            if ($AADP2Users.Count -gt 0) {
                if ($null -ne ($AADP2SKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains 'eec0eb4f-6444-4f95-aba0-50c24d67f998'}))) {
                    $AADP2Licenses = ($AADP2SKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                }
                else {
                    $AADP2Licenses = 0
                }
                $neededCount = ($AADP2Users | Select-Object -Unique).Count
                Write-Information -MessageData "Found $neededCount needed, $AADP1Licenses enabled AADP2 licenses" -Tags @('AnalysisResult')
                if ($AADP2Licenses -lt $neededCount) {
                    Add-Result -PlanName 'Azure Active Directory Premium P2' -EnabledCount $AADP2Licenses -NeededCount $neededCount
                }
            }
            if ($ATPUsers.Count -gt 0) {
                if ($null -ne ($ATPSKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'}))) {
                    $ATPLicenses = ($ATPSKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                    $neededCount = ($ATPUsers | Select-Object -Unique).Count
                    Write-Information -MessageData "Found $neededCount needed, $AADP1Licenses enabled DfOP2 licenses" -Tags @('AnalysisResult')
                    if ($ATPLicenses -lt $neededCount) {
                        Add-Result -PlanName 'Microsoft Defender for Office 365 P2' -EnabledCount $ATPLicenses -NeededCount $neededCount
                    }
                }
                elseif ($null -ne ($ATPSKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'}))) {
                    $ATPLicenses = ($ATPSKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                    $neededCount = ($ATPUsers | Select-Object -Unique).Count
                    Write-Information -MessageData "Found $neededCount needed, $AADP1Licenses enabled DfOP2 licenses" -Tags @('AnalysisResult')
                    if ($ATPLicenses -lt $neededCount) {
                        Add-Result -PlanName 'Microsoft Defender for Office 365 P1' -EnabledCount $ATPLicenses -NeededCount $neededCount
                    }
                }
            }
        }
        #endregion

        #region: Report
        if ($results.Values.Count -gt 0) {
            Add-Output -Output $style
            $critical = $false
            # Output basic SKU results
            if ($results.ContainsKey('SKU')) {
                Add-Output -Output "<p class=gray>Basic checkup - Products</p> `
                                    <p>Please check license counts for the following product SKUs and <a href=""$LicensingURL"">reserve</a> additional licenses:</p> `
                                    <p><table><tr><th>License type</th><th>Available count</th><th>Minimum count</th><th>Difference</th></tr>"
                foreach ($SKU in $results['SKU'].Keys) {
                    $differenceCount = $results['SKU'][$SKU]['availableCount'] - $results['SKU'][$SKU]['minimumCount']
                    Add-Output -Output "<tr> `
                                        <td>$(Get-SKUName -SKUID $SKU)</td> `
                                        <td>$($results['SKU'][$SKU]['availableCount'])</td> `
                                        <td>$($results['SKU'][$SKU]['minimumCount'])</td>"
                    if ($results['SKU'][$SKU]['availableCount'] / $results['SKU'][$SKU]['minimumCount'] * 100 -ge $SKUWarningThreshold_basic) {
                        Add-Output -Output "<td class=green>$differenceCount</td>"
                    }
                    elseif ($results['SKU'][$SKU]['availableCount'] / $results['SKU'][$SKU]['minimumCount'] * 100 -le $SKUCriticalThreshold_basic) {
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
            # Output advanced SKU results
            if ($results.ContainsKey('Advanced')) {
                Add-Output -Output "<p class=gray>Advanced checkup - Products</p> `
                                    <p>Please check license counts for the following product SKUs and <a href=""$LicensingURL"">reserve</a> additional licenses:</p> `
                                    <p><table><tr><th>License type</th><th>Enabled count</th><th>Needed count</th><th>Difference</th></tr>"
                foreach ($plan in $results['Advanced'].Keys) {
                    $differenceCount = $results['Advanced'][$plan]['enabledCount'] - $results['Advanced'][$plan]['neededCount']
                    Add-Output -Output "<tr> `
                                        <td>$plan</td> `
                                        <td>$($results['Advanced'][$plan]['enabledCount'])</td> `
                                        <td>$($results['Advanced'][$plan]['neededCount'])</td>"
                    if ($results['Advanced'][$plan]['enabledCount'] / $results['Advanced'][$plan]['neededCount'] * 100 -ge $SKUWarningThreshold_advanced) {
                        Add-Output -Output "<td class=green>$differenceCount</td>"
                    }
                    elseif ($results['Advanced'][$plan]['enabledCount'] / $results['Advanced'][$plan]['neededCount'] * 100 -le $SKUCriticalThreshold_advanced) {
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
            # Output basic user results
            if ($results.ContainsKey('User')) {
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

        Disconnect-MgGraph | Out-Null
    }
}