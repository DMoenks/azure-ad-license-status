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
    # Process
    $script:nestingLevel = 1
    # General
    $script:groups = [System.Collections.Generic.List[hashtable]]::new()
    $script:outputs = [System.Text.StringBuilder]::new()
    $script:results = @{}
    $script:skuTranslate = [string]::new([char[]]((Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -UseBasicParsing).Content)) | ConvertFrom-Csv
    # Exchange Online
    $script:EXOCmdlets = @('Get-Recipient',
                            'Get-DistributionGroupMember',
                            'Get-UnifiedGroupLinks',
                            'Get-ATPBuiltInProtectionRule',
                            'Get-ATPProtectionPolicyRule',
                            'Get-AntiPhishRule',
                            'Get-AntiPhishPolicy',
                            'Get-SafeAttachmentRule',
                            'Get-SafeAttachmentPolicy',
                            'Get-SafeLinksRule',
                            'Get-SafeLinksPolicy')
    $script:EXOProperties = @('ExchangeObjectId',
                            'ExternalDirectoryObjectId',
                            'PrimarySmtpAddress',
                            'RecipientTypeDetails')
    $script:EXOTypes_group = @('GroupMailbox',
                            'MailUniversalDistributionGroup',
                            'MailUniversalSecurityGroup')
    $script:EXOTypes_user = @('SharedMailbox',
                            'UserMailbox')
}

function Write-VerboseMessage {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    Write-Verbose -Message "$([string]::new('-', $nestingLevel)) $Message"
}

function Add-Output {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output
    )
    $nestingLevel++
    Write-VerboseMessage 'Add-Output'

    $outputs.AppendLine($Output) | Out-Null
    $nestingLevel--
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
        [ValidateSet('Interchangeable', 'Optimizable', 'Removable')]
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
    $nestingLevel++
    Write-VerboseMessage 'Add-Result'

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
    $nestingLevel--
}

function Get-AADGroupMembers {
    [OutputType([guid[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid[]]$GroupIDs
    )
    $nestingLevel++
    Write-VerboseMessage 'Get-AADGroupMembers'

    $groupMembers = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($groupID in $GroupIDs) {
        $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?$select=id' -f $groupID
        while ($null -ne $URI) {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $groupMembers.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
    }
    $groupMembers_unique = @($groupMembers.id | Select-Object -Unique)
    Write-VerboseMessage "Found $($groupMembers_unique.Count) members"
    $nestingLevel--
    Write-Output ([guid[]]$groupMembers_unique) -NoEnumerate
}

function Get-EXOGroupMembers {
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid[]]$GroupIDs
    )
    $nestingLevel++
    Write-VerboseMessage 'Get-EXOGroupMembers'

    $groupMembers = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($groupID in $GroupIDs) {
        if ($null -ne ($group = Get-Recipient $groupID.Guid -RecipientTypeDetails $EXOTypes_group | Select-Object -Property $EXOProperties)) {
            switch ($group.RecipientTypeDetails) {
                'GroupMailbox' {
                    $members = @(Get-UnifiedGroupLinks $group.ExchangeObjectId.Guid -LinkType Members -ResultSize Unlimited | Select-Object -Property $EXOProperties)
                }
                Default {
                    $members = @(Get-DistributionGroupMember $group.ExchangeObjectId.Guid -ResultSize Unlimited | Select-Object -Property $EXOProperties)
                }
            }
            foreach ($member in $members) {
                switch ($member.RecipientTypeDetails) {
                    {$_ -in $EXOTypes_user} {
                        $groupMembers.Add($member)
                    }
                    {$_ -in $EXOTypes_group} {
                        $groupMembers.AddRange((Get-EXOGroupMembers -GroupIDs $member.ExchangeObjectId))
                    }
                }
            }
        }
    }
    $groupMembers_unique = @($groupMembers | Select-Object -Unique)
    Write-VerboseMessage "Found $($groupMembers_unique.Count) members"
    $nestingLevel--
    Write-Output ([pscustomobject[]]$groupMembers_unique) -NoEnumerate
}

function Resolve-ATPRecipients {
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$Users,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$Groups,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$Domains
    )
    $nestingLevel++
    Write-VerboseMessage 'Resolve-ATPRecipients'

    $categoryCount = 0
    $affectedAsUser = [System.Collections.Generic.List[pscustomobject]]::new()
    $affectedAsGroup = [System.Collections.Generic.List[pscustomobject]]::new()
    $affectedAsDomain = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($null -ne $Users) {
        $categoryCount++
        if ($null -ne ($recipients = Get-Recipient -RecipientTypeDetails $EXOTypes_user -ResultSize Unlimited | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress -in $Users})) {
            $affectedAsUser.AddRange([pscustomobject[]]@($recipients))
        }
    }
    Write-VerboseMessage "Found $($affectedAsUser.Count) recipients by users"
    if ($null -ne $Groups) {
        $categoryCount++
        if ($null -ne ($recipients = Get-Recipient -RecipientTypeDetails $EXOTypes_group -ResultSize Unlimited | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress -in $Groups})) {
            $affectedAsGroup.AddRange((Get-EXOGroupMembers -GroupIDs $recipients.ExchangeObjectId))
        }
    }
    Write-VerboseMessage "Found $($affectedAsGroup.Count) recipients by groups"
    if ($null -ne $Domains) {
        $categoryCount++
        if ($null -ne ($recipients = Get-Recipient -RecipientTypeDetails $EXOTypes_user -ResultSize Unlimited | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress.Split('@')[1] -in $Domains})) {
            $affectedAsDomain.AddRange([pscustomobject[]]@($recipients))
        }
        if ($null -ne ($recipients = Get-Recipient -RecipientTypeDetails $EXOTypes_group -ResultSize Unlimited | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress.Split('@')[1] -in $Domains})) {
            $affectedAsDomain.AddRange((Get-EXOGroupMembers -GroupIDs $recipients.ExchangeObjectId))
        }
    }
    Write-VerboseMessage "Found $($affectedAsDomain.Count) recipients by domains"
    if ($null -ne ($resolvedUsers = @($affectedAsUser | Select-Object -Unique) + @($affectedAsGroup | Select-Object -Unique) + @($affectedAsDomain | Select-Object -Unique) | Group-Object -Property ExchangeObjectId | Where-Object{$_.Count -eq $categoryCount})) {
        $resolvedUsers_unique = @($resolvedUsers.Group | Select-Object -Unique)
        Write-VerboseMessage "Found $($resolvedUsers_unique.Count) recipients by combination"
        $nestingLevel--
        Write-Output ([pscustomobject[]]$resolvedUsers_unique) -NoEnumerate
    }
    else {
        Write-VerboseMessage "Found 0 recipients by combination"
        $nestingLevel--
        Write-Output @([pscustomobject[]]::new(0)) -NoEnumerate
    }
}

function Get-ATPRecipients {
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$IncludedUsers,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$IncludedGroups,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$IncludedDomains,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$ExcludedUsers,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$ExcludedGroups,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]$ExcludedDomains
    )
    $nestingLevel++
    Write-VerboseMessage 'Get-ATPRecipients'

    Write-VerboseMessage 'Checking included recipients'
    if ($null -eq $IncludedUsers -and
    $null -eq $IncludedGroups -and
    $null -eq $IncludedDomains) {
        $userRecipients = @(Get-Recipient -RecipientTypeDetails $EXOTypes_user -ResultSize Unlimited | Select-Object -Property $EXOProperties)
        $groupRecipients = Get-EXOGroupMembers -GroupIDs (Get-Recipient -RecipientTypeDetails $EXOTypes_group -ResultSize Unlimited).ExchangeObjectId
        $includedRecipients = $userRecipients + $groupRecipients | Select-Object -Unique
    }
    else {
        $includedRecipients = Resolve-ATPRecipients -Users $IncludedUsers -Groups $IncludedGroups -Domains $IncludedDomains
    }
    Write-VerboseMessage "Found $($includedRecipients.Count) included recipients"
    Write-VerboseMessage 'Checking excluded recipients'
    if ($null -eq $ExcludedUsers -and
    $null -eq $ExcludedGroups -and
    $null -eq $ExcludedDomains) {
        $excludedRecipients = @()
    }
    else {
        $excludedRecipients = Resolve-ATPRecipients -Users $ExcludedUsers -Groups $ExcludedGroups -Domains $ExcludedDomains
    }
    Write-VerboseMessage "Found $($excludedRecipients.Count) excluded recipients"
    Write-VerboseMessage 'Checking affected recipients'
    $affectedRecipients = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($null -ne ($affectedRecipientComparison = Compare-Object -ReferenceObject $includedRecipients -DifferenceObject $excludedRecipients)) {
        if ($null -ne ($affectedRecipientResults = $affectedRecipientComparison | Where-Object{$_.SideIndicator -eq '<='})) {
            $affectedRecipients.AddRange([pscustomobject[]]@($affectedRecipientResults.InputObject))
        }
    }
    $affectedRecipients_unique = @($affectedRecipients | Select-Object -Unique)
    Write-VerboseMessage "Found $($affectedRecipients_unique.Count) affected recipients"
    $nestingLevel--
    Write-Output ([pscustomobject[]]$affectedRecipients_unique) -NoEnumerate
}

function Get-SKUName {
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid]$SKUID
    )
    $nestingLevel++
    Write-VerboseMessage 'Get-SKUName'

    if ($null -ne ($skuName = ($skuTranslate | Where-Object{$_.GUID -eq $SKUID}).Product_Display_Name | Select-Object -Unique)) {
        $skuName = [cultureinfo]::new('en-US').TextInfo.ToTitleCase($skuName.ToLower())
    }
    else {
        $skuName = $SKUID
    }
    $nestingLevel--
    Write-Output $skuName
}
#endregion

function Get-AzureADLicenseStatus {
    <#
    .SYNOPSIS
    Create an Azure AD license report for operative tasks based on license consumption and assignments
    .DESCRIPTION
    This script is meant to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

    SKU IDs and names are in accordance with https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
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
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -CertificateThumbprint 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com', 'recipient_2@example.com')

    Prepares a status report with default values by using only necessary parameters for authentication and report delivery
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -CertificateThumbprint 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com', 'recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com', 'recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500

    Prepares a status report with customized thresholds for larger organizations and additional recipients for when license counts reach critical levels
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -SubscriptionID '00000000-0000-0000-0000-000000000000' -KeyVaultName 'MyKeyVault' -CertificateName 'MyCertificate' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com', 'recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com', 'recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500 -ImportantSKUs @('18181a46-0d4e-45cd-891e-60aabd171b4e', '6fd2c87f-b296-42f0-b197-1e91e994b900') -InterchangeableSKUs @('4b585984-651b-448a-9e53-3b10f069cf7f', '18181a46-0d4e-45cd-891e-60aabd171b4e', '6fd2c87f-b296-42f0-b197-1e91e994b900', 'c7df2760-2c81-4ef7-b578-5b5392b571df') -AdvancedCheckups

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

    Initialize-Variables
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
        Write-VerboseMessage 'Succeeded to authenticate with Graph'
    }
    catch {
        $graphAuthentication = $false
        Write-Error -Message 'Failed to authenticate with Graph' -Category AuthenticationError
    }
    if ($graphAuthentication) {
        #region: SKUs
        # Get SKUs
        $organizationSKUs = [System.Collections.Generic.List[hashtable]]::new()
        $URI = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,prepaidUnits,consumedUnits,servicePlans'
        while ($null -ne $URI) {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $organizationSKUs.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
        Write-VerboseMessage "Found $($organizationSKUs.Count) SKUs"
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
                    if ($null -ne ($comparisonSKU = Compare-Object -ReferenceObject $referenceServicePlans.servicePlanId -DifferenceObject $differenceServicePlans.servicePlanId -IncludeEqual) -and
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
        Write-VerboseMessage "Found $($superiorSKUs_organization.Count) SKU matches for organization"
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
        Write-VerboseMessage "Found $($users.Count) users"
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
                    if ($null -ne ($comparison_interchangeable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $InterchangeableSKUs -ExcludeDifferent -IncludeEqual)) {
                        $userSKUs_interchangeable = @($comparison_interchangeable.InputObject)
                    }
                }
                # Identify optimizable SKUs, based on organization-level calculations
                if ($null -ne ($comparison_replaceableOrganization = $userSKUs | Where-Object{$_ -in $superiorSKUs_organization.Keys} | ForEach-Object{$superiorSKUs_organization[$_]})) {
                    $userSKUs_optimizable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableOrganization -ExcludeDifferent -IncludeEqual | ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_organization.Keys | Where-Object{$superiorSKUs_organization[$_] -contains $superiorSKU}} | Where-Object{$_ -in $userSKUs} | Select-Object -Unique
                }
                else {
                    $userSKUs_optimizable = $null
                }
                # Identify removable SKUs, based on user-level calculations
                $skuid_enabledPlans = @{}
                foreach ($skuid in $user.licenseAssignmentStates.skuid | Where-Object{$organizationSKUs.skuId -contains $_} | Select-Object -Unique) {
                    if (-not $skuid_enabledPlans.ContainsKey($skuid)) {
                        $skuid_enabledPlans.Add($skuid, [System.Collections.Generic.List[guid]]::new())
                    }
                    foreach ($assignment in $user.licenseAssignmentStates | Where-Object{$_.skuid -eq $skuid}) {
                        $skuid_enabledPlans[$skuid].AddRange([guid[]]@((($organizationSKUs | Where-Object{$_.skuid -eq $skuid}).servicePlans | Where-Object{$_.servicePlanId -notin $assignment.disabledPlans -and $_.appliesTo -eq 'User'}).servicePlanId))
                    }
                }
                $superiorSKUs_user = @{}
                foreach ($referenceSKU in $skuid_enabledPlans.Keys) {
                    foreach ($differenceSKU in $skuid_enabledPlans.Keys | Where-Object{$_ -ne $referenceSKU}) {
                        if ($null -ne ($referenceServicePlans = $skuid_enabledPlans[$referenceSKU]) -and
                        $null -ne ($differenceServicePlans = $skuid_enabledPlans[$differenceSKU])) {
                            if ($null -ne ($comparisonSKU = Compare-Object -ReferenceObject $referenceServicePlans -DifferenceObject $differenceServicePlans -IncludeEqual) -and
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
                    $userSKUs_removable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableUser -ExcludeDifferent -IncludeEqual | ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_user.Keys | Where-Object{$superiorSKUs_user[$_] -contains $superiorSKU}} | Where-Object{$_ -in $userSKUs} | Select-Object -Unique
                }
                else {
                    $userSKUs_removable = $null
                }
                # Add results
                if ($userSKUs_interchangeable.Count -gt 1) {
                    Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Interchangeable -ConflictSKUs $userSKUs_interchangeable
                    Write-VerboseMessage "Found $($userSKUs_interchangeable.Count) interchangeable SKUs for user $($user.userPrincipalName)"
                }
                if ($null -ne $userSKUs_optimizable) {
                    Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Optimizable -ConflictSKUs $userSKUs_optimizable
                    Write-VerboseMessage "Found $(@($userSKUs_optimizable).Count) optimizable SKUs for user $($user.userPrincipalName)"
                }
                if ($null -ne $userSKUs_removable) {
                    Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Removable -ConflictSKUs $userSKUs_removable
                    Write-VerboseMessage "Found $(@($userSKUs_removable).Count) removable SKUs for user $($user.userPrincipalName)"
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
            Write-VerboseMessage "Found $($groups.Count) groups"
            # Azure AD P1 based on dynamic groups
            if ($null -ne ($dynamicGroups = $groups | Where-Object{$_.groupTypes -contains 'DynamicMembership'})) {
                $AADP1Users.AddRange((Get-AADGroupMembers -GroupIDs $dynamicGroups.id))
            }
            # Azure AD P1 based on group-based application assignments
            $applications = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo&$top=999'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $applications.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            Write-VerboseMessage "Found $($applications.Count) service principals"
            if ($null -ne ($applicationGroups = ($applications | Where-Object{$_.accountEnabled -eq $true -and $_.appRoleAssignmentRequired -eq $true -and $_.servicePrincipalType -eq 'Application'}).appRoleAssignedTo | Where-Object{$_.principalType -eq 'Group'})) {
                $AADP1Users.AddRange((Get-AADGroupMembers -GroupIDs $applicationGroups.principalId))
            }
            # Azure AD P1/P2 based on users covered by Conditional Access
            $conditionalAccessPolicies = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,conditions,state'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $conditionalAccessPolicies.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            $conditionalAccessSignIns = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=conditionalAccessStatus eq ''success'' or conditionalAccessStatus eq ''failure''&$top=999'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $conditionalAccessSignIns.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            if ($conditionalAccessPolicies.Count -gt 0 -and $conditionalAccessSignIns.Count -gt 0) {
                if ($null -ne ($CAAADP1Policies = $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled' -and $_.conditions.userRiskLevels.Count -eq 0 -and $_.conditions.signInRiskLevels.Count -eq 0})) {
                    Write-VerboseMessage "Found $(@($CAAADP1Policies).Count) basic conditional access policies"
                    if ($null -ne ($CAAADP1SignIns = $conditionalAccessSignIns | Where-Object{($_.appliedConditionalAccessPolicies | Where-Object{$_.result -in @('success','failure')}).id -in $CAAADP1Policies.id})) {
                        $CAAADP1Users = $CAAADP1SignIns.userId | Select-Object -Unique
                        Write-VerboseMessage "Found $(@($CAAADP1Users).Count) users with basic conditional access sign-ins"
                        $AADP1Users.AddRange([guid[]]@($CAAADP1Users))
                    }
                }
                if ($null -ne ($CAAADP2Policies = $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled' -and ($_.conditions.userRiskLevels.Count -gt 0 -or $_.conditions.signInRiskLevels.Count -gt 0)})) {
                    Write-VerboseMessage "Found $(@($CAAADP2Policies).Count) risk-based conditional access policies"
                    if ($null -ne ($CAAADP2SignIns = $conditionalAccessSignIns | Where-Object{($_.appliedConditionalAccessPolicies | Where-Object{$_.result -in @('success','failure')}).id -in $CAAADP2Policies.id})) {
                        $CAAADP2Users = $CAAADP2SignIns.userId | Select-Object -Unique
                        Write-VerboseMessage "Found $(@($CAAADP2Users).Count) users with risk-based conditional access sign-ins"
                        $AADP2Users.AddRange([guid[]]@($CAAADP2Users))
                    }
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
            Write-VerboseMessage "Found $($eligibleRoleMembers.Count) eligible role assignments"
            if ($eligibleRoleMembers.Count -gt 0) {
                if ($null -ne ($actuallyEligibleRoleMembers = $eligibleRoleMembers | Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or $_.scheduleInfo.expiration.type -eq 'noExpiration')})) {
                    $AADP2Users.AddRange([guid[]]@($actuallyEligibleRoleMembers.principalId))
                }
            }
            # Defender for Office 365 P1/P2 based on https://learn.microsoft.com/office365/servicedescriptions/office-365-advanced-threat-protection-service-description#licensing-terms
            $orgDomain = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains').value.verifiedDomains | Where-Object{$_.isInitial -eq $true}
            try {
                switch ($PSCmdlet.ParameterSetName) {
                    'AzureCertificate' {
                        Connect-ExchangeOnline -AppId $ApplicationID -Certificate $azureCertificate -Organization $orgDomain.name -CommandName $EXOCmdlets -ShowBanner:$false -ErrorAction Stop
                    }
                    'LocalCertificate' {
                        Connect-ExchangeOnline -AppId $ApplicationID -Certificate $Certificate -Organization $orgDomain.name -CommandName $EXOCmdlets -ShowBanner:$false -ErrorAction Stop
                    }
                    'LocalCertificateThumbprint' {
                        Connect-ExchangeOnline -AppId $ApplicationID -CertificateThumbprint $CertificateThumbprint -Organization $orgDomain.name -CommandName $EXOCmdlets -ShowBanner:$false -ErrorAction Stop
                    }
                }
                $exchangeAuthentication = $true
                Write-VerboseMessage 'Succeeded to authenticate with Exchange Online'
            }
            catch {
                $exchangeAuthentication = $false
                Write-Error -Message 'Failed to authenticate with Exchange Online' -Category AuthenticationError
            }
            if ($exchangeAuthentication) {
                if ($null -ne (Compare-Object -ReferenceObject $organizationSKUs.servicePlans.servicePlanId -DifferenceObject @('f20fedf3-f3c3-43c3-8267-2bfdd51c0939', '8e0c0a52-6a6c-4d40-8370-dd62790dcd70') -ExcludeDifferent -IncludeEqual)) {
                    # Protected mailboxes
                    if ($null -ne ($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'})) {
                        $ATPvariant = 'DfOP2'
                        Write-VerboseMessage 'Identified a Defender for Office P2 tenant'
                        if ($null -ne ($recipients = Get-Recipient -RecipientTypeDetails $EXOTypes_user -ResultSize Unlimited)) {
                            $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                            Write-VerboseMessage "Found $($recipients.Count) affected/protected recipients"
                        }
                    }
                    else {
                        $ATPvariant = 'DfOP1'
                        Write-VerboseMessage 'Identified a Defender for Office P1 tenant'
                        # Order of precedence according to https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#order-of-precedence-for-preset-security-policies-and-other-policies
                        $matchedRecipients = [System.Collections.Generic.List[guid]]::new()
                        # Handle strict protection rule
                        if ($null -ne ($strictProtectionRule = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -State Enabled -ErrorAction SilentlyContinue)) {
                            Write-VerboseMessage 'ATP strict rule'
                            if ($null -ne ($recipients = Get-ATPRecipients -IncludedUsers $strictProtectionRule.SentTo -IncludedGroups $strictProtectionRule.SentToMemberOf -IncludedDomains $strictProtectionRule.RecipientDomainIs -ExcludedUsers $strictProtectionRule.ExceptIfSentTo -ExcludedGroups $strictProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $strictProtectionRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                Write-VerboseMessage "Found $($recipients.Count) affected/protected recipients"
                            }
                        }
                        # Handle standard protection rule
                        if ($null -ne ($standardProtectionRule = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -State Enabled -ErrorAction SilentlyContinue)) {
                            Write-VerboseMessage 'ATP standard rule'
                            if ($null -ne ($recipients = Get-ATPRecipients -IncludedUsers $standardProtectionRule.SentTo -IncludedGroups $standardProtectionRule.SentToMemberOf -IncludedDomains $standardProtectionRule.RecipientDomainIs -ExcludedUsers $standardProtectionRule.ExceptIfSentTo -ExcludedGroups $standardProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $standardProtectionRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                Write-VerboseMessage "Found $($recipients.Count) affected/protected recipients"
                            }
                        }
                        # Handle custom protection rules
                        foreach ($customAntiPhishPolicy in Get-AntiPhishPolicy | Where-Object{$_.Identity -ne 'Office 365 AntiPhish Default' -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customAntiPhishRule = Get-AntiPhishRule | Where-Object{$_.AntiPhishPolicy -eq $customAntiPhishPolicy.Identity}).State -eq 'Enabled'){
                                Write-VerboseMessage "ATP custom anti-phishing policy '$($customAntiPhishPolicy.Name)'"
                                if ($null -ne ($recipients = Get-ATPRecipients -IncludedUsers $customAntiPhishRule.SentTo -IncludedGroups $customAntiPhishRule.SentToMemberOf -IncludedDomains $customAntiPhishRule.RecipientDomainIs -ExcludedUsers $customAntiPhishRule.ExceptIfSentTo -ExcludedGroups $customAntiPhishRule.ExceptIfSentToMemberOf -ExcludedDomains $customAntiPhishRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                    $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                    if ($customAntiPhishPolicy.Enabled) {
                                        $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                        Write-VerboseMessage "Found $($recipients.Count) affected, $($recipients.Count) protected recipients"
                                    }
                                    else {
                                        Write-VerboseMessage "Found $($recipients.Count) affected, 0 protected recipients"
                                    }
                                }
                            }
                        }
                        foreach ($customSafeAttachmentPolicy in Get-SafeAttachmentPolicy | Where-Object{$_.IsBuiltInProtection -eq $false -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customSafeAttachmentRule = Get-SafeAttachmentRule | Where-Object{$_.SafeAttachmentPolicy -eq $customSafeAttachmentPolicy.Identity}).State -eq 'Enabled'){
                                Write-VerboseMessage "ATP custom Safe Attachments policy '$($customSafeAttachmentPolicy.Name)'"
                                if ($null -ne ($recipients = Get-ATPRecipients -IncludedUsers $customSafeAttachmentRule.SentTo -IncludedGroups $customSafeAttachmentRule.SentToMemberOf -IncludedDomains $customSafeAttachmentRule.RecipientDomainIs -ExcludedUsers $customSafeAttachmentRule.ExceptIfSentTo -ExcludedGroups $customSafeAttachmentRule.ExceptIfSentToMemberOf -ExcludedDomains $customSafeAttachmentRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                    $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                    if ($customSafeAttachmentPolicy.Enable) {
                                        $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                        Write-VerboseMessage "Found $($recipients.Count) affected, $($recipients.Count) protected recipients"
                                    }
                                    else {
                                        Write-VerboseMessage "Found $($recipients.Count) affected, 0 protected recipients"
                                    }
                                }
                            }
                        }
                        foreach ($customSafeLinksPolicy in Get-SafeLinksPolicy | Where-Object{$_.IsBuiltInProtection -eq $false -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customSafeLinksRule = Get-SafeLinksRule | Where-Object{$_.SafeLinksPolicy -eq $customSafeLinksPolicy.Identity}).State -eq 'Enabled'){
                                Write-VerboseMessage "ATP custom Safe Links policy '$($customSafeLinksPolicy.Name)'"
                                if ($null -ne ($recipients = Get-ATPRecipients -IncludedUsers $customSafeLinksRule.SentTo -IncludedGroups $customSafeLinksRule.SentToMemberOf -IncludedDomains $customSafeLinksRule.RecipientDomainIs -ExcludedUsers $customSafeLinksRule.ExceptIfSentTo -ExcludedGroups $customSafeLinksRule.ExceptIfSentToMemberOf -ExcludedDomains $customSafeLinksRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                    $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                    if ($customSafeLinksPolicy.EnableSafeLinksForEmail -or $customSafeLinksPolicy.EnableSafeLinksForOffice -or $customSafeLinksPolicy.EnableSafeLinksForTeams) {
                                        $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                        Write-VerboseMessage "Found $($recipients.Count) affected, $($recipients.Count) protected recipients"
                                    }
                                    else {
                                        Write-VerboseMessage "Found $($recipients.Count) affected, 0 protected recipients"
                                    }
                                }
                            }
                        }
                        # Handle built-in protection rule
                        Write-VerboseMessage 'ATP built-in rule'
                        $builtinProtectionRule = Get-ATPBuiltInProtectionRule
                        if ($null -ne ($recipients = Get-ATPRecipients -IncludedUsers $builtinProtectionRule.SentTo -IncludedGroups $builtinProtectionRule.SentToMemberOf -IncludedDomains $builtinProtectionRule.RecipientDomainIs -ExcludedUsers $builtinProtectionRule.ExceptIfSentTo -ExcludedGroups $builtinProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $builtinProtectionRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                            $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                            $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                            Write-VerboseMessage "Found $($recipients.Count) affected/protected recipients"
                        }
                    }
                }
                else {
                    $ATPvariant = 'EOP'
                    Write-VerboseMessage 'Identified an Exchange Online Protection tenant'
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
                Write-VerboseMessage "Found $neededCount needed, $AADP1Licenses enabled AADP1 licenses"
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
                Write-VerboseMessage "Found $neededCount needed, $AADP1Licenses enabled AADP2 licenses"
                if ($AADP2Licenses -lt $neededCount) {
                    Add-Result -PlanName 'Azure Active Directory Premium P2' -EnabledCount $AADP2Licenses -NeededCount $neededCount
                }
            }
            if ($ATPUsers.Count -gt 0) {
                $neededCount = ($ATPUsers | Select-Object -Unique).Count
                switch ($ATPvariant) {
                    'DfOP1' {
                        $ATPSKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains 'f20fedf3-f3c3-43c3-8267-2bfdd51c0939'})
                        $ATPLicenses = ($ATPSKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                        Write-VerboseMessage "Found $neededCount needed, $ATPLicenses enabled DfOP2 licenses"
                        if ($ATPLicenses -lt $neededCount) {
                            Add-Result -PlanName 'Microsoft Defender for Office 365 P1' -EnabledCount $ATPLicenses -NeededCount $neededCount
                        }
                    }
                    'DfOP2' {
                        $ATPSKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'})
                        $ATPLicenses = ($ATPSKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                        Write-VerboseMessage "Found $neededCount needed, $ATPLicenses enabled DfOP2 licenses"
                        if ($ATPLicenses -lt $neededCount) {
                            Add-Result -PlanName 'Microsoft Defender for Office 365 P2' -EnabledCount $ATPLicenses -NeededCount $neededCount
                        }
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
            Add-Output -Output '<p class=gray>Basic checkup - Products</p>'
            if ($results.ContainsKey('SKU')) {
                Add-Output -Output "<p>Please check license counts for the following product SKUs and <a href=""$LicensingURL"">reserve</a> additional licenses:</p> `
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
            else {
                Add-Output -Output 'Nothing to report'
            }
            # Output advanced SKU results
            Add-Output -Output '<p class=gray>Advanced checkup - Products</p>'
            if ($results.ContainsKey('Advanced')) {
                Add-Output -Output "<p>Please check license counts for the following product SKUs and <a href=""$LicensingURL"">reserve</a> additional licenses:</p> `
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
                                    <li>Check <i>Azure AD P1</i> based on applications using group-based assignment</li>
                                    <li>Check <i>Azure AD P1</i> based on groups using dynamic membership</li>
                                    <li>Check <i>Azure AD P1</i> based on users enabled for Conditional Access</li>
                                    <li>Check <i>Azure AD P2</i> based on users enabled for Privileged Identity Management</li>
                                    <li>Check <i>Defender for Office 365 P1/P2</i> based on protected Exchange Online recipients</li></ul></p>'
            }
            else {
                Add-Output -Output 'Nothing to report'
            }
            # Output basic user results
            Add-Output -Output '<p class=gray>Basic checkup - Users</p>'
            if ($results.ContainsKey('User')) {
                Add-Output -Output '<p>Please check license assignments for the following user accounts and mitigate impact:</p>
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
            else {
                Add-Output -Output 'Nothing to report'
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