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
function Initialize-Module {
    # Common
    $script:outputs = [System.Text.StringBuilder]::new()
    $script:results = @{}
    $script:skuTranslate = [string]::new([char[]]((Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -UseBasicParsing).Content)) | ConvertFrom-Csv
    # Exchange Online
    $script:EXOCmdlets = @(
        'Get-Recipient',
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
    $script:EXOProperties = @(
        'ExchangeObjectId',
        'ExternalDirectoryObjectId',
        'PrimarySmtpAddress',
        'RecipientTypeDetails')
    $script:EXOTypes_group = @(
        'GroupMailbox',
        'MailUniversalDistributionGroup',
        'MailUniversalSecurityGroup')
    $script:EXOTypes_user = @(
        'SharedMailbox',
        'UserMailbox')
    # Graph
    $script:pageSize = 500
    $script:reportDays = 180
    # Process
    $script:nestingLevel = 0
}

function Write-Message {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [ValidateSet('Error', 'Verbose')]
        [string]$Type
    )

    $formattedMessage = ('[{0:yyyy-MM-dd HH:mm:ss}] {1}{2}' -f [datetime]::Now, [string]::new('-', $nestingLevel), $Message)
    if ($Type -eq 'Error') {
        Write-Error -Message $formattedMessage -Category AuthenticationError
    }
    elseif ($Type -eq 'Verbose') {
        Write-Verbose -Message $formattedMessage
    }
    else {
        $formattedMessage | Write-Output
    }
}

function Add-Output {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Output
    )

    # Logging
    $nestingLevel++
    Write-Message 'Add-Output' -Type Verbose
    # Processing
    $outputs.AppendLine($Output) | Out-Null
    $nestingLevel--
}

function Add-Result {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Basic')]
        [ValidateNotNullOrEmpty()]
        [guid]$SKUID,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Basic')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$AvailableCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Basic')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$MinimumCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Basic')]
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Advanced')]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Basic')]
        [ValidateSet('Interchangeable', 'Optimizable', 'Removable')]
        [string]$ConflictType,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Basic')]
        [ValidateNotNullOrEmpty()]
        [guid[]]$ConflictSKUs,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Advanced')]
        [ValidateNotNullOrEmpty()]
        [guid]$PreferableSKU,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Advanced')]
        [AllowEmptyCollection()]
        [guid[]]$OpposingSKUs,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Advanced')]
        [ValidateNotNullOrEmpty()]
        [string]$PlanName,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Advanced')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$EnabledCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Advanced')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$NeededCount
    )

    # Logging
    $nestingLevel++
    Write-Message 'Add-Result' -Type Verbose
    # Processing
    if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
        $results.Add($PSCmdlet.ParameterSetName, @{})
    }
    switch ($PSCmdlet.ParameterSetName) {
        'SKU_Advanced' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($PlanName)) {
                $results[$PSCmdlet.ParameterSetName].Add($PlanName, @{
                    'enabledCount' = $EnabledCount;
                    'neededCount' = $NeededCount
                })
            }
        }
        'SKU_Basic' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($SKUID)) {
                $results[$PSCmdlet.ParameterSetName].Add($SKUID, @{
                    'availableCount' = $AvailableCount;
                    'minimumCount' = $MinimumCount
                })
            }
        }
        'User_Advanced' {
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($UserPrincipalName)) {
                $results[$PSCmdlet.ParameterSetName].Add($UserPrincipalName, @{})
            }
            if (-not $results[$PSCmdlet.ParameterSetName][$UserPrincipalName].ContainsKey('Preferable')) {
                $results[$PSCmdlet.ParameterSetName][$UserPrincipalName].Add('Preferable', @{
                    'preferableSKU' = $PreferableSKU;
                    'opposingSKUs' = $OpposingSKUs
                })
            }
        }
        'User_Basic' {
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

function Get-AADGroupMember {
    [OutputType([guid[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid[]]$GroupIDs
    )

    # Logging
    $nestingLevel++
    Write-Message 'Get-AADGroupMember' -Type Verbose
    # Processing
    $groupMembers = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($groupID in $GroupIDs) {
        $URI = 'https://graph.microsoft.com/v1.0/groups/{0}/transitiveMembers?$select=id&$top={1}' -f $groupID, $pageSize
        while ($null -ne $URI) {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $groupMembers.AddRange([hashtable[]]($data.value))
            $URI = $data['@odata.nextLink']
        }
    }
    $groupMembers_unique = @($groupMembers.id | Select-Object -Unique)
    Write-Message "Found $($groupMembers_unique.Count) members" -Type Verbose
    $nestingLevel--
    Write-Output ([guid[]]$groupMembers_unique) -NoEnumerate
}

function Get-EXOGroupMember {
    [OutputType([pscustomobject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid[]]$GroupIDs
    )

    # Logging
    $nestingLevel++
    Write-Message 'Get-EXOGroupMember' -Type Verbose
    # Processing
    $groupMembers = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($groupID in $GroupIDs) {
        if ($null -ne ($group = [pscustomobject](Get-EXORecipient $groupID.Guid -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties) | Select-Object -Property $EXOProperties)) {
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
                        $groupMembers.AddRange((Get-EXOGroupMember -GroupIDs $member.ExchangeObjectId))
                    }
                }
            }
        }
    }
    $groupMembers_unique = @($groupMembers | Select-Object -Unique)
    Write-Message "Found $($groupMembers_unique.Count) members" -Type Verbose
    $nestingLevel--
    Write-Output ([pscustomobject[]]$groupMembers_unique) -NoEnumerate
}

function Resolve-ATPRecipient {
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

    # Logging
    $nestingLevel++
    Write-Message 'Resolve-ATPRecipient' -Type Verbose
    # Processing
    $categoryCount = 0
    $affectedAsUser = [System.Collections.Generic.List[pscustomobject]]::new()
    $affectedAsGroup = [System.Collections.Generic.List[pscustomobject]]::new()
    $affectedAsDomain = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($null -ne $Users) {
        $categoryCount++
        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_user -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress -in $Users})) {
            $affectedAsUser.AddRange([pscustomobject[]]@($recipients))
        }
    }
    Write-Message "Found $($affectedAsUser.Count) recipients by users" -Type Verbose
    if ($null -ne $Groups) {
        $categoryCount++
        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress -in $Groups})) {
            $affectedAsGroup.AddRange((Get-EXOGroupMember -GroupIDs $recipients.ExchangeObjectId))
        }
    }
    Write-Message "Found $($affectedAsGroup.Count) recipients by groups" -Type Verbose
    if ($null -ne $Domains) {
        $categoryCount++
        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_user -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress.Split('@')[1] -in $Domains})) {
            $affectedAsDomain.AddRange([pscustomobject[]]@($recipients))
        }
        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress.Split('@')[1] -in $Domains})) {
            $affectedAsDomain.AddRange((Get-EXOGroupMember -GroupIDs $recipients.ExchangeObjectId))
        }
    }
    Write-Message "Found $($affectedAsDomain.Count) recipients by domains" -Type Verbose
    if ($null -ne ($resolvedUsers = @($affectedAsUser | Select-Object -Unique) + @($affectedAsGroup | Select-Object -Unique) + @($affectedAsDomain | Select-Object -Unique) | Group-Object -Property ExchangeObjectId | Where-Object{$_.Count -eq $categoryCount})) {
        $resolvedUsers_unique = @($resolvedUsers.Group | Select-Object -Unique)
        Write-Message "Found $($resolvedUsers_unique.Count) recipients by combination" -Type Verbose
        $nestingLevel--
        Write-Output ([pscustomobject[]]$resolvedUsers_unique) -NoEnumerate
    }
    else {
        Write-Message "Found 0 recipients by combination" -Type Verbose
        $nestingLevel--
        Write-Output @([pscustomobject[]]::new(0)) -NoEnumerate
    }
}

function Get-ATPRecipient {
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

    # Logging
    $nestingLevel++
    Write-Message 'Get-ATPRecipient' -Type Verbose
    # Processing
    Write-Message 'Checking included recipients' -Type Verbose
    if ($null -eq $IncludedUsers -and
    $null -eq $IncludedGroups -and
    $null -eq $IncludedDomains) {
        $userRecipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_user -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties
        $groupRecipients = Get-EXOGroupMember -GroupIDs ([pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties -ResultSize Unlimited)).ExchangeObjectId
        $includedRecipients = $userRecipients + $groupRecipients | Select-Object -Unique
    }
    else {
        $includedRecipients = Resolve-ATPRecipient -Users $IncludedUsers -Groups $IncludedGroups -Domains $IncludedDomains
    }
    Write-Message "Found $($includedRecipients.Count) included recipients" -Type Verbose
    Write-Message 'Checking excluded recipients' -Type Verbose
    if ($null -eq $ExcludedUsers -and
    $null -eq $ExcludedGroups -and
    $null -eq $ExcludedDomains) {
        $excludedRecipients = @()
    }
    else {
        $excludedRecipients = Resolve-ATPRecipient -Users $ExcludedUsers -Groups $ExcludedGroups -Domains $ExcludedDomains
    }
    Write-Message "Found $($excludedRecipients.Count) excluded recipients" -Type Verbose
    Write-Message 'Checking affected recipients' -Type Verbose
    $affectedRecipients = [System.Collections.Generic.List[pscustomobject]]::new()
    if ($null -ne ($affectedRecipientComparison = Compare-Object -ReferenceObject $includedRecipients -DifferenceObject $excludedRecipients)) {
        if ($null -ne ($affectedRecipientResults = $affectedRecipientComparison | Where-Object{$_.SideIndicator -eq '<='})) {
            $affectedRecipients.AddRange([pscustomobject[]]@($affectedRecipientResults.InputObject))
        }
    }
    $affectedRecipients_unique = @($affectedRecipients | Select-Object -Unique)
    Write-Message "Found $($affectedRecipients_unique.Count) affected recipients" -Type Verbose
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

    # Logging
    $nestingLevel++
    Write-Message 'Get-SKUName' -Type Verbose
    # Processing
    if ($SKUID -eq [guid]::Empty) {
        $skuName = 'N/A'
    }
    elseif ($null -ne ($skuName = ($skuTranslate | Where-Object{$_.GUID -eq $SKUID}).Product_Display_Name | Select-Object -Unique)) {
        $skuName = [cultureinfo]::new('en-US').TextInfo.ToTitleCase($skuName.ToLower())
    }
    else {
        $skuName = $SKUID
    }
    $nestingLevel--
    Write-Output $skuName
}
#endregion

class PreferableSKURule {
    [datetime]$LastActiveEarlierThan = [datetime]::MaxValue
    [UInt16]$OneDriveGBUsedLessThan = [UInt16]::MaxValue
    [UInt16]$MailboxGBUsedLessThan = [UInt16]::MaxValue
    [ValidateSet('True', 'False', 'Skip')]
    [string]$MailboxHasArchive = 'Skip'
    [ValidateSet('True', 'False', 'Skip')]
    [string]$WindowsAppUsed = 'Skip'
    [ValidateSet('True', 'False', 'Skip')]
    [string]$MacAppUsed = 'Skip'
    [ValidateSet('True', 'False', 'Skip')]
    [string]$MobileAppUsed = 'Skip'
    [ValidateSet('True', 'False', 'Skip')]
    [string]$WebAppUsed = 'Skip'
    [guid]$SKUID
}

function Get-AzureADLicenseStatus {
    <#
    .SYNOPSIS
    Creates an Azure AD license report based on license assignments and consumption
    .DESCRIPTION
    This function is meant to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

    SKU IDs and names are in accordance with https://learn.microsoft.com/azure/active-directory/enterprise-users/licensing-service-plan-reference
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
    .PARAMETER PreferableSKUs
    Specifies a list of SKUs which are deemed preferable based on their provided ruleset
    .PARAMETER SKUPrices
    Specifies a list of SKUs with their prices to calculate possible savings during user checkups
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
    .EXAMPLE
    Get-AzureADLicenseStatus -DirectoryID '00000000-0000-0000-0000-000000000000' -ApplicationID '00000000-0000-0000-0000-000000000000' -SubscriptionID '00000000-0000-0000-0000-000000000000' -KeyVaultName 'MyKeyVault' -CertificateName 'MyCertificate' -SenderAddress 'sender@example.com' -RecipientAddresses_normal @('recipient_1@example.com', 'recipient_2@example.com') -RecipientAddresses_critical @('recipient_3@example.com', 'recipient_4@example.com') -SKUPercentageThreshold_normal 1 -SKUTotalThreshold_normal 100 -SKUPercentageThreshold_important 1 -SKUTotalThreshold_important 500 -ImportantSKUs @('18181a46-0d4e-45cd-891e-60aabd171b4e', '6fd2c87f-b296-42f0-b197-1e91e994b900') -InterchangeableSKUs @('4b585984-651b-448a-9e53-3b10f069cf7f', '18181a46-0d4e-45cd-891e-60aabd171b4e', '6fd2c87f-b296-42f0-b197-1e91e994b900', 'c7df2760-2c81-4ef7-b578-5b5392b571df') -PreferableSKUs @([PreferableSKURule]@{OneDriveGBUsedLessThan = 1; MailboxGBUsedLessThan = 1; MailboxHasArchive = 'False'; WindowsAppUsed = 'False'; MacAppUsed = 'False'; SKUID = '4b585984-651b-448a-9e53-3b10f069cf7f'}) -SKUPrices @{'4b585984-651b-448a-9e53-3b10f069cf7f' = 4.0; '18181a46-0d4e-45cd-891e-60aabd171b4e' = 10.0; '6fd2c87f-b296-42f0-b197-1e91e994b900' = 23.0; 'c7df2760-2c81-4ef7-b578-5b5392b571df' = 38.0} -AdvancedCheckups

    Prepares a status report by using an Azure certificate for automation purposes, specifying important, interchangeable and preferable SKUs with their prices and activating advanced checkups
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
        [guid[]]$ImportantSKUs,
        [ValidateNotNullOrEmpty()]
        [guid[]]$InterchangeableSKUs,
        [ValidateNotNullOrEmpty()]
        [PreferableSKURule[]]$PreferableSKUs,
        [ValidateScript({$_.Keys | ForEach-Object{[guid]$_}; $_.Values | ForEach-Object{[decimal]$_}})]
        [hashtable]$SKUPrices,
        [ValidateNotNullOrEmpty()]
        [string]$LicensingURL = 'https://www.microsoft.com/licensing/servicecenter',
        [switch]$AdvancedCheckups
    )

    Initialize-Module
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
        Write-Message 'Succeeded to authenticate with Graph' -Type Verbose
    }
    catch {
        $graphAuthentication = $false
        Write-Message -Message 'Failed to authenticate with Graph' -Type Error
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
        Write-Message "Found $($superiorSKUs_organization.Count) SKU matches for organization, out ouf $($organizationSKUs.Count) SKUs"
        #endregion

        #region: Reports
        if ($AdvancedCheckups.IsPresent) {
            Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/reports/getM365AppUserDetail(period=''D{0}'')?$format=text/csv' -f $reportDays) -OutputFilePath "$env:TEMP\M365AppUserDetail.csv"
            $M365AppUserDetail = Import-Csv "$env:TEMP\M365AppUserDetail.csv" | Select-Object -Property 'User Principal Name', 'Last Activity Date', 'Windows', 'Mac', 'Mobile', 'Web'
            Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period=''D{0}'')' -f $reportDays) -OutputFilePath "$env:TEMP\MailboxUsageDetail.csv"
            $MailboxUsageDetail = Import-Csv "$env:TEMP\MailboxUsageDetail.csv" | Select-Object -Property 'User Principal Name', 'Last Activity Date', 'Storage Used (Byte)', 'Has Archive'
            Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period=''D{0}'')' -f $reportDays) -OutputFilePath "$env:TEMP\OneDriveUsageAccountDetail.csv"
            $OneDriveUsageAccountDetail = Import-Csv "$env:TEMP\OneDriveUsageAccountDetail.csv" | Select-Object -Property 'Owner Principal Name', 'Last Activity Date', 'Storage Used (Byte)'
            if ($M365AppUserDetail.'User Principal Name' -like '*@*' -or
            $MailboxUsageDetail.'User Principal Name' -like '*@*' -or
            $OneDriveUsageAccountDetail.'Owner Principal Name' -like '*@*') {
                $hashedReports = $false
            }
            else {
                $hashedReports = $true
            }
        }
        #endregion

        #region: Users
        $userCount = 0
        $URI = 'https://graph.microsoft.com/v1.0/users?$select=id,licenseAssignmentStates,userPrincipalName&$top={0}' -f $pageSize
        while ($null -ne $URI) {
            # Retrieve users
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $users = [hashtable[]]($data.value)
            $userCount += $users.Count
            $URI = $data['@odata.nextLink']
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
                            $results['SKU_Basic'][$countViolation]['availableCount'] -= 1
                        }
                    }
                    # Identify interchangeable SKUs, based on specifications
                    $userSKUs_interchangeable = @()
                    if ($null -ne $userSKUs -and
                    $null -ne $InterchangeableSKUs) {
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
                    # Identify preferable SKUs, based on user-level calculations
                    $hashCalculator = [System.Security.Cryptography.MD5]::Create()
                    if ($AdvancedCheckups.IsPresent) {
                        if ($hashedReports) {
                            $userName = ($hashCalculator.ComputeHash([Text.Encoding]::ASCII.GetBytes($user.userPrincipalName)) | ForEach-Object{'{0:X2}' -f $_}) -join ''
                        }
                        else {
                            $userName = $user.userPrincipalName
                        }
                        $userOneDriveLastActivityDate = [datetime]::MinValue
                        if ($null -ne ($userOneDrive = $OneDriveUsageAccountDetail | Where-Object{$_.'Owner Principal Name' -eq $userName})) {
                            [datetime]::TryParse($userOneDrive.'Last Activity Date', [ref]$userOneDriveLastActivityDate) | Out-Null
                            $userOneDriveStorageUsedGB = $userOneDrive.'Storage Used (Byte)' / [System.Math]::Pow(1000, 3)
                        }
                        else {
                            $userOneDriveStorageUsedGB = 0
                        }
                        $userMailboxLastActivityDate = [datetime]::MinValue
                        if ($null -ne ($userMailbox = $MailboxUsageDetail | Where-Object{$_.'User Principal Name' -eq $userName})) {
                            [datetime]::TryParse($userMailbox.'Last Activity Date', [ref]$userMailboxLastActivityDate) | Out-Null
                            $userMailboxStorageUsedGB = $userMailbox.'Storage Used (Byte)' / [System.Math]::Pow(1000, 3)
                            $userMailboxHasArchive = $userMailbox.'Has Archive'
                        }
                        else {
                            $userMailboxStorageUsedGB = 0
                            $userMailboxHasArchive = $false
                        }
                        $userAppsUsedLastActivityDate = [datetime]::MinValue
                        if ($null -ne ($userAppsUsed = $M365AppUserDetail | Where-Object{$_.'User Principal Name' -eq $userName})) {
                            [datetime]::TryParse($userAppsUsed.'Last Activity Date', [ref]$userAppsUsedLastActivityDate) | Out-Null
                            if ($userAppsUsed.'Windows' -eq 'Yes') {
                                $userWindowsAppUsed = $true
                            }
                            else {
                                $userWindowsAppUsed = $false
                            }
                            if ($userAppsUsed.'Mac' -eq 'Yes') {
                                $userMacAppUsed = $true
                            }
                            else {
                                $userMacAppUsed = $false
                            }
                            if ($userAppsUsed.'Mobile' -eq 'Yes') {
                                $userMobileAppUsed = $true
                            }
                            else {
                                $userMobileAppUsed = $false
                            }
                            if ($userAppsUsed.'Web' -eq 'Yes') {
                                $userWebAppUsed = $true
                            }
                            else {
                                $userWebAppUsed = $false
                            }
                        }
                        else {
                            $userWindowsAppUsed = $false
                            $userMacAppUsed = $false
                            $userMobileAppUsed = $false
                            $userWebAppUsed = $false
                        }
                        $userSKUs_preferable = $null
                        foreach ($preferableSKU in $PreferableSKUs) {
                            if ($null -eq $userSKUs_preferable) {
                                if ($userOneDriveLastActivityDate -lt $preferableSKU.LastActiveEarlierThan.Date -and
                                $userMailboxLastActivityDate -lt $preferableSKU.LastActiveEarlierThan.Date -and
                                $userAppsUsedLastActivityDate -lt $preferableSKU.LastActiveEarlierThan.Date -and
                                $userOneDriveStorageUsedGB -lt $preferableSKU.OneDriveGBUsedLessThan -and
                                $userMailboxStorageUsedGB -lt $preferableSKU.MailboxGBUsedLessThan -and
                                ("$userMailboxHasArchive" -eq $preferableSKU.MailboxHasArchive -or $preferableSKU.MailboxHasArchive -eq 'Skip') -and
                                ("$userWindowsAppUsed" -eq $preferableSKU.WindowsAppUsed -or $preferableSKU.WindowsAppUsed -eq 'Skip') -and
                                ("$userMacAppUsed" -eq $preferableSKU.MacAppUsed -or $preferableSKU.MacAppUsed -eq 'Skip') -and
                                ("$userMobileAppUsed" -eq $preferableSKU.MobileAppUsed -or $preferableSKU.MobileAppUsed -eq 'Skip') -and
                                ("$userWebAppUsed" -eq $preferableSKU.WebAppUsed -or $preferableSKU.WebAppUsed -eq 'Skip')) {
                                    $userSKUs_preferable = $preferableSKU.SKUID
                                }
                            }
                        }
                    }
                    # Add results
                    if ($userSKUs_interchangeable.Count -gt 1) {
                        Write-Message "Found $($userSKUs_interchangeable.Count) interchangeable SKUs for user $($user.userPrincipalName)"
                        Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Interchangeable -ConflictSKUs $userSKUs_interchangeable
                    }
                    if ($null -ne $userSKUs_optimizable) {
                        Write-Message "Found $(@($userSKUs_optimizable).Count) optimizable SKUs for user $($user.userPrincipalName)"
                        Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Optimizable -ConflictSKUs $userSKUs_optimizable
                    }
                    if ($null -ne $userSKUs_removable) {
                        Write-Message "Found $(@($userSKUs_removable).Count) removable SKUs for user $($user.userPrincipalName)"
                        Add-Result -UserPrincipalName $user.userPrincipalName -ConflictType Removable -ConflictSKUs $userSKUs_removable
                    }
                    if ($null -ne $userSKUs_preferable) {
                        if ($userSKUs -notcontains $userSKUs_preferable) {
                            Write-Message "Found preferable SKU for user $($user.userPrincipalName)"
                            if ($InterchangeableSKUs -contains $userSKUs_preferable -and
                            $null -ne $userSKUs_interchangeable) {
                                Add-Result -UserPrincipalName $user.userPrincipalName -PreferableSKU $userSKUs_preferable -OpposingSKUs $userSKUs_interchangeable
                            }
                            else {
                                Add-Result -UserPrincipalName $user.userPrincipalName -PreferableSKU $userSKUs_preferable -OpposingSKUs @()
                            }
                        }
                    }
                }
            }
        }
        Write-Message "Analyzed $userCount users"
        #endregion

        #region: Advanced
        if ($AdvancedCheckups.IsPresent) {
            $AADP1Users = [System.Collections.Generic.List[guid]]::new()
            $AADP2Users = [System.Collections.Generic.List[guid]]::new()
            $ATPUsers = [System.Collections.Generic.List[guid]]::new()
            # Azure AD P1 based on groups using dynamic user membership
            $dynamicGroupCount = 0
            $URI = 'https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(x:x eq ''DynamicMembership'')&$select=id,membershipRule&$top={0}' -f $pageSize
            while ($null -ne $URI) {
                # Retrieve dynamic groups
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $dynamicGroups = [hashtable[]]($data.value)
                $dynamicGroupCount += $dynamicGroups.Count
                $URI = $data['@odata.nextLink']
                # Analyze dynamic groups
                if ($null -ne ($dynamicUserGroups = $dynamicGroups | Where-Object{$_.membershipRule -like '*user.*'})) {
                    $AADP1Users.AddRange((Get-AADGroupMember -GroupIDs $dynamicUserGroups.id))
                }
            }
            Write-Message "Analyzed $dynamicGroupCount dynamic groups"
            # Azure AD P1 based on applications using group-based assignment
            $applicationCount = 0
            $URI = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=accountEnabled eq true and appRoleAssignmentRequired eq true and servicePrincipalType eq ''Application''&$top={0}&$count=true' -f $pageSize
            while ($null -ne $URI) {
                # Retrieve applications
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI -Headers @{'ConsistencyLevel' = 'eventual'}
                $applications = [hashtable[]]($data.value)
                $applicationCount += $applications.Count
                $URI = $data['@odata.nextLink']
                # Analyze applications
                foreach ($application in $applications) {
                    $applicationData = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$expand=appRoleAssignedTo&$select=id,appRoleAssignedTo' -f $application.id)
                    if ($null -ne ($applicationGroups = $applicationData.appRoleAssignedTo | Where-Object{$_.principalType -eq 'Group'})) {
                        $AADP1Users.AddRange((Get-AADGroupMember -GroupIDs $applicationGroups.principalId))
                    }
                }
            }
            Write-Message "Analyzed $applicationCount applications"
            # Azure AD P1/P2 based on users covered by Conditional Access
            $CAAADP1Policies = [System.Collections.Generic.List[guid]]::new()
            $CAAADP2Policies = [System.Collections.Generic.List[guid]]::new()
            $conditionalAccessPolicyCount = 0
            $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,conditions,state'
            while ($null -ne $URI) {
                # Retrieve Conditional Access policies
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $conditionalAccessPolicies = [hashtable[]]($data.value)
                $conditionalAccessPolicyCount += $conditionalAccessPolicies.Count
                $URI = $data['@odata.nextLink']
                # Analyze Conditional Access policies
                if ($null -ne ($CAPolicies = $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled' -and $_.conditions.userRiskLevels.Count -eq 0 -and $_.conditions.signInRiskLevels.Count -eq 0})) {
                    $CAAADP1Policies.AddRange([guid[]]$CAPolicies.id)
                }
                if ($null -ne ($CAPolicies = $conditionalAccessPolicies | Where-Object{$_.state -eq 'enabled' -and ($_.conditions.userRiskLevels.Count -gt 0 -or $_.conditions.signInRiskLevels.Count -gt 0)})) {
                    $CAAADP2Policies.AddRange([guid[]]$CAPolicies.id)
                }
            }
            Write-Message "Found $(@($CAAADP1Policies).Count) basic Conditional Access policies, out of $conditionalAccessPolicyCount policies"
            Write-Message "Found $(@($CAAADP2Policies).Count) risk-based Conditional Access policies, out of $conditionalAccessPolicyCount policies"
            $CAAADP1Users = [System.Collections.Generic.List[guid]]::new()
            $CAAADP2Users = [System.Collections.Generic.List[guid]]::new()
            $signInCount = 0
            $today = [datetime]::Today
            if (($today.DayOfWeek - [System.DayOfWeek]::Friday) -lt 1) {
                $secondTimespanEnd = $today.AddDays(-($today.DayOfWeek - [System.DayOfWeek]::Friday + 7))
            }
            else {
                $secondTimespanEnd = $today.AddDays(-($today.DayOfWeek - [System.DayOfWeek]::Friday))
            }
            $secondTimespanStart = $secondTimespanEnd.AddDays(-4)
            $firstTimespanEnd = $secondTimespanEnd.AddDays(-14)
            $firstTimespanStart = $secondTimespanEnd.AddDays(-18)
            #TODO: Check date formats
            $URI = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=(conditionalAccessStatus eq ''success'' or conditionalAccessStatus eq ''failure'') and ((createdDateTime ge {0:yyyy-MM-ddT00:00:00Z} and createdDateTime le {1:yyyy-MM-ddT23:59:59Z}) or (createdDateTime ge {2:yyyy-MM-ddT00:00:00Z} and createdDateTime le {3:yyyy-MM-ddT23:59:59Z}))&$top={4}' -f $firstTimespanStart, $firstTimespanEnd, $secondTimespanStart, $secondTimespanEnd, $pageSize
            while ($null -ne $URI) {
                # Retrieve Conditional Access sign-ins
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $signIns = [hashtable[]]($data.value)
                $signInCount += $signIns.Count
                $URI = $data['@odata.nextLink']
                # Analyze Conditional Access sign-ins
                foreach ($signIn in $signIns) {
                    if ($null -ne ($appliedCAPolicies = $signIn.appliedConditionalAccessPolicies | Where-Object{$_.result -in @('success','failure')})) {
                        if ($null -ne $CAAADP1Policies) {
                            if ($null -ne (Compare-Object -ReferenceObject $appliedCAPolicies.id -DifferenceObject $CAAADP1Policies -ExcludeDifferent -IncludeEqual)) {
                                $CAAADP1Users.Add($signIn.userId)
                            }
                        }
                        if ($null -ne $CAAADP2Policies) {
                            if ($null -ne (Compare-Object -ReferenceObject $appliedCAPolicies.id -DifferenceObject $CAAADP2Policies -ExcludeDifferent -IncludeEqual)) {
                                $CAAADP2Users.Add($signIn.userId)
                            }
                        }
                    }
                }
            }
            Write-Message "Found $(@($CAAADP1Users | Select-Object -Unique).Count) users with basic conditional access sign-ins, based on $signInCount sign-ins"
            Write-Message "Found $(@($CAAADP2Users | Select-Object -Unique).Count) users with risk-based conditional access sign-ins, based on $signInCount sign-ins"
            $AADP1Users.AddRange([guid[]]@($CAAADP1Users | Select-Object -Unique))
            $AADP2Users.AddRange([guid[]]@($CAAADP2Users | Select-Object -Unique))
            Remove-Variable 'CAAADP1Policies','CAAADP2Policies','CAAADP1Users','CAAADP2Users' -Force
            # Azure AD P2 based on users in scope of Privileged Identity Management
            $eligibleRoleMembers = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,scheduleInfo'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $eligibleRoleMembers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            if ($eligibleRoleMembers.Count -gt 0) {
                if ($null -ne ($actuallyEligibleRoleMembers = $eligibleRoleMembers | Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or $_.scheduleInfo.expiration.type -eq 'noExpiration')})) {
                    $AADP2Users.AddRange([guid[]]@($actuallyEligibleRoleMembers.principalId))
                }
            }
            Write-Message "Analyzed $($eligibleRoleMembers.Count) eligible role assignments"
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
                Write-Message 'Succeeded to authenticate with Exchange Online' -Type Verbose
            }
            catch {
                $exchangeAuthentication = $false
                Write-Message -Message 'Failed to authenticate with Exchange Online' -Type Error
            }
            if ($exchangeAuthentication) {
                if ($null -ne (Compare-Object -ReferenceObject $organizationSKUs.servicePlans.servicePlanId -DifferenceObject @('f20fedf3-f3c3-43c3-8267-2bfdd51c0939', '8e0c0a52-6a6c-4d40-8370-dd62790dcd70') -ExcludeDifferent -IncludeEqual)) {
                    # Protected mailboxes
                    if ($null -ne ($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'})) {
                        $ATPvariant = 'DfOP2'
                        Write-Message 'Identified a Defender for Office P2 tenant'
                        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_user -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties)) {
                            $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                            Write-Message "Found $($recipients.Count) affected/protected recipients"
                        }
                    }
                    else {
                        $ATPvariant = 'DfOP1'
                        Write-Message 'Identified a Defender for Office P1 tenant'
                        # Order of precedence according to https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide#order-of-precedence-for-preset-security-policies-and-other-policies
                        $matchedRecipients = [System.Collections.Generic.List[guid]]::new()
                        # Handle strict protection rule
                        if ($null -ne ($strictProtectionRule = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -State Enabled -ErrorAction SilentlyContinue)) {
                            Write-Message 'ATP strict rule'
                            if ($null -ne ($recipients = Get-ATPRecipient -IncludedUsers $strictProtectionRule.SentTo -IncludedGroups $strictProtectionRule.SentToMemberOf -IncludedDomains $strictProtectionRule.RecipientDomainIs -ExcludedUsers $strictProtectionRule.ExceptIfSentTo -ExcludedGroups $strictProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $strictProtectionRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                Write-Message "Found $($recipients.Count) affected/protected recipients"
                            }
                        }
                        # Handle standard protection rule
                        if ($null -ne ($standardProtectionRule = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -State Enabled -ErrorAction SilentlyContinue)) {
                            Write-Message 'ATP standard rule'
                            if ($null -ne ($recipients = Get-ATPRecipient -IncludedUsers $standardProtectionRule.SentTo -IncludedGroups $standardProtectionRule.SentToMemberOf -IncludedDomains $standardProtectionRule.RecipientDomainIs -ExcludedUsers $standardProtectionRule.ExceptIfSentTo -ExcludedGroups $standardProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $standardProtectionRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                Write-Message "Found $($recipients.Count) affected/protected recipients"
                            }
                        }
                        # Handle custom protection rules
                        foreach ($customAntiPhishPolicy in Get-AntiPhishPolicy | Where-Object{$_.Identity -ne 'Office 365 AntiPhish Default' -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customAntiPhishRule = Get-AntiPhishRule | Where-Object{$_.AntiPhishPolicy -eq $customAntiPhishPolicy.Identity}).State -eq 'Enabled'){
                                Write-Message "ATP custom anti-phishing policy '$($customAntiPhishPolicy.Name)'"
                                if ($null -ne ($recipients = Get-ATPRecipient -IncludedUsers $customAntiPhishRule.SentTo -IncludedGroups $customAntiPhishRule.SentToMemberOf -IncludedDomains $customAntiPhishRule.RecipientDomainIs -ExcludedUsers $customAntiPhishRule.ExceptIfSentTo -ExcludedGroups $customAntiPhishRule.ExceptIfSentToMemberOf -ExcludedDomains $customAntiPhishRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                    $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                    if ($customAntiPhishPolicy.Enabled) {
                                        $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                        Write-Message "Found $($recipients.Count) affected, $($recipients.Count) protected recipients"
                                    }
                                    else {
                                        Write-Message "Found $($recipients.Count) affected, 0 protected recipients"
                                    }
                                }
                            }
                        }
                        foreach ($customSafeAttachmentPolicy in Get-SafeAttachmentPolicy | Where-Object{$_.IsBuiltInProtection -eq $false -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customSafeAttachmentRule = Get-SafeAttachmentRule | Where-Object{$_.SafeAttachmentPolicy -eq $customSafeAttachmentPolicy.Identity}).State -eq 'Enabled'){
                                Write-Message "ATP custom Safe Attachments policy '$($customSafeAttachmentPolicy.Name)'"
                                if ($null -ne ($recipients = Get-ATPRecipient -IncludedUsers $customSafeAttachmentRule.SentTo -IncludedGroups $customSafeAttachmentRule.SentToMemberOf -IncludedDomains $customSafeAttachmentRule.RecipientDomainIs -ExcludedUsers $customSafeAttachmentRule.ExceptIfSentTo -ExcludedGroups $customSafeAttachmentRule.ExceptIfSentToMemberOf -ExcludedDomains $customSafeAttachmentRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                    $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                    if ($customSafeAttachmentPolicy.Enable) {
                                        $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                        Write-Message "Found $($recipients.Count) affected, $($recipients.Count) protected recipients"
                                    }
                                    else {
                                        Write-Message "Found $($recipients.Count) affected, 0 protected recipients"
                                    }
                                }
                            }
                        }
                        foreach ($customSafeLinksPolicy in Get-SafeLinksPolicy | Where-Object{$_.IsBuiltInProtection -eq $false -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customSafeLinksRule = Get-SafeLinksRule | Where-Object{$_.SafeLinksPolicy -eq $customSafeLinksPolicy.Identity}).State -eq 'Enabled'){
                                Write-Message "ATP custom Safe Links policy '$($customSafeLinksPolicy.Name)'"
                                if ($null -ne ($recipients = Get-ATPRecipient -IncludedUsers $customSafeLinksRule.SentTo -IncludedGroups $customSafeLinksRule.SentToMemberOf -IncludedDomains $customSafeLinksRule.RecipientDomainIs -ExcludedUsers $customSafeLinksRule.ExceptIfSentTo -ExcludedGroups $customSafeLinksRule.ExceptIfSentToMemberOf -ExcludedDomains $customSafeLinksRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                                    $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                    if ($customSafeLinksPolicy.EnableSafeLinksForEmail -or $customSafeLinksPolicy.EnableSafeLinksForOffice -or $customSafeLinksPolicy.EnableSafeLinksForTeams) {
                                        $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                        Write-Message "Found $($recipients.Count) affected, $($recipients.Count) protected recipients"
                                    }
                                    else {
                                        Write-Message "Found $($recipients.Count) affected, 0 protected recipients"
                                    }
                                }
                            }
                        }
                        # Handle built-in protection rule
                        Write-Message 'ATP built-in rule'
                        $builtinProtectionRule = Get-ATPBuiltInProtectionRule
                        if ($null -ne ($recipients = Get-ATPRecipient -IncludedUsers $builtinProtectionRule.SentTo -IncludedGroups $builtinProtectionRule.SentToMemberOf -IncludedDomains $builtinProtectionRule.RecipientDomainIs -ExcludedUsers $builtinProtectionRule.ExceptIfSentTo -ExcludedGroups $builtinProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $builtinProtectionRule.ExceptIfRecipientDomainIs | Where-Object{$_.ExternalDirectoryObjectId -notin $matchedRecipients})) {
                            $matchedRecipients.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                            $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                            Write-Message "Found $($recipients.Count) affected/protected recipients"
                        }
                    }
                }
                else {
                    $ATPvariant = 'EOP'
                    Write-Message 'Identified an Exchange Online Protection tenant'
                }
                Disconnect-ExchangeOnline -Confirm:$false
            }
            # Intune Device based on devices managed by Intune and used by unlicensed users
            $managedDevices = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$expand=users'
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $managedDevices.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
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
                Write-Message "Found $neededCount needed, $AADP1Licenses enabled AADP1 licenses"
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
                Write-Message "Found $neededCount needed, $AADP2Licenses enabled AADP2 licenses"
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
                        Write-Message "Found $neededCount needed, $ATPLicenses enabled DfOP2 licenses"
                        if ($ATPLicenses -lt $neededCount) {
                            Add-Result -PlanName 'Microsoft Defender for Office 365 P1' -EnabledCount $ATPLicenses -NeededCount $neededCount
                        }
                    }
                    'DfOP2' {
                        $ATPSKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '8e0c0a52-6a6c-4d40-8370-dd62790dcd70'})
                        $ATPLicenses = ($ATPSKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                        Write-Message "Found $neededCount needed, $ATPLicenses enabled DfOP2 licenses"
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
            if ($results.ContainsKey('SKU_Basic')) {
                Add-Output -Output "<p>Please check license counts for the following product SKUs and <a href=""$LicensingURL"">reserve</a> additional licenses:</p> `
                                    <p><table><tr>
                                    <th>License type</th>
                                    <th>Available count</th>
                                    <th>Minimum count</th>
                                    <th>Difference</th></tr>"
                foreach ($SKU in $results['SKU_Basic'].Keys) {
                    $differenceCount = $results['SKU_Basic'][$SKU]['availableCount'] - $results['SKU_Basic'][$SKU]['minimumCount']
                    Add-Output -Output "<tr> `
                                        <td>$(Get-SKUName -SKUID $SKU)</td> `
                                        <td>$($results['SKU_Basic'][$SKU]['availableCount'])</td> `
                                        <td>$($results['SKU_Basic'][$SKU]['minimumCount'])</td>"
                    if ($results['SKU_Basic'][$SKU]['availableCount'] / $results['SKU_Basic'][$SKU]['minimumCount'] * 100 -ge $SKUWarningThreshold_basic) {
                        Add-Output -Output "<td class=green>$differenceCount</td>"
                    }
                    elseif ($results['SKU_Basic'][$SKU]['availableCount'] / $results['SKU_Basic'][$SKU]['minimumCount'] * 100 -le $SKUCriticalThreshold_basic) {
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
                Add-Output -Output '<p>Nothing to report</p>'
            }
            # Output advanced SKU results
            Add-Output -Output '<p class=gray>Advanced checkup - Products</p>'
            if ($results.ContainsKey('SKU_Advanced')) {
                Add-Output -Output "<p>Please check license counts for the following product SKUs and <a href=""$LicensingURL"">reserve</a> additional licenses:</p> `
                                    <p><table><tr>
                                    <th>License type</th>
                                    <th>Enabled count</th>
                                    <th>Needed count</th>
                                    <th>Difference</th></tr>"
                foreach ($plan in $results['SKU_Advanced'].Keys) {
                    $differenceCount = $results['SKU_Advanced'][$plan]['enabledCount'] - $results['SKU_Advanced'][$plan]['neededCount']
                    Add-Output -Output "<tr> `
                                        <td>$plan</td> `
                                        <td>$($results['SKU_Advanced'][$plan]['enabledCount'])</td> `
                                        <td>$($results['SKU_Advanced'][$plan]['neededCount'])</td>"
                    if ($results['SKU_Advanced'][$plan]['enabledCount'] / $results['SKU_Advanced'][$plan]['neededCount'] * 100 -ge $SKUWarningThreshold_advanced) {
                        Add-Output -Output "<td class=green>$differenceCount</td>"
                    }
                    elseif ($results['SKU_Advanced'][$plan]['enabledCount'] / $results['SKU_Advanced'][$plan]['neededCount'] * 100 -le $SKUCriticalThreshold_advanced) {
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
                                    <li>Check <i>Azure AD P1</i> based on groups using dynamic user membership</li>
                                    <li>Check <i>Azure AD P1</i> based on applications using group-based assignment</li>
                                    <li>Check <i>Azure AD P1</i> based on users covered by Conditional Access</li>
                                    <li>Check <i>Azure AD P2</i> based on users in scope of Privileged Identity Management</li>
                                    <li>Check <i>Defender for Office 365 P1/P2</i> based on protected Exchange Online recipients</li></ul></p>'
            }
            else {
                Add-Output -Output '<p>Nothing to report</p>'
            }
            # Output basic user results
            Add-Output -Output '<p class=gray>Basic checkup - Users</p>'
            if ($results.ContainsKey('User_Basic')) {
                [decimal]$possibleSavings = 0
                Add-Output -Output '<p>Please check license assignments for the following user accounts and mitigate impact:</p>
                                    <p><table><tr>
                                    <th>Account</th>
                                    <th>Interchangeable</th>
                                    <th>Optimizable</th>
                                    <th>Removable</th></tr>'
                foreach ($user in $results['User_Basic'].Keys | Sort-Object) {
                    $interchangeableSKUIDs = $results['User_Basic'][$user]['Interchangeable'] | Where-Object{$null -ne $_}
                    $optimizableSKUIDs = $results['User_Basic'][$user]['Optimizable'] | Where-Object{$null -ne $_}
                    $removableSKUIDs = $results['User_Basic'][$user]['Removable'] | Where-Object{$null -ne $_}
                    if ($null -ne $SKUPrices) {
                        $possibleSavings += ($interchangeableSKUIDs | ForEach-Object{[decimal]$SKUPrices["$_"]} | Sort-Object | Select-Object -Skip 1 | Measure-Object -Sum).Sum +
                                            ($optimizableSKUIDs | ForEach-Object{[decimal]$SKUPrices["$_"]} | Measure-Object -Sum).Sum +
                                            ($removableSKUIDs | ForEach-Object{[decimal]$SKUPrices["$_"]} | Measure-Object -Sum).Sum
                    }
                    Add-Output -Output "<tr> `
                                        <td>$user</td> `
                                        <td>$(($interchangeableSKUIDs |
                                                ForEach-Object{Get-SKUName -SKUID $_} |
                                                Sort-Object) -join '<br>')</td> `
                                        <td>$(($optimizableSKUIDs |
                                                ForEach-Object{Get-SKUName -SKUID $_} |
                                                Sort-Object) -join '<br>')</td> `
                                        <td>$(($removableSKUIDs |
                                                ForEach-Object{Get-SKUName -SKUID $_} |
                                                Sort-Object) -join '<br>')</td></tr>"
                }
                Add-Output -Output '</table></p>
                                    <p>The following criteria were used during the checkup:<ul>
                                    <li>Check accounts with any number of assigned licenses</li>
                                    <li>Report theoretically exclusive licenses as <strong>interchangeable</strong>, based on specified SKUs</li>
                                    <li>Report practically inclusive licenses as <strong>optimizable</strong>, based on available SKU features</li>
                                    <li>Report actually inclusive licenses as <strong>removable</strong>, based on enabled SKU features</li></ul></p>'
                if ($possibleSavings -gt 0) {
                    Add-Output -Output ('<p>Possible savings: {0:C}</p>' -f $possibleSavings)
                }
            }
            else {
                Add-Output -Output '<p>Nothing to report</p>'
            }
            # Output advanced user results
            Add-Output -Output '<p class=gray>Advanced checkup - Users</p>'
            if ($results.ContainsKey('User_Advanced')) {
                [decimal]$possibleSavings = 0
                Add-Output -Output '<p>Please check license assignments for the following user accounts and mitigate impact:</p>
                                    <p><table><tr>
                                    <th>Account</th>
                                    <th>Preferable</th>
                                    <th>Interchangeable</th></tr>'
                foreach ($user in $results['User_Advanced'].Keys | Sort-Object) {
                    $preferableSKUID = $results['User_Advanced'][$user]['Preferable']['preferableSKU'] | Where-Object{$null -ne $_}
                    $opposingSKUIDs = $results['User_Advanced'][$user]['Preferable']['opposingSKUs'] | Where-Object{$null -ne $_}
                    if ($null -ne $SKUPrices) {
                        $possibleSavings += ($opposingSKUIDs | ForEach-Object{[decimal]$SKUPrices["$_"]} | Measure-Object -Sum).Sum -
                                            [decimal]$SKUPrices["$preferableSKUID"]
                    }
                    Add-Output -Output "<tr> `
                                        <td>$user</td> `
                                        <td>$(Get-SKUName -SKUID $preferableSKUID)</td>
                                        <td>$(($opposingSKUIDs |
                                                ForEach-Object{Get-SKUName -SKUID $_} |
                                                Sort-Object) -join '<br>')</td></tr>"
                }
                Add-Output -Output '</table></p>
                                    <p>The following criteria were used during the checkup, in order:</p>
                                    <p><table><tr>
                                    <th>License type</th>
                                    <th>Activity limit</th>
                                    <th>OneDrive limit</th>
                                    <th>Mailbox limit</th>
                                    <th>Mailbox archive</th>
                                    <th>Windows app</th>
                                    <th>Mac app</th>
                                    <th>Mobile app</th>
                                    <th>Web app</th></tr>'
                foreach ($preferableSKU in $PreferableSKUs) {
                    Add-Output -Output ('<tr><td>{0}</td><td>{1:yyyy-MM-dd}</td><td>{2} GB</td><td>{3} GB</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f
                                        (Get-SKUName -SKUID $preferableSKU.SKUID),
                                        $preferableSKU.LastActiveEarlierThan,
                                        $preferableSKU.OneDriveGBUsedLessThan,
                                        $preferableSKU.MailboxGBUsedLessThan,
                                        $preferableSKU.MailboxHasArchive,
                                        $preferableSKU.WindowsAppUsed,
                                        $preferableSKU.MacAppUsed,
                                        $preferableSKU.MobileAppUsed,
                                        $preferableSKU.WebAppUsed)
                }
                Add-Output -Output '</table></p>'
                if ($possibleSavings -gt 0) {
                    Add-Output -Output ('<p>Possible savings: {0:C}</p>' -f $possibleSavings)
                }
            }
            else {
                Add-Output -Output '<p>Nothing to report</p>'
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