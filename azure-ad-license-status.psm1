Set-StrictMode -Version 3.0

#region: Classes
class AdvancedUserResult {
    [string]$UserPrincipalName
    [guid]$PreferableSKUID
    [guid[]]$ReplaceableSKUIDs
}

class BasicUserResult {
    [string]$UserPrincipalName
    [guid[]]$InterchangeableSKUIDs
    [guid[]]$OptimizableSKUIDs
    [guid[]]$RemovableSKUIDs
}

class SKUPrice {
    [guid]$SKUID
    [decimal]$Price
}

class SKURule {
    [guid]$SKUID
    [ValidateSet('True', 'False', 'Skip')]
    [string]$AccountEnabled = [SKURule]::AccountEnabledDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$AccountGuest = [SKURule]::AccountGuestDefault()
    [datetime]$CreatedEarlierThan = [SKURule]::CreatedEarlierThanDefault()
    [datetime]$LastActiveEarlierThan = [SKURule]::LastActiveEarlierThanDefault()
    [datetime]$LastLicenseChangeEarlierThan = [SKURule]::LastLicenseChangeEarlierThanDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$DeviceOwned = [SKURule]::DeviceOwnedDefault()
    [decimal]$OneDriveGBUsedLessThan = [SKURule]::OneDriveGBUsedLessThanDefault()
    [decimal]$MailboxGBUsedLessThan = [SKURule]::MailboxGBUsedLessThanDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$MailboxHasArchive = [SKURule]::MailboxHasArchiveDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$WindowsAppUsed = [SKURule]::WindowsAppUsedDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$MacAppUsed = [SKURule]::MacAppUsedDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$MobileAppUsed = [SKURule]::MobileAppUsedDefault()
    [ValidateSet('True', 'False', 'Skip')]
    [string]$WebAppUsed = [SKURule]::WebAppUsedDefault()

    static [string]AccountEnabledDefault() {
        return 'Skip'
    }
    static [string]AccountGuestDefault() {
        return 'Skip'
    }
    static [datetime]CreatedEarlierThanDefault() {
        return [datetime]::MaxValue
    }
    static [datetime]LastActiveEarlierThanDefault() {
        return [datetime]::MaxValue
    }
    static [datetime]LastLicenseChangeEarlierThanDefault() {
        return [datetime]::MaxValue
    }
    static [string]DeviceOwnedDefault() {
        return 'Skip'
    }
    static [UInt16]OneDriveGBUsedLessThanDefault() {
        return [UInt16]::MaxValue
    }
    static [UInt16]MailboxGBUsedLessThanDefault() {
        return [UInt16]::MaxValue
    }
    static [string]MailboxHasArchiveDefault() {
        return 'Skip'
    }
    static [string]WindowsAppUsedDefault() {
        return 'Skip'
    }
    static [string]MacAppUsedDefault() {
        return 'Skip'
    }
    static [string]MobileAppUsedDefault() {
        return 'Skip'
    }
    static [string]WebAppUsedDefault() {
        return 'Skip'
    }
}
#endregion

#region: Functions
function Initialize-Module {
    [OutputType([void])]

    $script:nestingLevel = 0
    $script:results = @{}
    $script:skuTranslate = [System.Text.Encoding]::UTF8.GetString((Invoke-WebRequest -Uri 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv' -UseBasicParsing).Content) | ConvertFrom-Csv
    $script:appUsage = @{}
    $script:mailboxUsage = @{}
    $script:driveUsage = @{}
}

function Write-Message {
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [ValidateSet('Error', 'Verbose')]
        [string]$Type,
        [ValidateSet('AuthenticationError', 'InvalidArgument', 'InvalidData')]
        [string]$Category
    )

    $formattedMessage = '[{0:yyyy-MM-dd HH:mm:ss}] {1}{2}' -f
                        [datetime]::Now,
                        [string]::new('-', $nestingLevel),
                        $Message
    if ($Type -eq 'Error') {
        Write-Error -Message $formattedMessage -Category $Category
    }
    elseif ($Type -eq 'Verbose') {
        Write-Verbose -Message $formattedMessage
    }
    else {
        $formattedMessage | Write-Output
    }
}

function Add-Result {
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Basic')]
        [ValidateNotNullOrEmpty()]
        [guid]$SKUID,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Basic')]
        [ValidateNotNullOrEmpty()]
        [Int32]$AvailableCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Basic')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$MinimumCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Advanced')]
        [ValidateNotNullOrEmpty()]
        [string]$PlanName,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Advanced')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$EnabledCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'SKU_Advanced')]
        [ValidateNotNullOrEmpty()]
        [UInt32]$NeededCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Basic')]
        [BasicUserResult]$BasicUserResult,
        [Parameter(Mandatory = $true, ParameterSetName = 'User_Advanced')]
        [AdvancedUserResult]$AdvancedUserResult
    )

    # Logging
    $nestingLevel++
    Write-Message 'Add-Result' -Type Verbose
    # Processing
    switch ($PSCmdlet.ParameterSetName) {
        'SKU_Basic' {
            if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
                $results.Add($PSCmdlet.ParameterSetName, @{})
            }
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($SKUID)) {
                $results[$PSCmdlet.ParameterSetName].Add($SKUID, @{
                    'availableCount' = $AvailableCount
                    'minimumCount' = $MinimumCount
                })
            }
        }
        'SKU_Advanced' {
            if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
                $results.Add($PSCmdlet.ParameterSetName, @{})
            }
            if (-not $results[$PSCmdlet.ParameterSetName].ContainsKey($PlanName)) {
                $results[$PSCmdlet.ParameterSetName].Add($PlanName, @{
                    'enabledCount' = $EnabledCount
                    'neededCount' = $NeededCount
                })
            }
        }
        'User_Basic' {
            if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
                $results.Add($PSCmdlet.ParameterSetName, [System.Collections.Generic.List[BasicUserResult]]::new())
            }
            $results[$PSCmdlet.ParameterSetName].Add($BasicUserResult)
        }
        'User_Advanced' {
            if (-not $results.ContainsKey($PSCmdlet.ParameterSetName)) {
                $results.Add($PSCmdlet.ParameterSetName, [System.Collections.Generic.List[AdvancedUserResult]]::new())
            }
            $results[$PSCmdlet.ParameterSetName].Add($AdvancedUserResult)
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
    if ($groupMembers.Count -gt 0) {
        $groupMembers_unique = @($groupMembers.id | Sort-Object -Unique)
    }
    else {
        $groupMembers_unique = @()
    }
    Write-Message "Found $($groupMembers_unique.Count) members" -Type Verbose
    $nestingLevel--
    Write-Output ([guid[]]$groupMembers_unique) -NoEnumerate
}

function Get-EXOGroupMember {
    [OutputType([psobject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid[]]$GroupIDs
    )

    # Logging
    $nestingLevel++
    Write-Message 'Get-EXOGroupMember' -Type Verbose
    # Processing
    $groupMembers = [System.Collections.Generic.List[psobject]]::new()
    foreach ($groupID in $GroupIDs) {
        if ($null -ne ($group = [pscustomobject](Get-EXORecipient $groupID -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties) | Select-Object -Property $EXOProperties)) {
            switch ($group.RecipientTypeDetails) {
                'GroupMailbox' {
                    $members = @(Get-UnifiedGroupLinks $group.ExternalDirectoryObjectId -LinkType Members -ResultSize Unlimited | Select-Object -Property $EXOProperties)
                }
                Default {
                    $members = @(Get-DistributionGroupMember $group.ExternalDirectoryObjectId -ResultSize Unlimited | Select-Object -Property $EXOProperties)
                }
            }
            foreach ($member in $members) {
                switch ($member.RecipientTypeDetails) {
                    {$_ -in $EXOTypes_user} {
                        $groupMembers.Add($member)
                    }
                    {$_ -in $EXOTypes_group} {
                        $groupMembers.AddRange((Get-EXOGroupMember -GroupIDs $member.ExternalDirectoryObjectId))
                    }
                }
            }
        }
    }
    $groupMembers_unique = @($groupMembers | Sort-Object -Property $EXOProperties -Unique)
    Write-Message "Found $($groupMembers_unique.Count) members" -Type Verbose
    $nestingLevel--
    Write-Output ([pscustomobject[]]$groupMembers_unique) -NoEnumerate
}

function Resolve-ATPRecipient {
    [OutputType([psobject[]])]
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
    $affectedAsUser = [System.Collections.Generic.List[psobject]]::new()
    $affectedAsGroup = [System.Collections.Generic.List[psobject]]::new()
    $affectedAsDomain = [System.Collections.Generic.List[psobject]]::new()
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
            $affectedAsGroup.AddRange((Get-EXOGroupMember -GroupIDs $recipients.ExternalDirectoryObjectId))
        }
    }
    Write-Message "Found $($affectedAsGroup.Count) recipients by groups" -Type Verbose
    if ($null -ne $Domains) {
        $categoryCount++
        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_user -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress.Split('@')[1] -in $Domains})) {
            $affectedAsDomain.AddRange([pscustomobject[]]@($recipients))
        }
        if ($null -ne ($recipients = [pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties -ResultSize Unlimited) | Select-Object -Property $EXOProperties | Where-Object{$_.PrimarySmtpAddress.Split('@')[1] -in $Domains})) {
            $affectedAsDomain.AddRange((Get-EXOGroupMember -GroupIDs $recipients.ExternalDirectoryObjectId))
        }
    }
    Write-Message "Found $($affectedAsDomain.Count) recipients by domains" -Type Verbose
    if ($null -ne ($resolvedUsers = @($affectedAsUser | Sort-Object -Property $EXOProperties -Unique) + @($affectedAsGroup | Sort-Object -Property $EXOProperties -Unique) + @($affectedAsDomain | Sort-Object -Property $EXOProperties -Unique) | Group-Object -Property ExternalDirectoryObjectId | Where-Object{$_.Count -eq $categoryCount})) {
        $resolvedUsers_unique = @($resolvedUsers.Group | Sort-Object -Property $EXOProperties -Unique)
        Write-Message "Found $($resolvedUsers_unique.Count) recipients by combination" -Type Verbose
        $nestingLevel--
        Write-Output ([pscustomobject[]]$resolvedUsers_unique) -NoEnumerate
    }
    else {
        Write-Message 'Found 0 recipients by combination' -Type Verbose
        $nestingLevel--
        Write-Output @([psobject[]]::new(0)) -NoEnumerate
    }
}

function Get-ATPRecipient {
    [OutputType([psobject[]])]
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
        $groupRecipients = Get-EXOGroupMember -GroupIDs ([pscustomobject[]]@(Get-EXORecipient -RecipientTypeDetails $EXOTypes_group -Properties $EXOProperties -ResultSize Unlimited)).ExternalDirectoryObjectId
        $includedRecipients = [pscustomobject[]]@($userRecipients + $groupRecipients | Sort-Object -Property $EXOProperties -Unique)
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
    $affectedRecipients = [System.Collections.Generic.List[psobject]]::new()
    if ($null -ne ($affectedRecipientComparison = Compare-Object -ReferenceObject $includedRecipients -DifferenceObject $excludedRecipients -Property $EXOProperties)) {
        if ($null -ne ($affectedRecipientResults = $affectedRecipientComparison | Where-Object{$_.SideIndicator -eq '<='})) {
            $affectedRecipients.AddRange([pscustomobject[]]@($affectedRecipientResults | Select-Object -Property $EXOProperties))
        }
    }
    $affectedRecipients_unique = @($affectedRecipients | Sort-Object -Property $EXOProperties -Unique)
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
    elseif ($null -ne ($skuName = ($skuTranslate | Where-Object{$_.GUID -eq $SKUID}).Product_Display_Name | Sort-Object -Unique)) {
        $skuName = [cultureinfo]::new('en-US').TextInfo.ToTitleCase($skuName.ToLower())
    }
    else {
        $skuName = $SKUID
    }
    $nestingLevel--
    Write-Output $skuName
}
#endregion

#region: Variables
# Exchange Online
$EXOCmdlets = @(
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
$EXOProperties = @(
    'ExternalDirectoryObjectId',
    'PrimarySmtpAddress',
    'RecipientTypeDetails')
$EXOTypes_group = @(
    'GroupMailbox',
    'MailUniversalDistributionGroup',
    'MailUniversalSecurityGroup')
$EXOTypes_user = @(
    'SharedMailbox',
    'UserMailbox')
# Graph
$pageSize = 500
$reportDays = 180
#endregion

function Get-AzureADLicenseStatus {
    # .EXTERNALHELP azure-ad-license-status.psm1-help.xml

    [CmdletBinding(PositionalBinding = $false)]
    [OutputType([void])]
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
        [ValidateRange(1, 99)]
        [UInt16]$SKUWarningThreshold_basic = 80,
        [ValidateRange(1, 99)]
        [UInt16]$SKUCriticalThreshold_basic = 20,
        [ValidateRange(1, 99)]
        [UInt16]$SKUWarningThreshold_advanced = 99,
        [ValidateRange(1, 99)]
        [UInt16]$SKUCriticalThreshold_advanced = 95,
        [ValidateNotNullOrEmpty()]
        [guid[]]$ImportantSKUs,
        [ValidateNotNullOrEmpty()]
        [guid[]]$InterchangeableSKUs,
        [ValidateNotNullOrEmpty()]
        [SKURule[]]$PreferableSKUs,
        [ValidateNotNullOrEmpty()]
        [SKUPrice[]]$SKUPrices,
        [ValidateNotNullOrEmpty()]
        [hashtable]$HumanUserAttributes,
        [ValidateSet('CSV', 'TranslatedCSV', 'JSON')]
        [string]$AttachmentFormat,
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
                $null = Connect-MgGraph -Certificate $azureCertificate -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop
            }
            'LocalCertificate' {
                $null = Connect-MgGraph -Certificate $Certificate -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop
            }
            'LocalCertificateThumbprint' {
                $null = Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -TenantId $DirectoryID -ClientId $ApplicationID -ErrorAction Stop
            }
        }
        $graphAuthentication = $true
        Write-Message 'Succeeded to authenticate with Graph' -Type Verbose
    }
    catch {
        $graphAuthentication = $false
        Write-Message -Message 'Failed to authenticate with Graph' -Type Error -Category AuthenticationError
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
                    # Replace with 'IsSubsetOf'
                    <#
                    if ($null -ne ($comparisonSKU = Compare-Object -ReferenceObject $referenceServicePlans.servicePlanId -DifferenceObject $differenceServicePlans.servicePlanId -IncludeEqual) -and
                    $comparisonSKU.SideIndicator -contains '==' -and
                    $comparisonSKU.SideIndicator -notcontains '=>') {
                        if (-not $superiorSKUs_organization.ContainsKey($differenceSKU.skuId)) {
                            $superiorSKUs_organization.Add($differenceSKU.skuId, [System.Collections.Generic.List[guid]]::new())
                        }
                        $superiorSKUs_organization[$differenceSKU.skuId].Add($referenceSKU.skuId)
                    }
                    #>
                    $referenceServicePlanIDs = [System.Collections.Generic.HashSet[guid]]$referenceServicePlans.servicePlanId
                    $differenceServicePlanIDs = [System.Collections.Generic.HashSet[guid]]$differenceServicePlans.servicePlanId
                    if ($referenceServicePlanIDs.IsSupersetOf($differenceServicePlanIDs)) {
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
        if ($AdvancedCheckups) {
            Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/reports/getM365AppUserDetail(period=''D{0}'')?$format=text/csv' -f $reportDays) -OutputFilePath "$env:TEMP\appUsage.csv"
            foreach ($entry in Import-Csv "$env:TEMP\appUsage.csv" | Select-Object -Property 'User Principal Name', 'Last Activity Date', 'Windows', 'Mac', 'Mobile', 'Web') {
                if (-not $appUsage.ContainsKey($entry.'User Principal Name')) {
                    $lastActivityDate = [datetime]::MinValue
                    $null = [datetime]::TryParse($entry.'Last Activity Date', [ref]$lastActivityDate)
                    if ($entry.'Windows' -eq 'Yes') {
                        $windowsApp = $true
                    }
                    else {
                        $windowsApp = $false
                    }
                    if ($entry.'Mac' -eq 'Yes') {
                        $macApp = $true
                    }
                    else {
                        $macApp = $false
                    }
                    if ($entry.'Mobile' -eq 'Yes') {
                        $mobileApp = $true
                    }
                    else {
                        $mobileApp = $false
                    }
                    if ($entry.'Web' -eq 'Yes') {
                        $webApp = $true
                    }
                    else {
                        $webApp = $false
                    }
                    $appUsage.Add($entry.'User Principal Name', @{
                        'LastActivityDate' = $lastActivityDate
                        'WindowsApp' = $windowsApp
                        'MacApp' = $macApp
                        'MobileApp' = $mobileApp
                        'WebApp' = $webApp
                    })
                }
                else {
                    Write-Message -Message "Found duplicate user name $($entry.'User Principal Name') in app usage reports" -Type Error -Category InvalidData
                }
            }
            Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period=''D{0}'')' -f $reportDays) -OutputFilePath "$env:TEMP\mailboxUsage.csv"
            foreach ($entry in Import-Csv "$env:TEMP\mailboxUsage.csv" | Select-Object -Property 'User Principal Name', 'Is Deleted', 'Last Activity Date', 'Storage Used (Byte)', 'Has Archive' | Where-Object{$_.'Is Deleted' -eq 'False'}) {
                if (-not $mailboxUsage.ContainsKey($entry.'User Principal Name')) {
                    $lastActivityDate = [datetime]::MinValue
                    $null = [datetime]::TryParse($entry.'Last Activity Date', [ref]$lastActivityDate)
                    $storageUsed = [decimal]($entry.'Storage Used (Byte)' / [System.Math]::Pow(1000, 3))
                    $hasArchive = [bool]::Parse($entry.'Has Archive')
                    $mailboxUsage.Add($entry.'User Principal Name', @{
                        'LastActivityDate' = $lastActivityDate
                        'StorageUsed' = $storageUsed
                        'HasArchive' = $hasArchive
                    })
                }
                else {
                    Write-Message -Message "Found duplicate user name $($entry.'User Principal Name') in mailbox usage reports" -Type Error -Category InvalidData
                }
            }
            Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period=''D{0}'')' -f $reportDays) -OutputFilePath "$env:TEMP\driveUsage.csv"
            foreach ($entry in Import-Csv "$env:TEMP\driveUsage.csv" | Select-Object -Property 'Owner Principal Name', 'Is Deleted', 'Last Activity Date', 'Storage Used (Byte)' | Where-Object{$_.'Is Deleted' -eq 'False'}) {
                if (-not $driveUsage.ContainsKey($entry.'Owner Principal Name')) {
                    $lastActivityDate = [datetime]::MinValue
                    $null = [datetime]::TryParse($entry.'Last Activity Date', [ref]$lastActivityDate)
                    $storageUsed = [decimal]($entry.'Storage Used (Byte)' / [System.Math]::Pow(1000, 3))
                    $driveUsage.Add($entry.'Owner Principal Name', @{
                        'LastActivityDate' = $lastActivityDate
                        'StorageUsed' = $storageUsed
                    })
                }
                else {
                    Write-Message -Message "Found duplicate user name $($entry.'Owner Principal Name') in OneDrive usage reports" -Type Error -Category InvalidData
                }
            }
            if ($appUsage.Keys.Count -gt 0 -and
            $mailboxUsage.Keys.Count -gt 0 -and
            $driveUsage.Keys.Count -gt 0) {
                if ($appUsage.Keys -like '*@*' -or
                $mailboxUsage.Keys -like '*@*' -or
                $driveUsage.Keys -like '*@*') {
                    $hashedReports = $false
                }
                else {
                    $hashedReports = $true
                }
                $reportsRetrieved = $true
                Write-Message -Message 'Succeeded to retrieve usage reports' -Type Verbose
            }
            else {
                $reportsRetrieved = $false
                Write-Message -Message 'Failed to retrieve usage reports' -Type Error -Category InvalidData
            }
        }
        #endregion

        #region: Users
        # Retrieve users
        $userCount = 0
        $URI = 'https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled,createdDateTime,licenseAssignmentStates,userPrincipalName,userType&$expand=ownedDevices&$top={0}' -f $pageSize
        while ($null -ne $URI) {
            $data = Invoke-MgGraphRequest -Method GET -Uri $URI
            $users = [hashtable[]]($data.value)
            $userCount += $users.Count
            $URI = $data['@odata.nextLink']
            # Analyze users
            foreach ($user in $users) {
                if ($user.licenseAssignmentStates.Count -gt 0) {
                    if ($null -ne ($userSKUAssignments = $user.licenseAssignmentStates | Where-Object{$_.state -eq 'Active' -or $_.error -in @('CountViolation', 'MutuallyExclusiveViolation')})) {
                        $userSKUs = $userSKUAssignments.skuId
                    }
                    else {
                        $userSKUs = @()
                    }
                    if ($null -ne ($countViolations = $user.licenseAssignmentStates | Where-Object{$_.error -eq 'CountViolation'})) {
                        foreach ($countViolation in $countViolations.skuId | Sort-Object -Unique) {
                            $results['SKU_Basic'][[guid]$countViolation]['availableCount'] -= 1
                        }
                    }
                    # Identify interchangeable SKUs, based on specifications
                    $userSKUs_interchangeable = @()
                    if ($null -ne $userSKUs -and
                    $null -ne $InterchangeableSKUs) {
                        # Replace with 'IntersectWith'
                        <#
                        if ($null -ne ($comparison_interchangeable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $InterchangeableSKUs -ExcludeDifferent -IncludeEqual)) {
                            $userSKUs_interchangeable = @($comparison_interchangeable.InputObject)
                        }
                        #>
                        $userSKUs_interchangeable = [System.Collections.Generic.HashSet[guid]]$userSKUs
                        $organizationSKUs_interchangeable = [System.Collections.Generic.HashSet[guid]]$InterchangeableSKUs
                        $userSKUs_interchangeable.IntersectWith($organizationSKUs_interchangeable)
                    }
                    # Identify optimizable SKUs, based on organization-level calculations
                    if ($null -ne ($comparison_replaceableOrganization = $userSKUs | Where-Object{$_ -in $superiorSKUs_organization.Keys} | ForEach-Object{$superiorSKUs_organization[$_]})) {
                        # Replace with 'IntersectWith'
                        $userSKUs_optimizable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableOrganization -ExcludeDifferent -IncludeEqual | ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_organization.Keys | Where-Object{$superiorSKUs_organization[$_] -contains $superiorSKU}} | Where-Object{$_ -in $userSKUs} | Sort-Object -Unique
                    }
                    else {
                        $userSKUs_optimizable = $null
                    }
                    # Identify removable SKUs, based on user-level calculations
                    $skuid_enabledPlans = @{}
                    foreach ($skuid in $user.licenseAssignmentStates.skuid | Where-Object{$organizationSKUs.skuId -contains $_} | Sort-Object -Unique) {
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
                                # Replace with 'IsSubsetOf'
                                <#
                                if ($null -ne ($comparisonSKU = Compare-Object -ReferenceObject $referenceServicePlans -DifferenceObject $differenceServicePlans -IncludeEqual) -and
                                $comparisonSKU.SideIndicator -contains '==' -and
                                $comparisonSKU.SideIndicator -notcontains '=>') {
                                    if (-not $superiorSKUs_user.ContainsKey($differenceSKU)) {
                                        $superiorSKUs_user.Add($differenceSKU, [System.Collections.Generic.List[guid]]::new())
                                    }
                                    $superiorSKUs_user[$differenceSKU].Add($referenceSKU)
                                }
                                #>
                                $referenceServicePlanIDs = [System.Collections.Generic.HashSet[guid]]$referenceServicePlans
                                $differenceServicePlanIDs = [System.Collections.Generic.HashSet[guid]]$differenceServicePlans
                                if ($referenceServicePlanIDs.IsSupersetOf($differenceServicePlanIDs)) {
                                    if (-not $superiorSKUs_user.ContainsKey($differenceSKU)) {
                                        $superiorSKUs_user.Add($differenceSKU, [System.Collections.Generic.List[guid]]::new())
                                    }
                                    $superiorSKUs_user[$differenceSKU].Add($referenceSKU)
                                }
                            }
                        }
                    }
                    if ($null -ne ($comparison_replaceableUser = $userSKUs | Where-Object{$_ -in $superiorSKUs_user.Keys} | ForEach-Object{$superiorSKUs_user[$_]})) {
                        # Replace with 'IntersectWith'
                        $userSKUs_removable = Compare-Object -ReferenceObject $userSKUs -DifferenceObject $comparison_replaceableUser -ExcludeDifferent -IncludeEqual | ForEach-Object{$superiorSKU = $_.InputObject; $superiorSKUs_user.Keys | Where-Object{$superiorSKUs_user[$_] -contains $superiorSKU}} | Where-Object{$_ -in $userSKUs} | Sort-Object -Unique
                    }
                    else {
                        $userSKUs_removable = $null
                    }
                    # Identify preferable SKUs, based on user-level calculations
                    $userSKUs_preferable = $null
                    if ($AdvancedCheckups -and
                    $reportsRetrieved) {
                        $hashCalculator = [System.Security.Cryptography.MD5]::Create()
                        if ($hashedReports) {
                            $userName = ($hashCalculator.ComputeHash([Text.Encoding]::ASCII.GetBytes($user.userPrincipalName)) | ForEach-Object{'{0:X2}' -f $_}) -join ''
                        }
                        else {
                            $userName = $user.userPrincipalName
                        }
                        if ($appUsage.ContainsKey($userName) -or
                        $mailboxUsage.ContainsKey($userName) -or
                        $driveUsage.ContainsKey($userName)) {
                            if ($null -ne $userSKUAssignments) {
                                $userLicenseLastChangeDate =  ($userSKUAssignments | Sort-Object lastUpdatedDateTime -Descending | Select-Object -First 1).lastUpdatedDateTime
                            }
                            else {
                                $userLicenseLastChangeDate =  [datetime]::MinValue
                            }
                            if ($appUsage.ContainsKey($userName)) {
                                $userAppsUsedLastActivityDate = $appUsage[$userName]['LastActivityDate']
                                $userWindowsAppUsed = $appUsage[$userName]['WindowsApp']
                                $userMacAppUsed = $appUsage[$userName]['MacApp']
                                $userMobileAppUsed = $appUsage[$userName]['MobileApp']
                                $userWebAppUsed = $appUsage[$userName]['WebApp']
                            }
                            else {
                                $userAppsUsedLastActivityDate = [datetime]::MinValue
                                $userWindowsAppUsed = $false
                                $userMacAppUsed = $false
                                $userMobileAppUsed = $false
                                $userWebAppUsed = $false
                            }
                            if ($mailboxUsage.ContainsKey($userName)) {
                                $userMailboxLastActivityDate = $mailboxUsage[$userName]['LastActivityDate']
                                $userMailboxStorageUsedGB = $mailboxUsage[$userName]['StorageUsed']
                                $userMailboxHasArchive = $mailboxUsage[$userName]['HasArchive']
                            }
                            else {
                                $userMailboxLastActivityDate = [datetime]::MinValue
                                $userMailboxStorageUsedGB = 0
                                $userMailboxHasArchive = $false
                            }
                            if ($driveUsage.ContainsKey($userName)) {
                                $userOneDriveLastActivityDate = $driveUsage[$userName]['LastActivityDate']
                                $userOneDriveStorageUsedGB = $driveUsage[$userName]['StorageUsed']
                            }
                            else {
                                $userOneDriveLastActivityDate = [datetime]::MinValue
                                $userOneDriveStorageUsedGB = 0
                            }
                            foreach ($preferableSKU in $PreferableSKUs) {
                                if (($user.accountEnabled.ToString() -eq $preferableSKU.AccountEnabled -or $preferableSKU.AccountEnabled -eq 'Skip') -and
                                (($user.userType -eq 'Guest').ToString() -eq $preferableSKU.AccountGuest -or $preferableSKU.AccountGuest -eq 'Skip') -and
                                $user.createdDateTime -lt $preferableSKU.CreatedEarlierThan -and
                                $userAppsUsedLastActivityDate -lt $preferableSKU.LastActiveEarlierThan.Date -and
                                $userLicenseLastChangeDate -lt $preferableSKU.LastLicenseChangeEarlierThan -and
                                (($user.ownedDevices.Count -gt 0).ToString() -eq $preferableSKU.DeviceOwned -or $preferableSKU.DeviceOwned -eq 'Skip') -and
                                ($userWindowsAppUsed.ToString() -eq $preferableSKU.WindowsAppUsed -or $preferableSKU.WindowsAppUsed -eq 'Skip') -and
                                ($userMacAppUsed.ToString() -eq $preferableSKU.MacAppUsed -or $preferableSKU.MacAppUsed -eq 'Skip') -and
                                ($userMobileAppUsed.ToString() -eq $preferableSKU.MobileAppUsed -or $preferableSKU.MobileAppUsed -eq 'Skip') -and
                                ($userWebAppUsed.ToString() -eq $preferableSKU.WebAppUsed -or $preferableSKU.WebAppUsed -eq 'Skip') -and
                                $userMailboxLastActivityDate -lt $preferableSKU.LastActiveEarlierThan.Date -and
                                $userMailboxStorageUsedGB -lt $preferableSKU.MailboxGBUsedLessThan -and
                                ($userMailboxHasArchive.ToString() -eq $preferableSKU.MailboxHasArchive -or $preferableSKU.MailboxHasArchive -eq 'Skip') -and
                                $userOneDriveLastActivityDate -lt $preferableSKU.LastActiveEarlierThan.Date -and
                                $userOneDriveStorageUsedGB -lt $preferableSKU.OneDriveGBUsedLessThan) {
                                    if ((($InterchangeableSKUs -contains $preferableSKU.SKUID -and
                                    $userSKUs -notcontains $preferableSKU.SKUID) -or
                                    [guid]::Empty -eq $preferableSKU.SKUID) -and
                                    $userSKUs_interchangeable.Count -gt 0) {
                                        $userSKUs_preferable = $preferableSKU.SKUID
                                    }
                                    break
                                }
                            }
                        }
                    }
                    # Add results
                    if ($userSKUs_interchangeable.Count -gt 1) {
                        Write-Message "Found $($userSKUs_interchangeable.Count) interchangeable SKUs for user $($user.userPrincipalName)" -Type Verbose
                        $basicResults_interchangeable = $userSKUs_interchangeable
                    }
                    else {
                        $basicResults_interchangeable = [guid[]]::new(0)
                    }
                    if ($null -ne $userSKUs_optimizable) {
                        Write-Message "Found $(@($userSKUs_optimizable).Count) optimizable SKUs for user $($user.userPrincipalName)" -Type Verbose
                        $basicResults_optimizable = $userSKUs_optimizable
                    }
                    else {
                        $basicResults_optimizable = [guid[]]::new(0)
                    }
                    if ($null -ne $userSKUs_removable) {
                        Write-Message "Found $(@($userSKUs_removable).Count) removable SKUs for user $($user.userPrincipalName)" -Type Verbose
                        $basicResults_removable = $userSKUs_removable
                    }
                    else {
                        $basicResults_removable = [guid[]]::new(0)
                    }
                    if ($basicResults_interchangeable.Count -gt 0 -or
                    $basicResults_optimizable.Count -gt 0 -or
                    $basicResults_removable.Count -gt 0) {
                        Add-Result -BasicUserResult ([BasicUserResult]@{
                            'UserPrincipalName' = $user.userPrincipalName
                            'InterchangeableSKUIDs' = $basicResults_interchangeable
                            'OptimizableSKUIDs' = $basicResults_optimizable
                            'RemovableSKUIDs' = $basicResults_removable
                        })
                    }
                    if ($null -ne $userSKUs_preferable) {
                        Write-Message "Found preferable SKU for user $($user.userPrincipalName)" -Type Verbose
                        Add-Result -AdvancedUserResult ([AdvancedUserResult]@{
                            'UserPrincipalName' = $user.userPrincipalName
                            'PreferableSKUID' = $userSKUs_preferable
                            'ReplaceableSKUIDs' = $userSKUs_interchangeable
                        })
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
            $IntuneDevices = [System.Collections.Generic.List[guid]]::new()
            # 'Human' users based on parameters
            $URI = 'https://graph.microsoft.com/v1.0/users?$select=id&$filter={0}&top={1}&$count=true' -f (($humanUserAttributes.Keys | ForEach-Object{"$_ in ('$($humanUserAttributes[$_] -join ''',''')')"}) -join ' and '), $pageSize
            $humanUsers = [System.Collections.Generic.List[hashtable]]::new()
            try {
                while ($null -ne $URI) {
                    $data = Invoke-MgGraphRequest -Method GET -Uri $URI -Headers @{'ConsistencyLevel' = 'eventual'} -ErrorAction Stop
                    $humanUsers.AddRange([hashtable[]]($data.value))
                    $URI = $data['@odata.nextLink']
                }
                Write-Message "Found $($humanUsers.Count) human users" -Type Verbose
            }
            catch {
                Write-Message "Found 0 human users, property mismatch" -Type Error -Category InvalidArgument
            }
            if ($humanUsers.Count -gt 0) {
                $humanUsersHashSet = [System.Collections.Generic.HashSet[guid]]@($humanUsers.id)
                # Entra ID P1 based on groups using dynamic user membership
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
                        <#
                        if ($null -ne ($matchedUsers = Compare-Object $humanUsers.id (Get-AADGroupMember -GroupIDs $dynamicUserGroups.id) -ExcludeDifferent -IncludeEqual)) {
                            $AADP1Users.AddRange([guid[]]@($matchedUsers.InputObject))
                        }
                        #>
                        $tmpUsersHashSet = [System.Collections.Generic.HashSet[guid]](Get-AADGroupMember -GroupIDs $dynamicUserGroups.id)
                        $tmpUsersHashSet.IntersectWith($humanUsersHashSet)
                        if ($tmpUsersHashSet.Count -gt 0) {
                            $AADP1Users.AddRange([guid[]]@($tmpUsersHashSet))
                        }
                    }
                }
                Write-Message "Analyzed $dynamicGroupCount dynamic groups"
                # Entra ID P1 based on applications using group-based assignment
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
                            <#
                            if ($null -ne ($matchedUsers = Compare-Object $humanUsers.id (Get-AADGroupMember -GroupIDs $applicationGroups.principalId) -ExcludeDifferent -IncludeEqual)) {
                                $AADP1Users.AddRange([guid[]]@($matchedUsers.InputObject))
                            }
                            #>
                            $tmpUsersHashSet = [System.Collections.Generic.HashSet[guid]](Get-AADGroupMember -GroupIDs $applicationGroups.principalId)
                            $tmpUsersHashSet.IntersectWith($humanUsersHashSet)
                            if ($tmpUsersHashSet.Count -gt 0) {
                                $AADP1Users.AddRange([guid[]]@($tmpUsersHashSet))
                            }
                        }
                    }
                }
                Write-Message "Analyzed $applicationCount applications"
                # Entra ID P1/P2 based on users covered by Conditional Access
                $conditionalAccessPolicyCount = 0
                $URI = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=conditions&$filter=state eq ''enabled'''
                while ($null -ne $URI) {
                    # Retrieve Conditional Access policies
                    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                    $conditionalAccessPolicies = [hashtable[]]($data.value)
                    $conditionalAccessPolicyCount += $conditionalAccessPolicies.Count
                    $URI = $data['@odata.nextLink']
                    # Analyze Conditional Access policies
                    foreach ($conditionalAccessPolicy in $conditionalAccessPolicies) {
                        if ($conditionalAccessPolicy.conditions.users.includeUsers -notcontains 'None') {
                            if ($conditionalAccessPolicy.conditions.users.includeUsers -contains 'All') {
                                $users = [System.Collections.Generic.List[hashtable]]::new()
                                $URI = 'https://graph.microsoft.com/v1.0/users?$select=id&$top={0}' -f $pageSize
                                while ($null -ne $URI) {
                                    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                                    $users.AddRange([hashtable[]]($data.value))
                                    $URI = $data['@odata.nextLink']
                                }
                                $includeUsers = $users.id
                            }
                            elseif ($null -eq ($includeUsers = @($conditionalAccessPolicy.conditions.users.includeUsers | Where-Object{$_ -ne 'GuestsOrExternalUsers'}))) {
                                $includeUsers = @()
                            }
                            $excludeUsers = $conditionalAccessPolicy.conditions.users.excludeUsers
                            if ($conditionalAccessPolicy.conditions.users.includeGroups.Count -gt 0) {
                                $includeGroupUsers = Get-AADGroupMember -GroupIDs $conditionalAccessPolicy.conditions.users.includeGroups
                            }
                            else {
                                $includeGroupUsers = @()
                            }
                            if ($conditionalAccessPolicy.conditions.users.excludeGroups.Count -gt 0) {
                                $excludeGroupUsers = Get-AADGroupMember -GroupIDs $conditionalAccessPolicy.conditions.users.excludeGroups
                            }
                            else {
                                $excludeGroupUsers = @()
                            }
                            # Replace with 'ExceptWith'
                            <#
                            if ($null -ne ($conditionalAccessUsers = Compare-Object -ReferenceObject ([guid[]]$includeUsers + [guid[]]$includeGroupUsers) -DifferenceObject ([guid[]]$excludeUsers + [guid[]]$excludeGroupUsers) | Where-Object{$_.SideIndicator -eq '<='})) {
                                if ($null -ne ($matchedUsers = Compare-Object $humanUsers.id $conditionalAccessUsers.InputObject -ExcludeDifferent -IncludeEqual)) {
                                    if ($conditionalAccessPolicy.conditions.userRiskLevels.Count -gt 0 -or $conditionalAccessPolicy.conditions.signInRiskLevels.Count -gt 0) {
                                        $AADP2Users.AddRange([guid[]]@($matchedUsers.InputObject))
                                    }
                                    else {
                                        $AADP1Users.AddRange([guid[]]@($matchedUsers.InputObject))
                                    }
                                }
                            }
                            #>
                            $includeUsers_Complete = [System.Collections.Generic.HashSet[guid]]([guid[]]$includeUsers + [guid[]]$includeGroupUsers)
                            $excludeUsers_Complete = [System.Collections.Generic.HashSet[guid]]([guid[]]$excludeUsers + [guid[]]$excludeGroupUsers)
                            $includeUsers_Complete.ExceptWith($excludeUsers_Complete)
                            $includeUsers_Complete.IntersectWith($humanUsersHashSet)
                            if ($conditionalAccessPolicy.conditions.userRiskLevels.Count -gt 0 -or $conditionalAccessPolicy.conditions.signInRiskLevels.Count -gt 0) {
                                $AADP2Users.AddRange([guid[]]@($includeUsers_Complete))
                            }
                            else {
                                $AADP1Users.AddRange([guid[]]@($includeUsers_Complete))
                            }
                        }
                    }
                }
                Write-Message "Analyzed $conditionalAccessPolicyCount conditional access policies"
                # Entra ID P2 based on users eligible for Privileged Identity Management
                $roleAssignmentCount = 0
                $URI = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=principalId,scheduleInfo'
                while ($null -ne $URI) {
                    # Retrieve role assignments
                    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                    $roleAssignments = [hashtable[]]($data.value)
                    $roleAssignmentCount += $roleAssignments.Count
                    $URI = $data['@odata.nextLink']
                    # Analyze role assignments
                    if ($null -ne ($eligibleRoleAssignments = $roleAssignments | Where-Object{$_.scheduleInfo.startDateTime -le [datetime]::Today -and ($_.scheduleInfo.expiration.endDateTime -ge [datetime]::Today -or $_.scheduleInfo.expiration.type -eq 'noExpiration')})) {
                        <#
                        if ($null -ne ($matchedUsers = Compare-Object $humanUsers.id $eligibleRoleAssignments.principalId -ExcludeDifferent -IncludeEqual)) {
                            $AADP2Users.AddRange([guid[]]@($matchedUsers.InputObject))
                        }
                        #>
                        $tmpUsersHashSet = [System.Collections.Generic.HashSet[guid]]@($eligibleRoleAssignments.principalId)
                        $tmpUsersHashSet.IntersectWith($humanUsersHashSet)
                        if ($tmpUsersHashSet.Count -gt 0) {
                            $AADP2Users.AddRange([guid[]]@($tmpUsersHashSet))
                        }
                    }
                }
                Write-Message "Analyzed $roleAssignmentCount role assignments"
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
                Write-Message 'Succeeded to authenticate with Exchange Online' -Type Verbose
            }
            catch {
                $exchangeAuthentication = $false
                Write-Message -Message 'Failed to authenticate with Exchange Online' -Type Error -Category AuthenticationError
            }
            if ($exchangeAuthentication) {
                # Replace with 'IntersectWith'?
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
                        # Handle strict protection rule
                        if ($null -ne ($strictProtectionRule = Get-ATPProtectionPolicyRule -Identity 'Strict Preset Security Policy' -State Enabled -ErrorAction SilentlyContinue)) {
                            Write-Message 'ATP strict rule'
                            if (($recipients = Get-ATPRecipient -IncludedUsers $strictProtectionRule.SentTo -IncludedGroups $strictProtectionRule.SentToMemberOf -IncludedDomains $strictProtectionRule.RecipientDomainIs -ExcludedUsers $strictProtectionRule.ExceptIfSentTo -ExcludedGroups $strictProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $strictProtectionRule.ExceptIfRecipientDomainIs).Count -gt 0) {
                                $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                Write-Message "Found $($recipients.Count) affected/protected recipients"
                            }
                        }
                        # Handle standard protection rule
                        if ($null -ne ($standardProtectionRule = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -State Enabled -ErrorAction SilentlyContinue)) {
                            Write-Message 'ATP standard rule'
                            if (($recipients = Get-ATPRecipient -IncludedUsers $standardProtectionRule.SentTo -IncludedGroups $standardProtectionRule.SentToMemberOf -IncludedDomains $standardProtectionRule.RecipientDomainIs -ExcludedUsers $standardProtectionRule.ExceptIfSentTo -ExcludedGroups $standardProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $standardProtectionRule.ExceptIfRecipientDomainIs).Count -gt 0) {
                                $ATPUsers.AddRange([guid[]]@($recipients.ExternalDirectoryObjectId))
                                Write-Message "Found $($recipients.Count) affected/protected recipients"
                            }
                        }
                        # Handle custom protection rules
                        foreach ($customAntiPhishPolicy in Get-AntiPhishPolicy | Where-Object{$_.Identity -ne 'Office365 AntiPhish Default' -and $_.RecommendedPolicyType -notin @('Standard', 'Strict')}) {
                            if (($customAntiPhishRule = Get-AntiPhishRule | Where-Object{$_.AntiPhishPolicy -eq $customAntiPhishPolicy.Identity}).State -eq 'Enabled'){
                                Write-Message "ATP custom anti-phishing policy '$($customAntiPhishPolicy.Name)'"
                                if (($recipients = Get-ATPRecipient -IncludedUsers $customAntiPhishRule.SentTo -IncludedGroups $customAntiPhishRule.SentToMemberOf -IncludedDomains $customAntiPhishRule.RecipientDomainIs -ExcludedUsers $customAntiPhishRule.ExceptIfSentTo -ExcludedGroups $customAntiPhishRule.ExceptIfSentToMemberOf -ExcludedDomains $customAntiPhishRule.ExceptIfRecipientDomainIs).Count -gt 0) {
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
                                if (($recipients = Get-ATPRecipient -IncludedUsers $customSafeAttachmentRule.SentTo -IncludedGroups $customSafeAttachmentRule.SentToMemberOf -IncludedDomains $customSafeAttachmentRule.RecipientDomainIs -ExcludedUsers $customSafeAttachmentRule.ExceptIfSentTo -ExcludedGroups $customSafeAttachmentRule.ExceptIfSentToMemberOf -ExcludedDomains $customSafeAttachmentRule.ExceptIfRecipientDomainIs).Count -gt 0) {
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
                                if (($recipients = Get-ATPRecipient -IncludedUsers $customSafeLinksRule.SentTo -IncludedGroups $customSafeLinksRule.SentToMemberOf -IncludedDomains $customSafeLinksRule.RecipientDomainIs -ExcludedUsers $customSafeLinksRule.ExceptIfSentTo -ExcludedGroups $customSafeLinksRule.ExceptIfSentToMemberOf -ExcludedDomains $customSafeLinksRule.ExceptIfRecipientDomainIs).Count -gt 0) {
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
                        if (($recipients = Get-ATPRecipient -IncludedUsers $builtinProtectionRule.SentTo -IncludedGroups $builtinProtectionRule.SentToMemberOf -IncludedDomains $builtinProtectionRule.RecipientDomainIs -ExcludedUsers $builtinProtectionRule.ExceptIfSentTo -ExcludedGroups $builtinProtectionRule.ExceptIfSentToMemberOf -ExcludedDomains $builtinProtectionRule.ExceptIfRecipientDomainIs).Count -gt 0) {
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
            # Intune Device based on devices managed by Intune and assigned to unlicensed users
            $managedDeviceCount = 0
            # Retrieve Intune licensed users
            $intuneUsers = [System.Collections.Generic.List[hashtable]]::new()
            $URI = 'https://graph.microsoft.com/v1.0/users?$filter=assignedPlans/any(x:x/servicePlanId eq c1ec4a95-1f05-45b3-a911-aa3fa01094f5 and capabilityStatus eq ''Enabled'') or assignedPlans/any(x:x/servicePlanId eq 3e170737-c728-4eae-bbb9-3f3360f7184c and capabilityStatus eq ''Enabled'')&$select=id&top={0}&$count=true' -f $pageSize
            while ($null -ne $URI) {
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI -Headers @{'ConsistencyLevel' = 'eventual'}
                $intuneUsers.AddRange([hashtable[]]($data.value))
                $URI = $data['@odata.nextLink']
            }
            $URI = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,userId&$top={0}' -f $pageSize
            while ($null -ne $URI) {
                # Retrieve managed devices
                $data = Invoke-MgGraphRequest -Method GET -Uri $URI
                $managedDevices = [hashtable[]]($data.value)
                $managedDeviceCount += $managedDevices.Count
                $URI = $data['@odata.nextLink']
                # Analyze managed devices
                #TODO: Verify calculation for correctness based on license terms
                foreach ($managedDevice in $managedDevices) {
                    if ($managedDevice.userId -notin $intuneUsers.id) {
                        $IntuneDevices.Add($managedDevice.id)
                    }
                }
            }
            Write-Message "Analyzed $managedDeviceCount managed devices"
            # Add results
            if ($AADP1Users.Count -gt 0) {
                if ($null -ne ($AADP1SKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains '41781fb2-bc02-4b7c-bd55-b576c07bb09d'}))) {
                    $AADP1Licenses = ($AADP1SKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                }
                else {
                    $AADP1Licenses = 0
                }
                $neededCount = @($AADP1Users | Sort-Object -Unique).Count
                Write-Message "Found $neededCount needed, $AADP1Licenses enabled EIDP1 licenses"
                if ($AADP1Licenses -lt $neededCount) {
                    Add-Result -PlanName 'Entra ID Premium P1' -EnabledCount $AADP1Licenses -NeededCount $neededCount
                }
            }
            if ($AADP2Users.Count -gt 0) {
                if ($null -ne ($AADP2SKUs = @($organizationSKUs | Where-Object{@($_.servicePlans.servicePlanId) -contains 'eec0eb4f-6444-4f95-aba0-50c24d67f998'}))) {
                    $AADP2Licenses = ($AADP2SKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                }
                else {
                    $AADP2Licenses = 0
                }
                $neededCount = @($AADP2Users | Sort-Object -Unique).Count
                Write-Message "Found $neededCount needed, $AADP2Licenses enabled EIDP2 licenses"
                if ($AADP2Licenses -lt $neededCount) {
                    Add-Result -PlanName 'Entra ID Premium P2' -EnabledCount $AADP2Licenses -NeededCount $neededCount
                }
            }
            if ($ATPUsers.Count -gt 0) {
                $neededCount = @($ATPUsers | Sort-Object -Unique).Count
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
            if ($IntuneDevices.Count -gt 0) {
                if ($null -ne ($IntuneDeviceSKUs = @($organizationSKUs | Where-Object{$_.skuId -eq '2b317a4a-77a6-4188-9437-b68a77b4e2c6'}))) {
                    $IntuneDeviceLicenses = ($IntuneDeviceSKUs.prepaidUnits.enabled | Measure-Object -Sum).Sum
                }
                else {
                    $IntuneDeviceLicenses = 0
                }
                $neededCount = @($IntuneDevices | Sort-Object -Unique).Count
                Write-Message "Found $neededCount needed, $IntuneDeviceLicenses enabled Intune Device licenses"
                if ($IntuneDeviceLicenses -lt $neededCount) {
                    Add-Result -PlanName 'Intune Device' -EnabledCount $IntuneDeviceLicenses -NeededCount $neededCount
                }
            }
        }
        #endregion

        #region: Report
        if ($results.Keys.Count -gt 0) {
            $critical = $false
            $outputs = [System.Text.StringBuilder]::new()
            $null = $outputs.AppendLine('<style>
                                            table, th, td {
                                                border: none;
                                                border-collapse: collapse;
                                            }
                                            th, td {
                                                padding: 5px;
                                                vertical-align: top;
                                            }
                                            th {
                                                text-align: center;
                                            }
                                            td {
                                                text-align: left;
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
                                            .rule {
                                                border-left-style: solid;
                                            }
                                            </style>')
            # Output basic SKU results
            $null = $outputs.AppendLine('<p class=gray>Basic checkup - Products</p>')
            if ($results.ContainsKey('SKU_Basic')) {
                $null = $outputs.AppendLine(('<p>Please check license counts for the following product SKUs and <a href="{0}">reserve</a> additional licenses:</p>
                                                <p><table>
                                                <tr><th>License type</th>
                                                <th>Available count</th>
                                                <th>Minimum count</th>
                                                <th>Difference</th></tr>' -f
                                                $LicensingURL))
                foreach ($SKU in $results['SKU_Basic'].Keys) {
                    $differenceCount = $results['SKU_Basic'][$SKU]['availableCount'] - $results['SKU_Basic'][$SKU]['minimumCount']
                    $null = $outputs.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td>' -f
                                                    (Get-SKUName -SKUID $SKU),
                                                    $results['SKU_Basic'][$SKU]['availableCount'],
                                                    $results['SKU_Basic'][$SKU]['minimumCount']))
                    if ($results['SKU_Basic'][$SKU]['availableCount'] / $results['SKU_Basic'][$SKU]['minimumCount'] * 100 -ge $SKUWarningThreshold_basic) {
                        $null = $outputs.AppendLine("<td class=green>$differenceCount</td>")
                    }
                    elseif ($results['SKU_Basic'][$SKU]['availableCount'] / $results['SKU_Basic'][$SKU]['minimumCount'] * 100 -le $SKUCriticalThreshold_basic) {
                        $critical = $true
                        $null = $outputs.AppendLine("<td class=red>$differenceCount</td>")
                    }
                    else {
                        $null = $outputs.AppendLine("<td class=yellow>$differenceCount</td>")
                    }
                    $null = $outputs.AppendLine('</tr>')
                }
                $null = $outputs.AppendLine(('</table></p>
                                                <p>The following criteria were used during the checkup:<ul>
                                                <li>Check products with &gt;{0} total licenses</li>
                                                <li>Report normal products having both &lt;{1} licenses and &lt;{2}% of their total licenses available</li>
                                                <li>Report important products having both &lt;{3} licenses and &lt;{4}% of their total licenses available</li></ul></p>' -f
                                                $SKUIgnoreThreshold,
                                                $SKUTotalThreshold_normal,
                                                $SKUPercentageThreshold_normal,
                                                $SKUTotalThreshold_important,
                                                $SKUPercentageThreshold_important))
            }
            else {
                $null = $outputs.AppendLine('<p>Nothing to report</p>')
            }
            # Output advanced SKU results
            $null = $outputs.AppendLine('<p class=gray>Advanced checkup - Products</p>')
            if ($results.ContainsKey('SKU_Advanced')) {
                $null = $outputs.AppendLine(('<p>Please check license counts for the following product SKUs and <a href="{0}">reserve</a> additional licenses:</p>
                                                <p><table>
                                                <tr><th>License type</th>
                                                <th>Enabled count</th>
                                                <th>Needed count</th>
                                                <th>Difference</th></tr>' -f
                                                $LicensingURL))
                foreach ($plan in $results['SKU_Advanced'].Keys) {
                    $differenceCount = $results['SKU_Advanced'][$plan]['enabledCount'] - $results['SKU_Advanced'][$plan]['neededCount']
                    $null = $outputs.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td>' -f
                                                    $plan,
                                                    $results['SKU_Advanced'][$plan]['enabledCount'],
                                                    $results['SKU_Advanced'][$plan]['neededCount']))
                    if ($results['SKU_Advanced'][$plan]['enabledCount'] / $results['SKU_Advanced'][$plan]['neededCount'] * 100 -ge $SKUWarningThreshold_advanced) {
                        $null = $outputs.AppendLine("<td class=green>$differenceCount</td>")
                    }
                    elseif ($results['SKU_Advanced'][$plan]['enabledCount'] / $results['SKU_Advanced'][$plan]['neededCount'] * 100 -le $SKUCriticalThreshold_advanced) {
                        $critical = $true
                        $null = $outputs.AppendLine("<td class=red>$differenceCount</td>")
                    }
                    else {
                        $null = $outputs.AppendLine("<td class=yellow>$differenceCount</td>")
                    }
                    $null = $outputs.AppendLine('</tr>')
                }
                $null = $outputs.AppendLine('</table></p>
                                                <p>The following criteria were used during the checkup:<ul>
                                                <li>Check <em>Entra ID P1</em> based on groups using dynamic user membership</li>
                                                <li>Check <em>Entra ID P1</em> based on applications using group-based assignment</li>
                                                <li>Check <em>Entra ID P1/P2</em> based on users covered by Conditional Access</li>
                                                <li>Check <em>Entra ID P2</em> based on users eligible for Privileged Identity Management</li>
                                                <li>Check <em>Defender for Office 365 P1/P2</em> based on protected Exchange Online recipients</li>
                                                <li>Check <em>Intune Device</em> based on devices managed by Intune and used by unlicensed users</li></ul></p>')
            }
            else {
                $null = $outputs.AppendLine('<p>Nothing to report</p>')
            }
            # Output basic user results
            $null = $outputs.AppendLine('<p class=gray>Basic checkup - Users</p>')
            if ($results.ContainsKey('User_Basic')) {
                [decimal]$potentialSavings = 0
                $null = $outputs.AppendLine('<p>Please check license assignments for the following user accounts and mitigate impact:</p>
                                                <p><table>
                                                <tr><th>Account</th>
                                                <th>Interchangeable</th>
                                                <th>Optimizable</th>
                                                <th>Removable</th></tr>')
                foreach ($user in $results['User_Basic'] | Sort-Object UserPrincipalName) {
                    if ($null -ne $SKUPrices) {
                        if ($null -ne ($interchangeableSKUPrices = $SKUPrices | Where-Object{$_.SKUID -in $user.InterchangeableSKUIDs} | Sort-Object Price | Select-Object -Skip 1)) {
                            $potentialSavings += ($interchangeableSKUPrices.Price |
                                                Measure-Object -Sum).Sum
                        }
                        if ($null -ne ($optimizableSKUPrices = $SKUPrices | Where-Object{$_.SKUID -in $user.OptimizableSKUIDs})) {
                            $potentialSavings += ($optimizableSKUPrices.Price |
                                                Measure-Object -Sum).Sum
                        }
                        if ($null -ne ($removableSKUPrices = $SKUPrices | Where-Object{$_.SKUID -in $user.RemovableSKUIDs})) {
                            $potentialSavings += ($removableSKUPrices.Price |
                                                Measure-Object -Sum).Sum
                        }
                    }
                    $null = $outputs.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
                                                    $user.UserPrincipalName,
                                                    (($user.InterchangeableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_} | Sort-Object) -join '<br>'),
                                                    (($user.OptimizableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_} | Sort-Object) -join '<br>'),
                                                    (($user.RemovableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_} | Sort-Object) -join '<br>')))
                }
                $null = $outputs.AppendLine('</table></p>')
                if ($potentialSavings -gt 0) {
                    $null = $outputs.AppendLine(('<p>Potential savings when mitigating license assignment impact: {0:C}</p>' -f
                                                    $potentialSavings))
                }
                $null = $outputs.AppendLine('<p>The following criteria were used during the checkup:<ul>
                                                <li>Check accounts with any number of assigned licenses</li>
                                                <li>Report theoretically exclusive licenses as <strong>interchangeable</strong>, based on specified SKUs</li>
                                                <li>Report practically inclusive licenses as <strong>optimizable</strong>, based on available SKU features</li>
                                                <li>Report actually inclusive licenses as <strong>removable</strong>, based on enabled SKU features</li></ul></p>')
            }
            else {
                $null = $outputs.AppendLine('<p>Nothing to report</p>')
            }
            # Output advanced user results
            $null = $outputs.AppendLine('<p class=gray>Advanced checkup - Users</p>')
            if ($results.ContainsKey('User_Advanced')) {
                [decimal]$potentialSavings = 0
                $null = $outputs.AppendLine('<p>Please check license assignments for the following user accounts and mitigate impact:</p>
                                                <p><table>
                                                <tr><th>Account</th>
                                                <th>Preferable</th>
                                                <th>Replaceable</th></tr>')
                foreach ($user in $results['User_Advanced'] | Sort-Object UserPrincipalName) {
                    if ($null -ne $SKUPrices) {
                        if ($null -ne ($replaceableSKUPrices = $SKUPrices | Where-Object{$_.SKUID -in $user.ReplaceableSKUIDs})) {
                            if ($null -ne ($preferableSKUPrice = $SKUPrices | Where-Object{$_.SKUID -eq $user.PreferableSKUID})) {
                                $potentialSavings += ($replaceableSKUPrices.Price |
                                                    Measure-Object -Sum).Sum -
                                                    $preferableSKUPrice.Price
                            }
                            else {
                                $potentialSavings += ($replaceableSKUPrices.Price |
                                                    Measure-Object -Sum).Sum
                            }
                        }
                    }
                    $null = $outputs.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f
                                                    $user.UserPrincipalName,
                                                    (Get-SKUName -SKUID $user.PreferableSKUID),
                                                    (($user.ReplaceableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_} | Sort-Object) -join '<br>')))
                }
                $null = $outputs.AppendLine('</table></p>')
                if ($potentialSavings -gt 0) {
                    $null = $outputs.AppendLine(('<p>Potential savings when mitigating license assignment impact: {0:C}</p>' -f
                                                    $potentialSavings))
                }
                $null = $outputs.AppendLine('<p>The following criteria were used during the checkup:</p>
                                                <p><table>
                                                <tr><th rowspan=2>Priority</th>
                                                <th rowspan=2 class=rule>License</th>
                                                <th colspan=5 class=rule>Account</th>
                                                <th rowspan=2 class=rule>Device</th>
                                                <th colspan=1 class=rule>OneDrive</th>
                                                <th colspan=2 class=rule>Mailbox</th>
                                                <th colspan=4 class=rule>Apps</th></tr>
                                                <tr><th class=rule>Enabled</th>
                                                <th>Guest</th>
                                                <th>Created</th>
                                                <th>Active</th>
                                                <th>Licensed</th>
                                                <th class=rule>Storage</th>
                                                <th class=rule>Storage</th>
                                                <th>Archive</th>
                                                <th class=rule>Windows</th>
                                                <th>Mac</th>
                                                <th>Mobile</th>
                                                <th>Web</th></tr>')
                for ($i = 0; $i -lt $PreferableSKUs.Count; $i++) {
                    $preferableSKU = $PreferableSKUs[$i]
                    if ($preferableSKU.AccountEnabled -ne [SKURule]::AccountEnabledDefault()) {
                        $ruleSetting_accountEnabled = $preferableSKU.AccountEnabled.ToUpper()
                    }
                    else {
                        $ruleSetting_accountEnabled = '-'
                    }
                    if ($preferableSKU.AccountGuest -ne [SKURule]::AccountGuestDefault()) {
                        $ruleSetting_accountGuest = $preferableSKU.AccountGuest.ToUpper()
                    }
                    else {
                        $ruleSetting_accountGuest = '-'
                    }
                    if ($preferableSKU.CreatedEarlierThan -ne [SKURule]::CreatedEarlierThanDefault()) {
                        $ruleSetting_createdEarlierThan = $preferableSKU.CreatedEarlierThan
                    }
                    else {
                        $ruleSetting_createdEarlierThan = '-'
                    }
                    if ($preferableSKU.LastActiveEarlierThan -ne [SKURule]::LastActiveEarlierThanDefault()) {
                        $ruleSetting_lastActiveEarlierThan = $preferableSKU.LastActiveEarlierThan
                    }
                    else {
                        $ruleSetting_lastActiveEarlierThan = '-'
                    }
                    if ($preferableSKU.LastLicenseChangeEarlierThan -ne [SKURule]::LastLicenseChangeEarlierThanDefault()) {
                        $ruleSetting_lastLicenseChangeEarlierThan = $preferableSKU.LastLicenseChangeEarlierThan
                    }
                    else {
                        $ruleSetting_lastLicenseChangeEarlierThan = '-'
                    }
                    if ($preferableSKU.DeviceOwned -ne [SKURule]::DeviceOwnedDefault()) {
                        $ruleSetting_deviceOwned = $preferableSKU.DeviceOwned
                    }
                    else {
                        $ruleSetting_deviceOwned = '-'
                    }
                    if ($preferableSKU.OneDriveGBUsedLessThan -ne [SKURule]::OneDriveGBUsedLessThanDefault()) {
                        $ruleSetting_oneDriveGBUsedLessThan = $preferableSKU.OneDriveGBUsedLessThan
                    }
                    else {
                        $ruleSetting_oneDriveGBUsedLessThan = '-'
                    }
                    if ($preferableSKU.MailboxGBUsedLessThan -ne [SKURule]::MailboxGBUsedLessThanDefault()) {
                        $ruleSetting_mailboxGBUsedLessThan = $preferableSKU.MailboxGBUsedLessThan
                    }
                    else {
                        $ruleSetting_mailboxGBUsedLessThan = '-'
                    }
                    if ($preferableSKU.MailboxHasArchive -ne [SKURule]::MailboxHasArchiveDefault()) {
                        $ruleSetting_mailboxHasArchive = $preferableSKU.MailboxHasArchive.ToUpper()
                    }
                    else {
                        $ruleSetting_mailboxHasArchive = '-'
                    }
                    if ($preferableSKU.WindowsAppUsed -ne [SKURule]::WindowsAppUsedDefault()) {
                        $ruleSetting_windowsAppUsed = $preferableSKU.WindowsAppUsed.ToUpper()
                    }
                    else {
                        $ruleSetting_windowsAppUsed = '-'
                    }
                    if ($preferableSKU.MacAppUsed -ne [SKURule]::MacAppUsedDefault()) {
                        $ruleSetting_macAppUsed = $preferableSKU.MacAppUsed.ToUpper()
                    }
                    else {
                        $ruleSetting_macAppUsed = '-'
                    }
                    if ($preferableSKU.MobileAppUsed -ne [SKURule]::MobileAppUsedDefault()) {
                        $ruleSetting_mobileAppUsed = $preferableSKU.MobileAppUsed.ToUpper()
                    }
                    else {
                        $ruleSetting_mobileAppUsed = '-'
                    }
                    if ($preferableSKU.WebAppUsed -ne [SKURule]::WebAppUsedDefault()) {
                        $ruleSetting_webAppUsed = $preferableSKU.WebAppUsed.ToUpper()
                    }
                    else {
                        $ruleSetting_webAppUsed = '-'
                    }
                    $null = $outputs.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4:&l\t\;yyyy&#8209\;MM&#8209\;dd}</td><td>{5:&l\t\;yyyy&#8209\;MM&#8209\;dd}</td><td>{6:&l\t\;yyyy&#8209\;MM&#8209\;dd}</td><td>{7}</td><td>{8:&lt\;0.#&nbsp\;GB}</td><td>{9:&lt\;0.#&nbsp\;GB}</td><td>{10}</td><td>{11}</td><td>{12}</td><td>{13}</td><td>{14}</td></tr>' -f
                                                    ($i + 1),
                                                    (Get-SKUName -SKUID $preferableSKU.SKUID),
                                                    $ruleSetting_accountEnabled,
                                                    $ruleSetting_accountGuest,
                                                    $ruleSetting_createdEarlierThan,
                                                    $ruleSetting_lastActiveEarlierThan,
                                                    $ruleSetting_lastLicenseChangeEarlierThan,
                                                    $ruleSetting_deviceOwned,
                                                    $ruleSetting_oneDriveGBUsedLessThan,
                                                    $ruleSetting_mailboxGBUsedLessThan,
                                                    $ruleSetting_mailboxHasArchive,
                                                    $ruleSetting_windowsAppUsed,
                                                    $ruleSetting_macAppUsed,
                                                    $ruleSetting_mobileAppUsed,
                                                    $ruleSetting_webAppUsed))
                }
                $null = $outputs.AppendLine('</table></p>')
            }
            else {
                $null = $outputs.AppendLine('<p>Nothing to report</p>')
            }
            # Configure and send email
            $email = @{
                'message' = @{
                    'subject' = 'Entra ID licenses need attention'
                    'importance' = 'normal'
                    'body' = @{
                        'contentType' = 'HTML'
                        'content' = $outputs.ToString()
                    }
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
                $email['message']['subject'] = 'Entra ID licenses need urgent attention'
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
            if ($null -ne $AttachmentFormat) {
                $email['message'].Add('attachments', [System.Collections.Generic.List[hashtable]]::new())
                switch -Wildcard ($AttachmentFormat) {
                    '*CSV' {
                        if ($results.ContainsKey('User_Basic')) {
                            switch ($AttachmentFormat) {
                                'CSV' {
                                    $csvOutput = $results['User_Basic'] |
                                        Select-Object UserPrincipalName,
                                            @{Name = 'InterchangeableSKUIDs'; Expression = {$_.InterchangeableSKUIDs -join ', '}},
                                            @{Name = 'OptimizableSKUIDs'; Expression = {$_.OptimizableSKUIDs -join ', '}},
                                            @{Name = 'RemovableSKUIDs'; Expression = {$_.RemovableSKUIDs -join ', '}} |
                                        ConvertTo-Csv -NoTypeInformation -Delimiter ';'
                                }
                                'TranslatedCSV' {
                                    $csvOutput = $results['User_Basic'] |
                                        Select-Object UserPrincipalName,
                                            @{Name = 'InterchangeableSKUIDs'; Expression = {($_.InterchangeableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_}) -join ', '}},
                                            @{Name = 'OptimizableSKUIDs'; Expression = {($_.OptimizableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_}) -join ', '}},
                                            @{Name = 'RemovableSKUIDs'; Expression = {($_.RemovableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_}) -join ', '}} |
                                        ConvertTo-Csv -NoTypeInformation -Delimiter ';'
                                }
                            }
                            $email['message']['attachments'].Add(@{
                                '@odata.type' = "#microsoft.graph.fileAttachment"
                                'name' = 'basic_results.csv'
                                'contentType' = 'text/csv'
                                'contentBytes' = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($csvOutput -join [System.Environment]::NewLine))
                            })
                        }
                        if ($results.ContainsKey('User_Advanced')) {
                            switch ($AttachmentFormat) {
                                'CSV' {
                                    $csvOutput = $results['User_Advanced'] |
                                        Select-Object UserPrincipalName,
                                            PreferableSKUID,
                                            @{Name = 'ReplaceableSKUIDs'; Expression = {$_.ReplaceableSKUIDs -join ', '}} |
                                        ConvertTo-Csv -NoTypeInformation -Delimiter ';'
                                }
                                'TranslatedCSV' {
                                    $csvOutput = $results['User_Advanced'] |
                                        Select-Object UserPrincipalName,
                                            @{Name = 'PreferableSKUID'; Expression = {Get-SKUName -SKUID $_.PreferableSKUID}},
                                            @{Name = 'ReplaceableSKUIDs'; Expression = {($_.ReplaceableSKUIDs | ForEach-Object{Get-SKUName -SKUID $_}) -join ', '}} |
                                        ConvertTo-Csv -NoTypeInformation -Delimiter ';'
                                }
                            }
                            $email['message']['attachments'].Add(@{
                                '@odata.type' = "#microsoft.graph.fileAttachment"
                                'name' = 'advanced_results.csv'
                                'contentType' = 'text/csv'
                                'contentBytes' = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($csvOutput -join [System.Environment]::NewLine))
                            })
                        }
                    }
                    'JSON' {
                        $jsonOutput = @{
                            'basic_results' = $results['User_Basic']
                            'advanced_results' = $results['User_Advanced']
                        } | ConvertTo-Json
                        $email['message']['attachments'].Add(@{
                            '@odata.type' = "#microsoft.graph.fileAttachment"
                            'name' = 'results.json'
                            'contentType' = 'application/json'
                            'contentBytes' = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($jsonOutput))
                        })
                    }
                }
            }
            Invoke-MgGraphRequest -Method POST -Uri ('https://graph.microsoft.com/v1.0/users/{0}/sendMail' -f $SenderAddress) -Body $email -ContentType 'application/json'
        }
        #endregion

        $null = Disconnect-MgGraph
    }
}