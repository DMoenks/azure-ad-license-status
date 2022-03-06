[OutputType([string])]
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
        [string]$emailSender,
        [Parameter(Mandatory=$true)]
        [string[]]$emailNormalRecipients,
        [string[]]$emailCriticalRecipients,
        [int]$licenseTestThreshold = 10,
        [int]$licensePercentageThreshold = 5,
        [int]$licenseTotalThreshold = 50,
        [int]$warningPercentageThreshold = 80,
        [int]$criticalPercentageThreshold = 20)

#region: Process configuration
$skuTranslate = @{'AAD_PREMIUM' = 'AzureActvDrctryPremP1';
                    'AAD_PREMIUM_P2' = 'AzureActvDrctryPremP2';
                    'ADALLOM_STANDALONE' = 'CloudAppSec';
                    'ATA' = 'AzureATPforUsrs';
                    'DESKLESSPACK' = 'O365F3';
                    'EMS' = 'EntMobandSecE3Full';
                    'ENTERPRISEPACK' = 'O365E3';
                    'ENTERPRISEPREMIUM' = 'O365E5';
                    'EQUIVIO_ANALYTICS' = 'Office 365 Advanced Compliance';
                    'IDENTITY_THREAT_PROTECTION' = 'M365E5Security';
                    'INFOPROTECTION_P2' = 'AzureInfoProtPremP2';
                    'INFORMATION_PROTECTION_COMPLIANCE' = 'M365E5Compliance';
                    'INTUNE_A_D' = 'Intune Device';
                    'INTUNE_A_VL' = 'IntunUSL';
                    'MCOEV' = 'Phone Sys';
                    'MCOMEETADV' = 'Audio Conf';
                    'POWER_BI_PRO' = 'PwrBIPro';
                    'PROJECTPREMIUM' = 'ProjectPlan5';
                    'PROJECTPROFESSIONAL' = 'ProjectPlan3';
                    'RIGHTSMANAGEMENT' = 'AzureInfoProtPremP1';
                    'SPE_E3' = 'M365E3';
                    'STANDARDPACK' = 'O365E1';
                    'THREAT_INTELLIGENCE' = 'AzureInfoProtPremP2';
                    'VISIOCLIENT' = 'VisioPlan2';
                    'VISIOONLINE_PLAN1' = 'VisioPlan1'}
#endregion

#region: HTML configuration
$tableHeaderLicenses = @"
<p>
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
<table>
<tr>
<th>License type</th>
<th>Available count</th>
<th>Minimum count</th>
<th>Difference</th>
</tr>
"@
$tableHeaderUsers = @"
<p>
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
</style>
<table>
<tr>
<th>Account</th>
<th>Interchangeable</th>
<th>Removable</th>
</tr>
"@
$tableFooter = @"
</table>
</p>
"@
#endregion

#region: Establish connections
# Connect to Azure
Connect-AzAccount -Identity -Subscription $subscriptionID | Out-Null
# Get certificate from Azure
$azCert = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $certificateName
$azCertSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $azCert.Name -AsPlainText
$azCertSecretBytes = [Convert]::FromBase64String($azCertSecret)
$x509Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($azCertSecretBytes)
# Connect to Microsoft Graph
Connect-MgGraph -Certificate $x509Cert -TenantId $directoryID -ClientId $applicationID | Out-Null
#endregion

#region: SKUs
# Get SKUs
$SKUs = [System.Collections.Generic.List[hashtable]]::new()
$URI = 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,servicePlans'
while ($null -ne $URI)
{
    $data = Invoke-MgGraphRequest -Method GET -Uri $URI
    $SKUs.AddRange([hashtable[]]($data.value))
    $URI = $data['@odata.nextLink']
}
# Calculate SKU usage
$resultsSKU = @{}
foreach ($SKU in $SKUs | Where-Object{$_.prepaidUnits.enabled -gt $licenseTestThreshold} | Sort-Object skuPartNumber)
{
    $availableCount = $SKU.prepaidUnits.enabled - $SKU.consumedUnits
    $totalCount = $SKU.prepaidUnits.enabled
    $minimumCount = (@([System.Math]::Ceiling($totalCount * $licensePercentageThreshold / 100), $licenseTotalThreshold) | Measure-Object -Minimum).Minimum
    if ($availableCount -lt $minimumCount)
    {
        $resultsSKU.Add($SKU.skuPartNumber, @{})
        $resultsSKU[$SKU.skuPartNumber].Add('availableCount', $availableCount)
        $resultsSKU[$SKU.skuPartNumber].Add('minimumCount', $minimumCount)
        $resultsSKU[$SKU.skuPartNumber].Add('differenceCount', ($availableCount - $minimumCount))
    }
}
# Configure theoretically interchangeable SKUs
$interchangeableSKUs_fixed = @('DESKLESSPACK',
                                'STANDARDPACK',
                                'ENTERPRISEPACK',
                                'ENTERPRISEPREMIUM',
                                'SPE_F1',
                                'SPE_E3',
                                'SPE_E5')
# Calculate practically interchangeable SKUs
$interchangeableSKUs_calculated_replacedBy = @{}
$interchangeableSKUs_calculated_replaces = @{}
foreach ($referenceSKU in $SKUs)
{
    foreach ($differenceSKU in $SKUs | Where-Object{$_.skuId -ne $referenceSKU.skuId})
    {
        if ($null -ne ($referenceServicePlans = $referenceSKU.servicePlans | Where-Object{$_.appliesTo -eq 'User'}) -and $null -ne ($differenceServicePlans = $differenceSKU.servicePlans | Where-Object{$_.appliesTo -eq 'User'}))
        {
            if ($null -ne ($comparisonSKU = Compare-Object $referenceServicePlans.servicePlanId $differenceServicePlans.servicePlanId -IncludeEqual) `
                -and ($comparisonSKU.SideIndicator | Select-Object -Unique) -contains '==' `
                -and ($comparisonSKU.SideIndicator | Select-Object -Unique) -notcontains '=>')
            {
                if (-not $interchangeableSKUs_calculated_replacedBy.ContainsKey($differenceSKU.skuPartNumber))
                {
                    $interchangeableSKUs_calculated_replacedBy.Add($differenceSKU.skuPartNumber, [System.Collections.Generic.List[string]]::new())
                }
                $interchangeableSKUs_calculated_replacedBy[$differenceSKU.skuPartNumber].Add($referenceSKU.skuPartNumber)
                if (-not $interchangeableSKUs_calculated_replaces.ContainsKey($referenceSKU.skuPartNumber))
                {
                    $interchangeableSKUs_calculated_replaces.Add($referenceSKU.skuPartNumber, [System.Collections.Generic.List[string]]::new())
                }
                $interchangeableSKUs_calculated_replaces[$referenceSKU.skuPartNumber].Add($differenceSKU.skuPartNumber)
            }
        }
    }
}
#endregion

#region: Users
# Get users
$users = [System.Collections.Generic.List[hashtable]]::new()
$URI = 'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,assignedLicenses'
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
    if ($user.assignedLicenses.count -gt 0)
    {
        $userSKUs = $SKUs | Where-Object{$_.skuId -in $user.assignedLicenses.skuId}
        if ($null -ne ($comparisonReplaceable = $userSKUs.skuPartNumber | Where-Object{$_ -in $interchangeableSKUs_calculated_replacedBy.Keys} | ForEach-Object{$interchangeableSKUs_calculated_replacedBy[$_]}))
        {
            $comparisonRemovable = Compare-Object -ReferenceObject $userSKUs.skuPartNumber -DifferenceObject $comparisonReplaceable -ExcludeDifferent -IncludeEqual | ForEach-Object{$interchangeableSKUs_calculated_replaces[$_.InputObject]} | Where-Object{$_ -in $userSKUs.skuPartNumber} | Select-Object -Unique
        }
        $comparisonInterchangeable = (Compare-Object $userSKUs.skuPartNumber $interchangeableSKUs_fixed -ExcludeDifferent -IncludeEqual).InputObject
        if ($null -ne $comparisonRemovable -or $comparisonInterchangeable.Count -gt 1)
        {
            $resultsUsers.Add($user.userPrincipalName, @{})
            if ($null -ne $comparisonRemovable)
            {
                $resultsUsers[$user.userPrincipalName].Add('Removable', $comparisonRemovable)
            }
            if ($comparisonInterchangeable.Count -gt 1)
            {
                $resultsUsers[$user.userPrincipalName].Add('Interchangeable', $comparisonInterchangeable)
            }
        }
    }
}
#endregion

#region: Report
# Report SKUs
if ($resultsSKU.Keys.Count -gt 0)
{
    $critical = $false
    $output = [System.Text.StringBuilder]::new()
    $output.AppendLine('<p>Please check license counts for the following products and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p>') | Out-Null
    $output.AppendLine($tableHeaderLicenses) | Out-Null
    foreach ($SKU in $resultsSKU.Keys)
    {
        $output.AppendLine('<tr>') | Out-Null
        $output.AppendLine("<td>$($skuTranslate[$SKU])</td>") | Out-Null
        $output.AppendLine("<td>$($resultsSKU[$SKU]['availableCount'])</td>") | Out-Null
        $output.AppendLine("<td>$($resultsSKU[$SKU]['minimumCount'])</td>") | Out-Null
        if ($resultsSKU[$SKU]['availableCount'] / $resultsSKU[$SKU]['minimumCount'] * 100 -ge $warningPercentageThreshold)
        {
            $output.AppendLine("<td class=green>$($resultsSKU[$SKU]['differenceCount'])</td>") | Out-Null
        }
        elseif ($resultsSKU[$SKU]['availableCount'] / $resultsSKU[$SKU]['minimumCount'] * 100 -le $criticalPercentageThreshold)
        {
            $critical = $true
            $output.AppendLine("<td class=red>$($resultsSKU[$SKU]['differenceCount'])</td>") | Out-Null
        }
        else
        {
            $output.AppendLine("<td class=yellow>$($resultsSKU[$SKU]['differenceCount'])</td>") | Out-Null
        }
        $output.AppendLine('</tr>') | Out-Null
    }
    $output.AppendLine($tableFooter) | Out-Null
    $output.AppendLine("<p>The following criteria were used during the checkup:<ul><li>Check products with >$licenseTestThreshold total licenses</li><li>Report products having <$licenseTotalThreshold licenses and <$licensePercentageThreshold% of their total licenses available</li></ul></p>") | Out-Null
    # Check accounts with issues
    if ($resultsUsers.Keys.Count -gt 0)
    {
        $output.AppendLine('<p>In addition, please check the following accounts having overlapping licenses assigned:</p>') | Out-Null
        $output.AppendLine($tableHeaderUsers) | Out-Null
        foreach ($user in $resultsUsers.Keys | Sort-Object)
        {
            $output.AppendLine('<tr>') | Out-Null
            $output.AppendLine("<td>$user</td>") | Out-Null
            $output.AppendLine("<td>$(($resultsUsers[$user]['Interchangeable'] | Sort-Object) -join '<br>')</td>") | Out-Null
            $output.AppendLine("<td>$(($resultsUsers[$user]['Removable'] | Sort-Object) -join '<br>')</td>") | Out-Null
            $output.AppendLine('</tr>') | Out-Null
        }
        $output.AppendLine($tableFooter) | Out-Null
        $output.AppendLine("<p>The following criteria were used during the checkup:<ul><li>Check accounts with any number of assigned licenses</li><li>Report simultaneously assigned but mutually exclusive licenses/license packages as <strong>interchangeable</strong>, an example would be Office 365 E1 and Office 365 E3</li><li>Report licenses/license packages included in simultaneously assigned license packages as <strong>removeable</strong>, an example would be Power BI Pro and Office 365 E5</li></ul></p>") | Out-Null
    }
    # Configure basic email settings
    $email = @{
                'message' = @{
                        'subject' = 'License counts below specified thresholds';
                        'importance' = 'normal';
                        'body' = @{
                            'contentType' = 'HTML';
                            'content' = $output.ToString()
                        };
                    }
                }
    # Add normal email recipients
    $email['message'].Add('toRecipients', [System.Collections.Generic.List[hashtable]]::new())
    foreach ($recipient in $emailNormalRecipients)
    {
        $email['message']['toRecipients'].Add(@{
                                                    'emailAddress' = @{
                                                        'address' = $recipient
                                                    }
                                                })
    }
    # Check criticality
    if ($critical)
    {
        # Replace subject and importance
        $email['message']['subject'] = 'License counts far below specified thresholds'
        $email['message']['importance'] = 'high'
        # Add critical email recipients
        if ($null -ne $emailCriticalRecipients)
        {
            $email['message'].Add('ccRecipients', [System.Collections.Generic.List[hashtable]]::new())
            foreach ($recipient in $emailCriticalRecipients)
            {
                $email['message']['ccRecipients'].Add(@{
                                                            'emailAddress' = @{
                                                                'address' = $recipient
                                                            }
                                                        })
            }
        }
    }
    # Initiate email delivery
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0//users/$emailSender/sendMail" -Body $email -ContentType 'application/json'
}
#endregion
