---
layout: default
permalink: /examples
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Usage](/azure-ad-license-status/usage) \| [6 Examples](/azure-ad-license-status/examples)

# 6 Examples

## 6.1 Example calls

### 6.1.1 Basic example with default settings

Prepares a status report with default values by using only necessary parameters for authentication and report delivery

```powershell
$directoryID = '00000000-0000-0000-0000-000000000000'
$applicationID = '00000000-0000-0000-0000-000000000000'
$certificateThumbprint = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
$senderAddress = 'sender@example.com'
$recipientAddresses_normal = @(
    'recipient_1@example.com'
    'recipient_2@example.com'
)

Get-AzureADLicenseStatus -DirectoryID $directoryID -ApplicationID $applicationID -CertificateThumbprint $certificateThumbprint -SenderAddress $senderAddress -RecipientAddresses_normal $recipientAddresses_normal
```

### 6.1.2 Basic example with modified thresholds

Prepares a status report with customized thresholds for larger organizations and additional recipients for when license counts reach critical levels

```powershell
$directoryID = '00000000-0000-0000-0000-000000000000'
$applicationID = '00000000-0000-0000-0000-000000000000'
$certificateThumbprint = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
$senderAddress = 'sender@example.com'
$recipientAddresses_normal = @(
    'recipient_1@example.com'
    'recipient_2@example.com'
)
$recipientAddresses_critical = @(
    'recipient_3@example.com'
    'recipient_4@example.com'
)
$skuPercentageThreshold_normal = 1
$skuTotalThreshold_normal = 100
$skuPercentageThreshold_important = 1
$skuTotalThreshold_important = 500

Get-AzureADLicenseStatus -DirectoryID $directoryID -ApplicationID $applicationID -CertificateThumbprint $certificateThumbprint -SenderAddress $senderAddress -RecipientAddresses_normal $recipientAddresses_normal -RecipientAddresses_critical $recipientAddresses_critical -SKUPercentageThreshold_normal $skuPercentageThreshold_normal -SKUTotalThreshold_normal $skuTotalThreshold_normal -SKUPercentageThreshold_important $skuPercentageThreshold_important -SKUTotalThreshold_important $skuTotalThreshold_important
```

### 6.1.3 Advanced example

Prepares a status report by using an Azure certificate for automation purposes, specifying both important and interchangeable SKUs and activating advanced checkups

```powershell
$directoryID = '00000000-0000-0000-0000-000000000000'
$applicationID = '00000000-0000-0000-0000-000000000000'
$subscriptionID = '00000000-0000-0000-0000-000000000000'
$keyVaultName = 'MyKeyVault'
$certificateName = 'MyCertificate'
$senderAddress = 'sender@example.com'
$recipientAddresses_normal = @(
    'recipient_1@example.com'
    'recipient_2@example.com'
)
$recipientAddresses_critical = @(
    'recipient_3@example.com'
    'recipient_4@example.com'
)
$skuPercentageThreshold_normal = 1
$skuTotalThreshold_normal = 100
$skuPercentageThreshold_important = 1
$skuTotalThreshold_important = 500
$importantSKUs = @(
    '18181a46-0d4e-45cd-891e-60aabd171b4e'
    '6fd2c87f-b296-42f0-b197-1e91e994b900'
)
$interchangeableSKUs = @(
    '4b585984-651b-448a-9e53-3b10f069cf7f'
    '18181a46-0d4e-45cd-891e-60aabd171b4e'
    '6fd2c87f-b296-42f0-b197-1e91e994b900'
    'c7df2760-2c81-4ef7-b578-5b5392b571df'
)

Get-AzureADLicenseStatus -DirectoryID $directoryID -ApplicationID $applicationID -SubscriptionID $subscriptionID -KeyVaultName $keyVaultName -CertificateName $certificateName -SenderAddress $senderAddress -RecipientAddresses_normal $recipientAddresses_normal -RecipientAddresses_critical $recipientAddresses_critical -SKUPercentageThreshold_normal $skuPercentageThreshold_normal -SKUTotalThreshold_normal $skuTotalThreshold_normal -SKUPercentageThreshold_important $skuPercentageThreshold_important -SKUTotalThreshold_important $skuTotalThreshold_important -ImportantSKUs $importantSKUs -InterchangeableSKUs $interchangeableSKUs -AdvancedCheckups
```

### 6.1.4 Complete example

Prepares a status report by using an Azure certificate for automation purposes, specifying important, interchangeable and preferable SKUs with their prices and activating advanced checkups

```powershell
$directoryID = '00000000-0000-0000-0000-000000000000'
$applicationID = '00000000-0000-0000-0000-000000000000'
$subscriptionID = '00000000-0000-0000-0000-000000000000'
$keyVaultName = 'MyKeyVault'
$certificateName = 'MyCertificate'
$senderAddress = 'sender@example.com'
$recipientAddresses_normal = @(
    'recipient_1@example.com'
    'recipient_2@example.com'
)
$recipientAddresses_critical = @(
    'recipient_3@example.com'
    'recipient_4@example.com'
)
$skuPercentageThreshold_normal = 1
$skuTotalThreshold_normal = 100
$skuPercentageThreshold_important = 1
$skuTotalThreshold_important = 500
$importantSKUs = @(
    '18181a46-0d4e-45cd-891e-60aabd171b4e'
    '6fd2c87f-b296-42f0-b197-1e91e994b900'
)
$interchangeableSKUs = @(
    '4b585984-651b-448a-9e53-3b10f069cf7f'
    '18181a46-0d4e-45cd-891e-60aabd171b4e'
    '6fd2c87f-b296-42f0-b197-1e91e994b900'
    'c7df2760-2c81-4ef7-b578-5b5392b571df'
)
$preferableSKUs = @(
    [SKURule]@{
        SKUID = [guid]::Empty
        AccountGuest = 'True'
    }
    [SKURule]@{
        SKUID = [guid]::Empty
        CreatedEarlierThan = [datetime]::Now.AddYears(-2)
        LastActiveEarlierThan = [datetime]::Now.AddYears(-2)
    }
    [SKURule]@{
        SKUID = '4b585984-651b-448a-9e53-3b10f069cf7f'
        OneDriveGBUsedLessThan = 2
        MailboxGBUsedLessThan = 2
        MailboxHasArchive = 'False'
        WindowsAppUsed = 'False'
        MacAppUsed = 'False'
    }
    [SKURule]@{
        SKUID = '18181a46-0d4e-45cd-891e-60aabd171b4e'
        MailboxGBUsedLessThan = 50
        MailboxHasArchive = 'False'
        WindowsAppUsed = 'False'
        MacAppUsed = 'False'
    }
)
$skuPrices = @(
    [SKUPrice]@{
        SKUID = '4b585984-651b-448a-9e53-3b10f069cf7f'
        Price = 4.0
    }
    [SKUPrice]@{
        SKUID = '18181a46-0d4e-45cd-891e-60aabd171b4e'
        Price = 10.0
    }
    [SKUPrice]@{
        SKUID = '6fd2c87f-b296-42f0-b197-1e91e994b900'
        Price = 23.0
    }
    [SKUPrice]@{
        SKUID = 'c7df2760-2c81-4ef7-b578-5b5392b571df'
        Price = 38.0
    }
)

Get-AzureADLicenseStatus -DirectoryID $directoryID -ApplicationID $applicationID -SubscriptionID $subscriptionID -KeyVaultName $keyVaultName -CertificateName $certificateName -SenderAddress $senderAddress -RecipientAddresses_normal $recipientAddresses_normal -RecipientAddresses_critical $recipientAddresses_critical -SKUPercentageThreshold_normal $skuPercentageThreshold_normal -SKUTotalThreshold_normal $skuTotalThreshold_normal -SKUPercentageThreshold_important $skuPercentageThreshold_important -SKUTotalThreshold_important $skuTotalThreshold_important -ImportantSKUs $importantSKUs -InterchangeableSKUs $interchangeableSKUs -PreferableSKUs $preferableSKUs -SKUPrices $skuPrices -AdvancedCheckups
```

## 6.2 Example report

Below example shows how a report might look like, although the example might differ from the actual result due to the manual's style settings

<div>
    <style>
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
    </style>
    <p class=gray>Basic checkup - Products</p>
    <p>Please check license counts for the following product SKUs and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p>
    <p>
        <table>
            <tr>
                <th>License type</th>
                <th>Available count</th>
                <th>Minimum count</th>
                <th>Difference</th>
            </tr>
            <tr>
                <td>Office 365 F3</td>
                <td>96</td>
                <td>100</td>
                <td class=green>-4</td>
            </tr>
            <tr>
                <td>Office 365 E1</td>
                <td>63</td>
                <td>100</td>
                <td class=yellow>-37</td>
            </tr>
            <tr>
                <td>Office 365 E3</td>
                <td>21</td>
                <td>100</td>
                <td class=red>-79</td>
            </tr>
            <tr>
                <td>Office 365 E5</td>
                <td>-13</td>
                <td>100</td>
                <td class=red>-113</td>
            </tr>
        </table>
    </p>
    <p>The following criteria were used during the checkup:
        <ul>
            <li>Check products with &gt;10 total licenses</li>
            <li>Report normal products having both &lt;10 licenses and &lt;90% of their total licenses available</li>
            <li>Report important products having both &lt;100 licenses and &lt;90% of their total licenses available</li>
        </ul>
    </p>
    <p class=gray>Advanced checkup - Products</p>
    <p>Please check license counts for the following product SKUs and <a href="https://www.microsoft.com/licensing/servicecenter">reserve</a> additional licenses:</p>
    <p>
        <table>
            <tr>
                <th>License type</th>
                <th>Enabled count</th>
                <th>Needed count</th>
                <th>Difference</th>
            </tr>
            <tr>
                <td>Entra ID Premium P1</td>
                <td>200</td>
                <td>670</td>
                <td class=red>-470</td>
            </tr>
            <tr>
                <td>Entra ID Premium P2</td>
                <td>100</td>
                <td>170</td>
                <td class=yellow>-70</td>
            </tr>
            <tr>
                <td>Defender for Office 365 P2</td>
                <td>250</td>
                <td>260</td>
                <td class=green>-10</td>
            </tr>
            <tr>
                <td>Intune Device</td>
                <td>50</td>
                <td>80</td>
                <td class=yellow>-30</td>
            </tr>
        </table>
    </p>
    <p>The following criteria were used during the checkup:
        <ul>
            <li>Check <em>Entra ID P1</em> based on groups using dynamic user membership</li>
            <li>Check <em>Entra ID P1</em> based on applications using group-based assignment</li>
            <li>Check <em>Entra ID P1/P2</em> based on users covered by Conditional Access</li>
            <li>Check <em>Entra ID P2</em> based on users in scope of Privileged Identity Management</li>
            <li>Check <em>Defender for Office 365 P1/P2</em> based on protected Exchange Online recipients</li>
            <li>Check <em>Intune Device</em> based on devices managed by Intune and used by unlicensed users</li>
        </ul>
    </p>
    <p class=gray>Basic checkup - Users</p>
    <p>Please check license assignments for the following user accounts and mitigate impact:</p>
    <p>
        <table>
            <tr>
                <th>Account</th>
                <th>Interchangeable</th>
                <th>Optimizable</th>
                <th>Removable</th>
            </tr>
            <tr>
                <td>user_1@example.com</td>
                <td></td>
                <td>Office 365 E3</td>
                <td></td>
            </tr>
            <tr>
                <td>user_2@example.com</td>
                <td>Office 365 E3<br>Office 365 E5</td>
                <td></td>
                <td>Office 365 E3</td>
            </tr>
            <tr>
                <td>user_3@example.com</td>
                <td>Office 365 F3<br>Office 365 E3</td>
                <td></td>
                <td></td>
            </tr>
        </table>
    </p>
    <p>Potential savings when mitigating license assignment impact: 52,30 €</p>
    <p>The following criteria were used during the checkup:
        <ul>
            <li>Check accounts with any number of assigned licenses</li>
            <li>Report theoretically exclusive licenses as <strong>interchangeable</strong>, based on specified SKUs</li>
            <li>Report practically inclusive licenses as <strong>optimizable</strong>, based on available SKU features</li>
            <li>Report actually inclusive licenses as <strong>removable</strong>, based on enabled SKU features</li>
        </ul>
    </p>
    <p class=gray>Advanced checkup - Users</p>
    <p>Please check license assignments for the following user accounts and mitigate impact:</p>
    <p>
        <table>
            <tr>
                <th>Account</th>
                <th>Preferable</th>
                <th>Replaceable</th>
            </tr>
            <tr>
                <td>user_4@example.com</td>
                <td>N/A</td>
                <td>Office 365 E3</td>
            </tr>
            <tr>
                <td>user_2@example.com</td>
                <td>Office 365 E1</td>
                <td>Office 365 E3<br>Office 365 E5</td>
            </tr>
            <tr>
                <td>user_5@example.com</td>
                <td>Office 365 F3</td>
                <td>Office 365 E1</td>
            </tr>
        </table>
    </p>
    <p>Potential savings when mitigating license assignment impact: 73,40 €</p>
    <p>The following criteria were used during the checkup, in order:</p>
    <p>
        <table>
            <tr>
                <th rowspan=2>Priority</th>
                <th rowspan=2 class=rule>License</th>
                <th colspan=4 class=rule>Account</th>
                <th colspan=1 class=rule>OneDrive</th>
                <th colspan=2 class=rule>Mailbox</th>
                <th colspan=4 class=rule>Apps</th>
            </tr>
            <tr>
                <th class=rule>Enabled</th>
                <th>Guest</th>
                <th>Created</th>
                <th>Active</th>
                <th class=rule>Storage</th>
                <th class=rule>Storage</th>
                <th>Archive</th>
                <th class=rule>Windows</th>
                <th>Mac</th>
                <th>Mobile</th>
                <th>Web</th>
            </tr>
            <tr>
                <td>1</td>
                <td>N/A</td>
                <td>-</td>
                <td>True</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
            </tr>
            <tr>
                <td>2</td>
                <td>N/A</td>
                <td>-</td>
                <td>-</td>
                <td>&lt;2021&#8209;07&#8209;01</td>
                <td>&lt;2021&#8209;07&#8209;01</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
            </tr>
            <tr>
                <td>3</td>
                <td>Office 365 F3</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>&lt;2&nbsp;GB</td>
                <td>&lt;2&nbsp;GB</td>
                <td>FALSE</td>
                <td>FALSE</td>
                <td>FALSE</td>
                <td>-</td>
                <td>-</td>
            </tr>
            <tr>
                <td>4</td>
                <td>Office 365 E1</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>&lt;50&nbsp;GB</td>
                <td>FALSE</td>
                <td>FALSE</td>
                <td>FALSE</td>
                <td>-</td>
                <td>-</td>
            </tr>
        </table>
    </p>
</div>
