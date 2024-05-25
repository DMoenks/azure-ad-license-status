---
layout: default
permalink: /usage
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Usage](/azure-ad-license-status/usage) \| [6 Examples](/azure-ad-license-status/examples)

# 5 Usage

## 5.1 Parameters

- DirectoryID &lt;System.Guid&gt;  
  Specifies the directory to connect to
- ApplicationID &lt;System.Guid&gt;  
  Specifies the application in target directory to authenticate with
- SubscriptionID &lt;System.Guid&gt;  
  Specifies the subscription in target directory to access
- KeyVaultName &lt;System.String&gt;  
  Specifies the key vault in target subscription to access
- CertificateName &lt;System.String&gt;  
  Specifies the certificate name in target key vault to use for authentication
- Certificate &lt;System.Security.Cryptography.X509Certificates.X509Certificate2&gt;  
  Specifies the certificate to use for authentication
- CertificateThumbprint &lt;System.String&gt;  
  Specifies the certificate thumbprint in local certificate store to use for authentication
- SenderAddress &lt;System.String&gt;  
  Specifies the sender address to be used for report delivery
- RecipientAddresses_normal &lt;System.String[]&gt;  
  Specifies the recipient addresses to be used for report delivery
- RecipientAddresses_critical &lt;System.String[]&gt;  
  Specifies the additional recipient addresses to be used for report delivery in critical cases
- SKUIgnoreThreshold &lt;System.UInt32&gt;  
  Specifies the minimum enabled license threshold for SKUs to be considered for the report, e.g. to ignore SKUs purchased for testing purposes or from trials  
  default: 10
- SKUPercentageThreshold_normal &lt;System.UInt16&gt;  
  Specifies the minimum available license percentage threshold for SKUs to be included in the report  
  default: 5
- SKUTotalThreshold_normal &lt;System.UInt32&gt;  
  Specifies the minimum available license amount threshold for SKUs to be included in the report  
  default: 10
- SKUPercentageThreshold_important &lt;System.UInt16&gt;  
  Specifies the minimum available license percentage threshold for SKUs to be included in the report  
  default: 5
- SKUTotalThreshold_important &lt;System.UInt32&gt;  
  Specifies the minimum available license amount threshold for SKUs to be included in the report  
  default: 50
- SKUWarningThreshold_basic &lt;System.UInt16&gt;  
  Specifies the warning percentage threshold to be used during report creation for basic checkups, should be higher than the value provided for the parameter 'SKUCriticalThreshold_basic'  
  default: 80
- SKUCriticalThreshold_basic &lt;System.UInt16&gt;  
  Specifies the critical percentage threshold to be used during report creation for basic checkups, should be lower than the value provided for the parameter 'SKUWarningThreshold_basic'  
  default: 20
- SKUWarningThreshold_advanced &lt;System.UInt16&gt;  
  Specifies the warning percentage threshold to be used during report creation for advanced checkups, should be higher than the value provided for the parameter 'SKUCriticalThreshold_advanced'  
  default: 99
- SKUCriticalThreshold_advanced &lt;System.UInt16&gt;  
  Specifies the critical percentage threshold to be used during report creation for advanced checkups, should be lower than the value provided for the parameter 'SKUWarningThreshold_advanced'  
  default: 95
- ImportantSKUs &lt;System.Guid[]&gt;  
  Specifies the SKUs which are deemed important, so different thresholds are used for calculation
- InterchangeableSKUs &lt;System.Guid[]&gt;  
  Specifies a list of SKUs which are deemed interchangeable, e.g Office 365 E1 and Office 365 E3
- PreferableSKUs &lt;SKURule[]&gt;  
  Specifies a list of SKUs which are deemed preferable based on their provided ruleset, relies on the parameter 'InterchangeableSKUs' to calculate replaceable SKUs
- SKUPrices &lt;SKUPrice[]&gt;  
  Specifies a list of SKUs with their prices to calculate potential savings during user checkups
- AttachmentFormat &lt;System.String&gt;  
  Specifies a format for user results attached to the report  
  accepts: 'CSV', 'TranslatedCSV', 'JSON'
- LicensingURL &lt;System.String&gt;  
  Specifies a licensing portal URL to be linked in the report, refers to Microsoft's Volume Licensing Service Center by default  
  default: <https://www.microsoft.com/licensing/servicecenter>
- AdvancedCheckups &lt;System.Management.Automation.SwitchParameter&gt;  
  Specifies if advanced license checkups should be run  
  ATTENTION: Advanced checkups require additional access permissions and might increase the checkup duration

## 5.2 Types

## 5.2.1 HumanIdentifier

### 5.2.1.1 Properties

- AttributeName &lt;System.String&gt;
- AttributeValues &lt;System.String[]&gt;

### 5.2.2 SKUPrice

#### 5.2.2.1 Properties

- SKUID &lt;System.Guid&gt;
- Price &lt;System.Decimal&gt;

### 5.2.3 SKURule

#### 5.2.3.1 Properties

- SKUID &lt;System.Guid&gt;
- AccountEnabled &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::AccountEnabledDefault()
- AccountGuest &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::AccountGuestDefault()
- CreatedEarlierThan &lt;System.DateTime&gt;  
  default: [SKURule]::CreatedEarlierThanDefault()
- LastActiveEarlierThan &lt;System.DateTime&gt;  
  default: [SKURule]::LastActiveEarlierThanDefault()
- LastLicenseChangeEarlierThan &lt;System.DateTime&gt;  
  default: [SKURule]::LastLicenseChangeEarlierThanDefault()
- DeviceOwned &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::DeviceOwnedDefault()
- OneDriveGBUsedLessThan &lt;System.Decimal&gt;  
  default: [SKURule]::OneDriveGBUsedLessThanDefault()
- MailboxGBUsedLessThan &lt;System.Decimal&gt;  
  default: [SKURule]::MailboxGBUsedLessThanDefault()
- MailboxHasArchive &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::MailboxHasArchiveDefault()
- WindowsAppUsed &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::WindowsAppUsedDefault()
- MacAppUsed &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::MacAppUsedDefault()
- MobileAppUsed &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::MobileAppUsedDefault()
- WebAppUsed &lt;System.String&gt;  
  accepts: 'True', 'False', 'Skip'  
  default: [SKURule]::WebAppUsedDefault()

#### 5.2.2.2 Methods

- AccountEnabledDefault() &lt;System.String&gt;  
  returns: 'Skip'
- AccountGuestDefault() &lt;System.String&gt;  
  returns: 'Skip'
- CreatedEarlierThanDefault() &lt;System.DateTime&gt;  
  returns: [datetime]::MaxValue
- LastActiveEarlierThanDefault() &lt;System.DateTime&gt;  
  returns: [datetime]::MaxValue
- LastLicenseChangeEarlierThanDefault() &lt;System.DateTime&gt;  
  returns: [datetime]::MaxValue
- DeviceOwnedDefault() &lt;System.String&gt;  
  returns: 'Skip'
- OneDriveGBUsedLessThanDefault() &lt;System.Decimal&gt;  
  returns: [UInt16]::MaxValue
- MailboxGBUsedLessThanDefault() &lt;System.Decimal&gt;  
  returns: [UInt16]::MaxValue
- MailboxHasArchiveDefault() &lt;System.String&gt;  
  returns: 'Skip'
- WindowsAppUsedDefault() &lt;System.String&gt;  
  returns: 'Skip'
- MacAppUsedDefault() &lt;System.String&gt;  
  returns: 'Skip'
- MobileAppUsedDefault() &lt;System.String&gt;  
  returns: 'Skip'
- WebAppUsedDefault() &lt;System.String&gt;  
  returns: 'Skip'
