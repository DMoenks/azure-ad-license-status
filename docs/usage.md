---
layout: default
permalink: /usage
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Usage](/azure-ad-license-status/usage) \| [6 Examples](/azure-ad-license-status/examples)

# 5 Usage

## 5.1 Parameters

- DirectoryID <System.Guid>
  Specifies the directory to connect to
- ApplicationID <System.Guid>
  Specifies the application in target directory to authenticate with
- SubscriptionID <System.Guid>
  Specifies the subscription in target directory to access
- KeyVaultName <System.String>
  Specifies the key vault in target subscription to access
- CertificateName <System.String>
  Specifies the certificate name in target key vault to use for authentication
- Certificate <System.Security.Cryptography.X509Certificates.X509Certificate2>
  Specifies the certificate to use for authentication
- CertificateThumbprint <System.String>
  Specifies the certificate thumbprint in local certificate store to use for authentication
- SenderAddress <System.String>
  Specifies the sender address to be used for report delivery
- RecipientAddresses_normal <System.String[]>
  Specifies the recipient addresses to be used for report delivery
- RecipientAddresses_critical <System.String[]>
  Specifies the additional recipient addresses to be used for report delivery in critical cases
- SKUIgnoreThreshold <System.UInt32>
  Specifies the minimum enabled license threshold for SKUs to be considered for the report, e.g. to ignore SKUs purchased for testing purposes or from trials
  default: 10
- SKUPercentageThreshold_normal <System.UInt16>
  Specifies the minimum available license percentage threshold for SKUs to be included in the report
  default: 5
- SKUTotalThreshold_normal <System.UInt32>
  Specifies the minimum available license amount threshold for SKUs to be included in the report
  default: 10 <System.UInt16>
- SKUPercentageThreshold_important
  Specifies the minimum available license percentage threshold for SKUs to be included in the report
  default: 5
- SKUTotalThreshold_important <System.UInt32>
  Specifies the minimum available license amount threshold for SKUs to be included in the report
  default: 50
- SKUWarningThreshold_basic <System.UInt16>
  Specifies the warning percentage threshold to be used during report creation for basic checkups, should be higher than the value provided for the parameter 'SKUCriticalThreshold_basic'
  default: 80
- SKUCriticalThreshold_basic <System.UInt16>
  Specifies the critical percentage threshold to be used during report creation for basic checkups, should be lower than the value provided for the parameter 'SKUWarningThreshold_basic'
  default: 20
- SKUWarningThreshold_advanced <System.UInt16>
  Specifies the warning percentage threshold to be used during report creation for advanced checkups, should be higher than the value provided for the parameter 'SKUCriticalThreshold_advanced'
  default: 99
- SKUCriticalThreshold_advanced <System.UInt16>
  Specifies the critical percentage threshold to be used during report creation for advanced checkups, should be lower than the value provided for the parameter 'SKUWarningThreshold_advanced'
  default: 95
- ImportantSKUs <System.Guid[]>
  Specifies the SKUs which are deemed important, so different thresholds are used for calculation
- InterchangeableSKUs <System.Guid[]>
  Specifies a list of SKUs which are deemed interchangeable, e.g Office 365 E1 and Office 365 E3
- PreferableSKUs <SKURule[]>
  Specifies a list of SKUs which are deemed preferable based on their provided ruleset, relies on the parameter 'InterchangeableSKUs' to calculate replaceable SKUs
- SKUPrices <SKUPrice[]>
  Specifies a list of SKUs with their prices to calculate potential savings during user checkups
- AttachmentFormat <System.String>
  Specifies a format for user results attached to the report
  accepts: 'CSV', 'TranslatedCSV', 'JSON'
- LicensingURL <System.String>
  Specifies a licensing portal URL to be linked in the report, refers to Microsoft's Volume Licensing Service Center by default
  default: https://www.microsoft.com/licensing/servicecenter
- AdvancedCheckups <System.Management.Automation.SwitchParameter>
  Specifies if advanced license checkups should be run  
  ATTENTION: Advanced checkups require additional access permissions and might increase the checkup duration

## 5.2 Types

### 5.2.1 SKUPrice

#### 5.2.1.1 Properties

- SKUID <System.Guid>
- Price <System.Decimal>

### 5.2.2 SKURule

#### 5.2.2.1 Properties

- SKUID <System.Guid>
- AccountEnabled <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::AccountEnabledDefault()
- AccountGuest <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::AccountGuestDefault()
- CreatedEarlierThan <System.DateTime>
  default: [SKURule]::CreatedEarlierThanDefault()
- LastActiveEarlierThan <System.DateTime>
  default: [SKURule]::LastActiveEarlierThanDefault()
- OneDriveGBUsedLessThan <System.Decimal>
  default: [SKURule]::OneDriveGBUsedLessThanDefault()
- MailboxGBUsedLessThan <System.Decimal>
  default: [SKURule]::MailboxGBUsedLessThanDefault()
- MailboxHasArchive <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::MailboxHasArchiveDefault()
- WindowsAppUsed <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::WindowsAppUsedDefault()
- MacAppUsed <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::MacAppUsedDefault()
- MobileAppUsed <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::MobileAppUsedDefault()
- WebAppUsed <System.String>
  accepts: 'True', 'False', 'Skip'
  default: [SKURule]::WebAppUsedDefault()

#### 5.2.2.2 Methods

- AccountEnabledDefault() <System.String>
  returns: 'Skip'
- AccountGuestDefault() <System.String>
  returns: 'Skip'
- CreatedEarlierThanDefault() <System.DateTime>
  returns: [datetime]::MaxValue
- LastActiveEarlierThanDefault() <System.DateTime>
  returns: [datetime]::MaxValue
- OneDriveGBUsedLessThanDefault() <System.Decimal>
  returns: [UInt16]::MaxValue
- MailboxGBUsedLessThanDefault() <System.Decimal>
  returns: [UInt16]::MaxValue
- MailboxHasArchiveDefault() <System.String>
  returns: 'Skip'
- WindowsAppUsedDefault() <System.String>
  returns: 'Skip'
- MacAppUsedDefault() <System.String>
  returns: 'Skip'
- MobileAppUsedDefault() <System.String>
  returns: 'Skip'
- WebAppUsedDefault() <System.String>
  returns: 'Skip'
