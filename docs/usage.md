---
layout: default
permalink: /usage
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Usage](/azure-ad-license-status/usage) \| [6 Examples](/azure-ad-license-status/examples)

## Connection parameters

### DirectoryID

Specifies the directory to connect to

### ApplicationID

Specifies the application in target directory to authenticate with

### SubscriptionID

Specifies the subscription in target directory to access

### KeyVaultName

Specifies the key vault in target subscription to access

### CertificateName

Specifies the certificate name in target key vault to use for authentication

### Certificate

Specifies the certificate to use for authentication

### CertificateThumbprint

Specifies the certificate thumbprint in local certificate store to use for authentication

## Configuration parameters

### SenderAddress

Specifies the sender address to be used for report delivery

### RecipientAddresses_normal

Specifies the recipient addresses to be used for report delivery

### RecipientAddresses_critical

Specifies the additional recipient addresses to be used for report delivery in critical cases

### SKUIgnoreThreshold

Specifies the minimum enabled license threshold for SKUs to be considered for the report, e.g. to ignore SKUs purchased for testing purposes or from trials

### SKUPercentageThreshold_normal

Specifies the minimum available license percentage threshold for SKUs to be included in the report

### SKUTotalThreshold_normal

Specifies the minimum available license amount threshold for SKUs to be included in the report

### SKUPercentageThreshold_important

Specifies the minimum available license percentage threshold for SKUs to be included in the report

### SKUTotalThreshold_important

Specifies the minimum available license amount threshold for SKUs to be included in the report

### SKUWarningThreshold_basic

Specifies the warning percentage threshold to be used during report creation for basic checkups, should be higher than the value provided for the parameter 'SKUCriticalThreshold_basic'

### SKUCriticalThreshold_basic

Specifies the critical percentage threshold to be used during report creation for basic checkups, should be lower than the value provided for the parameter 'SKUWarningThreshold_basic'

### SKUWarningThreshold_advanced

Specifies the warning percentage threshold to be used during report creation for advanced checkups, should be higher than the value provided for the parameter 'SKUCriticalThreshold_advanced'

### SKUCriticalThreshold_advanced

Specifies the critical percentage threshold to be used during report creation for advanced checkups, should be lower than the value provided for the parameter 'SKUWarningThreshold_advanced'

### ImportantSKUs

Specifies the SKUs which are deemed important, so different thresholds are used for calculation

### InterchangeableSKUs

Specifies a list of SKUs which are deemed interchangeable, e.g Office 365 E1 and Office 365 E3

### PreferableSKUs

Specifies a list of SKUs which are deemed preferable based on their provided ruleset, relies on the paramater 'InterchangeableSKUs' to calculate replaceable SKUs

### SKUPrices

Specifies a list of SKUs with their prices to calculate potential savings during user checkups

### AttachmentFormat

Specifies a format for user results attached to the report

### LicensingURL

Specifies a licensing portal URL to be linked in the report, refers to Microsoft's Volume Licensing Service Center by default

### AdvancedCheckups

Specifies if advanced license checkups should be run

ATTENTION: Advanced checkups require additional access permissions and might increase the checkup duration

## Classes

### SKUPrice

### SKURule
