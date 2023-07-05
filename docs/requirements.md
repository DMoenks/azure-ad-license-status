---
layout: default
permalink: /requirements
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Examples](/azure-ad-license-status/examples)

# 3 Requirements

## 3.1 Modules

### 3.1.1 Basic

_Microsoft.Graph.Authentication_  
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Microsoft.Graph.Authentication?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication)

### 3.1.2 Advanced

_ExchangeOnlineManagement_  
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/ExchangeOnlineManagement?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)

### 3.1.3 For Azure execution

_Az.Accounts_  
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Az.Accounts?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/Az.Accounts)

_Az.KeyVault_  
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Az.KeyVault?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/Az.KeyVault)

## 3.2 Permissions

### 3.2.1 Basic

- Microsoft Graph permission _Mail.Send_
- Microsoft Graph permission _Organization.Read.All_
- Microsoft Graph permission _User.Read.All_

### 3.2.2 Advanced

- Microsoft Graph permission _DeviceManagementManagedDevices.Read.All_
- Microsoft Graph permission _Policy.Read.All_
- Microsoft Graph permission _Reports.Read.All_
- Microsoft Graph permission _RoleManagement.Read.All_
- Office 365 Exchange Online permission _Exchange.ManageAsApp_
- Azure AD role _Global Reader_

> HINT: When granting the _Global Reader_ role to the application, the following Microsoft Graph permissions can be revoked, as they are already included in the role's permissions.
>
>- _Organization.Read.All_
>- _User.Read.All_

For further details, please refer to [Graph permissions](https://learn.microsoft.com/graph/permissions-reference) and [App-only authentication for Exchange Online](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#assign-azure-ad-roles-to-the-application).
