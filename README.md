# azure-ad-license-status

[![DevSkim](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/devskim.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/devskim.yml)
[![PSScriptAnalyzer](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/powershell.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/powershell.yml)

## 1 Use case description

The main motivation for this script was to conquer side-effects of manual or semi-automatic license assignments for Microsoft services in Azure AD, e.g. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any overlapping license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The script can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

> HINT: The requirements and preparations mentioned below can be deployed by using the provided Terraform module.

## 2 Feature overview

### 2.1 Organization level

#### 2.1.1 Basic

:heavy_check_mark: Check for license availability based on Azure AD license information

:heavy_check_mark: Calculate report importance based on organization's thresholds

#### 2.1.2 Advanced

Check for license need based on Azure AD and Office feature information:

:x: Azure Active Directory Premium P1 based on applications using application proxy

:heavy_check_mark: Azure Active Directory Premium P1 based on applications using group-based assignment

:heavy_check_mark: Azure Active Directory Premium P1 based on groups using dynamic membership

:heavy_check_mark: Azure Active Directory Premium P1 based on users enabled for Conditional Access

:heavy_check_mark: Azure Active Directory Premium P2 based on users enabled for Privileged Identity Management

:heavy_check_mark: Defender for Office 365 P1/P2 based on protected Exchange Online recipients

### 2.2 User level

#### 2.2.1 Basic

:heavy_check_mark: Check for Microsoft's mutually exclusive licenses

:x: Check for Microsoft's interchangeable licenses

:heavy_check_mark: Check for organization's interchangeable licenses

:heavy_check_mark: Calculate optimizable licenses based on available features

:heavy_check_mark: Calculate removable licenses based on enabled features

## 3 Requirements

### 3.1 Modules

#### 3.1.1 Basic

- For local execution
  - _Microsoft.Graph.Authentication_
- For Azure execution
  - _Az.Accounts_
  - _Az.KeyVault_
  - _Microsoft.Graph.Authentication_

#### 3.1.2 Advanced

- _ExchangeOnlineManagement_

### 3.2 Permissions

#### 3.2.1 Basic

- Microsoft Graph permission _Mail.Send_
- Microsoft Graph permission _Organization.Read.All_
- Microsoft Graph permission _User.Read.All_

#### 3.2.2 Advanced

- Microsoft Graph permission _Policy.Read.All_
- Microsoft Graph permission _RoleManagement.Read.All_
- Office 365 Exchange Online permission _Exchange.ManageAsApp_
- Azure AD role _Global Reader_

> HINT: When granting the _Global Reader_ role to the application, the following Microsoft Graph permissions can be revoked, as they are already included in the role's permissions.
>
>- _Organization.Read.All_
>- _User.Read.All_

## 4 Preparations

1. Prepare execution
   - For local execution
     1. Install required modules
     2. Install this module
     3. Create self-signed certificate
   - For Azure execution
     1. Create Azure automation account
        1. Add required modules
        2. Add this module
        3. Enable system-assigned managed identity
     2. Create Azure key vault
        1. Create self-signed certificate
        2. Grant Azure role _Key Vault Secrets User_ for automation account to certificate
2. Prepare authentication
   1. Create Azure AD application
   2. Add required permissions
   3. Add certificate
3. (optional) Limit permissions
   1. Create Exchange Online application access policy to restrict Azure AD application's _Mail.Send_ permission to intended sender mailbox

## 5 Links

- [Azure automation account](https://learn.microsoft.com/azure/automation/automation-create-standalone-account)
- [Azure key vault](https://learn.microsoft.com/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
