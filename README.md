# azure-ad-license-status

## 1 Use case description

The main motivation for this script was to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The script can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

## 2 Feature overview

### 2.1 Organization level

#### 2.1.1 Basic

:heavy_check_mark: Check for license availability based on Azure AD license information

:heavy_check_mark: Calculate report importance based on organization's thresholds

#### 2.1.2 Advanced

:heavy_check_mark: Check for license need based on Azure AD and Office feature information:

- Azure Active Directory Premium P1 based on group-based application assignments
- Azure Active Directory Premium P1 based on dynamic group memberships
- Azure Active Directory Premium P1 based on users enabled for Conditional Access
- Azure Active Directory Premium P2 based on users enabled for Privileged Identity Management
- Defender for Office 365 P1/P2 based on user and shared mailboxes

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

- **Microsoft Graph** permission _Mail.Send_
- **Microsoft Graph** permission _Organization.Read.All_
- **Microsoft Graph** permission _User.Read.All_

#### 3.2.2 Advanced

- **Microsoft Graph** permission _Application.Read.All_
- **Microsoft Graph** permission _GroupMember.Read.All_
- **Microsoft Graph** permission _Policy.Read.All_
- **Microsoft Graph** permission _RoleManagement.Read.All_
- **Office 365 Exchange Online** permission _Exchange.ManageAsApp_ and Azure AD role _Exchange Recipient Administrator_

> HINT: To simplify permission management, the following **Microsoft Graph** permissions can be replaced with the _Directory.Read.All_ permission. As this would provide the script with additional, probably unnecessary permissions, consider this at your own discretion.
>
>- _Application.Read.All_
>- _GroupMember.Read.All_
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
     1. Create Azure key vault
        1. Create self-signed certificate
        1. Grant Azure role _Key Vault Secrets User_ for automation account to certificate
2. Prepare authentication
   1. Create Azure AD application
   2. Add certificate
   3. Add required permissions
3. (optional) Limit send permissions
   1. Create Exchange Online application access policy to restrict Azure AD application's _Mail.Send_ permission to intended sender mailbox

## 5 Links

- [Azure automation runbook](https://learn.microsoft.com/azure/automation/automation-create-standalone-account)
- [Azure key vault](https://learn.microsoft.com/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
