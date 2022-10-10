# azure-ad-license-status

## Use case description

The main motivation for this script was to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The script can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

## Feature overview

### Organization level

:heavy_check_mark: Check for basic license availability, based on Azure AD licensing information and company's specified thresholds

:heavy_check_mark: Check for advanced license availability, based on calculated information:

- Azure Active Directory Premium P1 based on group-based application assignments
- Azure Active Directory Premium P1 based on dynamic group memberships
- Azure Active Directory Premium P1 based on users enabled for Conditional Access
- Azure Active Directory Premium P2 based on users enabled for Privileged Identity Management
- Defender for Office 365 P1/P2 based on user and shared mailboxes

### User level

:heavy_check_mark: Check for Microsoft's pre-defined mutually exclusive licenses

:x: Check for Microsoft's interchangeable licenses

:heavy_check_mark: Check for company's specified interchangeable licenses

:heavy_check_mark: Check for calculated optimizable licenses

:heavy_check_mark: Check for calculated removable licenses

## Requirements

To use the script for either basic or advanced checkups, it needs the following:

- Permissions for basic checkups
  - Microsoft Graph permission _Organization.Read.All_
  - Microsoft Graph permission _Mail.Send_
  - Microsoft Graph permission _User.Read.All_
- Permissions for advanced checkups
  - Microsoft Graph permission _Application.Read.All_
  - Microsoft Graph permission _GroupMember.Read.All_
  - Microsoft Graph permission _Policy.Read.All_
  - Microsoft Graph permission _RoleManagement.Read.All_
  - Office 365 Exchange Online permission _Exchange.ManageAsApp_ and Azure AD role _Exchange Recipient Administrator_
- PowerShell modules for basic checkups
  - _Az.Accounts_
  - _Az.KeyVault_
  - _Microsoft.Graph_
- PowerShell modules for advanced checkups
  - _ExchangeOnlineManagement_

> HINT: To simplify permission management, the following permissions can be replaced with the _Directory.Read.All_ permission. As this would provide the script with additional, probably unnecessary permissions, consider this at your own discretion.
>
>- _Application.Read.All_
>- _GroupMember.Read.All_
>- _Organization.Read.All_
>- _User.Read.All_

## Preparations

To use the script for automation purposes with Azure services, configure the following:

1. Create Azure automation account
   1. Create PowerShell runbook
   2. Add required modules
   3. Enable system-assigned managed identity
2. Create Azure key vault
   1. Create self-signed certificate
   2. Grant Azure role _Key Vault Secrets User_ for automation account to certificate
3. Create Azure AD application
   1. Add certificate
   2. Grant required permissions
4. (optional) Create Exchange Online application access policy
   1. Limit Azure AD application's permission to intended sender mailbox

## Links

- [Azure automation runbook](https://learn.microsoft.com/azure/automation/automation-create-standalone-account)
- [Azure key vault](https://learn.microsoft.com/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
