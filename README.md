# azure-ad-license-status

## Use case description

The main motivation for this script was to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The script can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with the default or even custom license terms and agreements applying to you.

## Feature overview

### Organization level

:heavy_check_mark: Check for basic license availability, based on Azure AD licensing information and company's specified thresholds

:x: Check for advanced license availability, based on calculated information

### User level

:heavy_check_mark: Check for company's specified interchangeable licenses

:heavy_check_mark: Check for calculated optimizable licenses

:heavy_check_mark: Check for calculated removable licenses

## Preparations

1. Create Azure automation account
   1. Create PowerShell runbook
   2. Enable managed identity
2. Create Azure key vault
   1. Create self-signed certificate
   2. Grant access for managed identity to certificate
3. Create Azure AD application
   1. Grant following _Application_ permissions for basic checkups
      - _Organization.Read.All_
      - _User.Read.All_
   2. (optional) Grant following _Application_ permissions for advanced checkups
      - _Mail.ReadBasic.All_
      - _Policy.Read.All_
      - _RoleManagement.Read.Directory_
      - _GroupMember.Read.All_
      - _Application.Read.All_
   3. Grant _Delegated_ permissions for report delivery
      - _Mail.Send_
   4. Attach certificate
4. (optional) Create Exchange Online application access policy
   1. Limit Azure AD application's permission to intended sender mailbox
   2. https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-post?view=graph-rest-1.0&tabs=http

> TIP: To simplify permission management, the following permissions can be replaced with the _Directory.Read.All_ permission
>
>- _Organization.Read.All_
>- _User.Read.All_
>- _GroupMember.Read.All_
>- _Application.Read.All_

## Links

- [Azure automation runbook](https://docs.microsoft.com/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://docs.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://docs.microsoft.com/azure/key-vault/general/quick-create-portal)
