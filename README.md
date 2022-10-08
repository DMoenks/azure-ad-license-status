# azure-ad-license-status

## Use case description

The main motivation for this script was to conquer side-effects of semi-automatic license assignments for Microsoft services in Azure AD, i.e. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any conflicting license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The script can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

## Feature overview

### Organization level

:heavy_check_mark: Check for basic license availability, based on Azure AD licensing information and company's specified thresholds

:x: Check for advanced license availability, based on calculated information

### User level

:x: Check for Microsoft's pre-defined mutually exclusive licenses

:x: Check for Microsoft's interchangeable licenses

:heavy_check_mark: Check for company's specified interchangeable licenses

:heavy_check_mark: Check for calculated optimizable licenses

:heavy_check_mark: Check for calculated removable licenses

## Preparations

1. Create Azure automation account
   1. Create PowerShell runbook with content of _Get-AzureADLicenseStatus.ps1_
   2. Add modules
      - _Az.Accounts_
      - _Az.KeyVault_
      - _Microsoft.Graph_
      - (optional) _ExchangeOnlineManagement_
   3. Enable system-assigned managed identity
2. Create Azure key vault
   1. Create self-signed certificate
   2. Grant Azure role _Key Vault Secrets User_ for automation account to certificate
3. Create Azure AD application
   1. Add certificate
   2. Grant **Application** permissions for basic checkups
      - Microsoft Graph permission _Organization.Read.All_
      - Microsoft Graph permission _User.Read.All_
   3. (optional) Grant additional **Application** permissions for advanced checkups
      - Microsoft Graph permission _Application.Read.All_  
        Azure AD P1 based on group-based application assignments and applications using application proxy
      - Microsoft Graph permission _GroupMember.Read.All_  
        Azure AD P1 based on dynamic groups
      - Microsoft Graph permission _Policy.Read.All_  
        Azure AD P1 based on MFA-enabled users
      - Microsoft Graph permission _RoleManagement.Read.All_  
        Azure AD P2 based on PIM-managed users
      - Office 365 Exchange Online permission _Exchange.ManageAsApp_ and Azure AD role _Exchange Recipient Administrator_  
        Defender for Office 365 P1/P2 based on user and shared mailboxes
   4. Consent to **Application** permissions on behalf of the tenant
   5. Grant **Delegated** permission for report delivery
      - Microsoft Graph permission _Mail.Send_
   6. Consent to **Delegated** permission on behalf of the report delivery user by running _Create-AzureADLicenseStatusGrant.ps1_

      ```powershell
      Create-AzureADLicenseStatusGrant.ps1 -applicationID "<Azure AD application's ID>" -senderAddress "<Report delivery user's email address>"
      ```

> HINT: To simplify permission management, the following permissions can be replaced with the _Directory.Read.All_ permission
>
>- _Application.Read.All_
>- _GroupMember.Read.All_
>- _Organization.Read.All_
>- _User.Read.All_

## Links

- [Azure automation runbook](https://docs.microsoft.com/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://docs.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [OAuth2 permission grant](https://learn.microsoft.com/graph/api/oauth2permissiongrant-post)
