# azure-ad-license-status

## Use case description

## Feature overview
- [x] Check for user-defined, mutually exclusive licenses
- [x] Check for calculated, replaceable licenses
- [ ] Check for multiple sets of user-defined, mutually exclusive licenses
- [ ] Check for calculated, removable licenses

## Preparations
1. Create an Azure automation account
   1. enable managed identity
   2. create PowerShell runbook
2. Create Azure key vault
   1. Create self-signed certificate
   2. Grant read access for automation account's managed identity to certificate
3. Create Azure AD application
   1. Link certificate from key vault
   2. Grant Microsoft Graph application permissions _Organization.Read.All_, _Mail.Send_
4. (optional) Create Exchange Online application access policy
   1. Limit Azure AD application's permission to target sender mailbox

## Links
- [Azure automation runbook](https://docs.microsoft.com/en-us/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
