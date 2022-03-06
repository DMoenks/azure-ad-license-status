# azure-ad-license-status

## Use case description

## Feature overview
- [x] Check for user-defined, mutually exclusive licenses
- [x] Check for calculated, replaceable licenses
- [ ] Check for multiple sets of user-defined, mutually exclusive licenses
- [ ] Check for calculated, removable licenses

## Requirements
- Azure automation account
  - PowerShell runbook
  - Managed Identity
- Azure key vault
  - self-signed certificate
  - read access for automation account's Managed Identity
- Azure AD application
  - Microsoft Graph application permissions _Organization.Read.All_, _Mail.Send_
  - certificate from key vault
- (optional)Exchange Online application access policy
  - Limit application permission to specific sender mailbox

## Links
- [Azure AD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [Azure automation runbook](https://docs.microsoft.com/en-us/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
- [Exchange Online application access policy](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
