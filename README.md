# azure-ad-license-status

## Use case description

## Feature overview
### Organization level
- [x] Check for basic license availability, based on Azure AD licensing information and multiple user-defined thresholds
- [ ] Check for advanced license availability, based on calculated information
### User level
- [x] Check for pre-defined, mutually exclusive licenses
- [x] Check for calculated, replaceable licenses
- [ ] Check for user-defined, mutually exclusive licenses
- [ ] Check for calculated, removable licenses

## Preparations
1. Create Azure automation account
   1. Create PowerShell runbook
   2. Enable managed identity
2. Create Azure key vault
   1. Create self-signed certificate
   2. Grant access for managed identity to certificate
3. Create Azure AD application
   1. Grant application permissions _Organization.Read.All_, _Mail.Send_
   2. Attach certificate
4. (optional) Create Exchange Online application access policy
   1. Limit Azure AD application's permission to intended sender mailbox

## Links
- [Azure automation runbook](https://docs.microsoft.com/en-us/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
