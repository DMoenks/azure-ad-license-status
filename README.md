# azure-ad-license-status

## Use case description

## Feature overview
- [x] Check for user-defined, mutually exclusive licenses
- [x] Check for calculated, replaceable licenses
- [ ] Check for multiple sets of user-defined, mutually exclusive licenses
- [ ] Check for calculated, removable licenses

## Requirements
- Azure AD application w/ Microsoft Graph application permission _Organization.Read.All_
- Azure Automation runbook w/ managed identity
- Azure key vault w/ certificate and read permission for the managed identity
- (optional)Exchange Online application access policy

## Links
- [Azure AD application](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [Azure automation runbook](https://docs.microsoft.com/en-us/azure/automation/quickstarts/create-account-portal)
- [Azure key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
- [Exchange Online application access policy](https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal)
