---
layout: default
permalink: /preparations
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Usage](/azure-ad-license-status/usage) \| [6 Examples](/azure-ad-license-status/examples)

# 4 Preparations

## 4.1 Execution

- For local execution
  1. Install required modules
  2. Install this module
  3. Generate or request certificate
- For Azure execution
  1. Create [Azure automation account](https://learn.microsoft.com/azure/automation/automation-create-standalone-account)
     1. Add required modules
     2. Add this module
     3. Enable system-assigned managed identity
  2. Create [Azure key vault](https://learn.microsoft.com/azure/key-vault/general/quick-create-portal)
     1. Generate, request or import certificate
     2. Grant role _Key Vault Secrets User_ to automation account's managed identity

## 4.2 Authentication

1. Register [Azure AD application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
2. Add required permissions
3. Upload certificate

## 4.3 Permissions

1. (optional, recommended) Create [Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access) to restrict Azure AD application's _Mail.Send_ permission to intended sender mailbox

> HINT: Most of the preparations for advanced Azure execution mentioned above can be deployed by using the Terraform module available in the [GitHub repository](https://github.com/DMoenks/azure-ad-license-status), the exception being an Exchange Online application access policy.
