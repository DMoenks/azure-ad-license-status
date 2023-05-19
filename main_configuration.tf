#region: Provider configuration
terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">=2.0.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.0.0"
    }
  }
}

provider "azuread" {
  tenant_id     = var.tenant_id
  client_id     = var.azuread_client_id
  client_secret = var.azuread_client_secret
}

provider "azurerm" {
  alias           = "automation_account"
  tenant_id       = var.tenant_id
  subscription_id = var.automation_account_subscription_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  features {}
}

provider "azurerm" {
  alias           = "key_vault"
  tenant_id       = var.tenant_id
  subscription_id = var.key_vault_subscription_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  features {}
}
#endregion

#region: 'azuread' configuration
resource "azuread_application" "application" {
  display_name = var.solution_name
  required_resource_access {
    # Provider: Microsoft Graph
    resource_app_id = "00000003-0000-0000-c000-000000000000"
    resource_access {
      # Permission: AuditLog.Read.All
      id   = "246dd0d5-5bd0-4def-940b-0421030a5b68"
      type = "Role"
    }
    resource_access {
      # Permission: Mail.Send
      id   = "b0afded3-3588-46d8-8b3d-9842eff778da"
      type = "Role"
    }
    resource_access {
      # Permission: Policy.Read.All
      id   = "b633e1c5-b582-4048-a93e-9f11b44c7e96"
      type = "Role"
    }
    resource_access {
      # Permission: RoleManagement.Read.All
      id   = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4"
      type = "Role"
    }
  }
  required_resource_access {
    # Provider: Office 365 Exchange Online
    resource_app_id = "00000002-0000-0ff1-ce00-000000000000"
    resource_access {
      # Permission: Exchange.ManageAsApp
      id   = "dc50a0fb-09a3-484d-be87-e023b12c6440"
      type = "Role"
    }
  }
}

resource "azuread_application_certificate" "application_certificate" {
  application_object_id = azuread_application.application.object_id
  encoding              = "hex"
  type                  = "AsymmetricX509Cert"
  value                 = azurerm_key_vault_certificate.key_vault_certificate.certificate_data
  start_date            = azurerm_key_vault_certificate.key_vault_certificate.certificate_attribute[0].not_before
  end_date              = azurerm_key_vault_certificate.key_vault_certificate.certificate_attribute[0].expires
}

resource "azuread_directory_role_assignment" "directory_role_assignment" {
  # Role: Global Reader
  principal_object_id = azuread_application.application.object_id
  role_id             = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
}
#endregion

#region: 'azurerm' configuration
data "azurerm_resource_group" "automation_account_resource_group" {
  provider = azurerm.automation_account
  name     = var.automation_account_resource_group_name
}

resource "azurerm_automation_account" "automation_account" {
  provider            = azurerm.automation_account
  resource_group_name = data.azurerm_resource_group.automation_account_resource_group.name
  name                = "aa-${var.solution_name}"
  location            = data.azurerm_resource_group.automation_account_resource_group.location
  sku_name            = "Basic"
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_automation_module" "automation_module_az_accounts" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.automation_account_resource_group.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Az.Accounts"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/Az.Accounts/2.12.1"
  }
}

resource "azurerm_automation_module" "automation_module_az_keyvault" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.automation_account_resource_group.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Az.KeyVault"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/Az.KeyVault/4.9.2"
  }
}

resource "azurerm_automation_module" "automation_module_exchangeonlinemanagement" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.automation_account_resource_group.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "ExchangeOnlineManagement"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/ExchangeOnlineManagement/3.1.0"
  }
}

resource "azurerm_automation_module" "automation_module_microsoft_graph_authentication" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.automation_account_resource_group.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Microsoft.Graph.Authentication"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/1.27.0"
  }
}

resource "azurerm_automation_module" "automation_module_main" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.automation_account_resource_group.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "azure-ad-license-status"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/azure-ad-license-status/1.2.6"
  }
}

resource "azurerm_automation_runbook" "automation_runbook_script" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.automation_account_resource_group.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Run-AzureADLicenseStatus"
  location                = data.azurerm_resource_group.automation_account_resource_group.location
  runbook_type            = "PowerShell"
  log_progress            = false
  log_verbose             = false
  publish_content_link {
    uri = "https://raw.githubusercontent.com/DMoenks/azure-ad-license-status/main/Run-AzureADLicenseStatus.ps1"
  }
}

data "azurerm_resource_group" "key_vault_resource_group" {
  provider = azurerm.key_vault
  name     = var.key_vault_resource_group_name
}

resource "azurerm_key_vault" "key_vault" {
  provider                  = azurerm.key_vault
  resource_group_name       = data.azurerm_resource_group.key_vault_resource_group.name
  name                      = "kv-${var.solution_name}"
  location                  = data.azurerm_resource_group.key_vault_resource_group.location
  sku_name                  = "standard"
  tenant_id                 = var.tenant_id
  enable_rbac_authorization = true
  access_policy             = []
}

resource "azurerm_key_vault_certificate" "key_vault_certificate" {
  provider     = azurerm.key_vault
  name         = var.solution_name
  key_vault_id = azurerm_key_vault.key_vault.id
  certificate_policy {
    issuer_parameters {
      name = "Self"
    }
    key_properties {
      exportable = false
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = false
    }
    secret_properties {
      content_type = "application/x-pkcs12"
    }
    x509_certificate_properties {
      extended_key_usage = ["1.3.6.1.5.5.7.3.2"]
      key_usage = [
        "digitalSignature"
      ]
      subject            = "CN=${var.solution_name}"
      validity_in_months = 12
    }
  }
}

resource "azurerm_role_assignment" "role_assignment" {
  # Role: Key Vault Secrets User
  provider                         = azurerm.key_vault
  scope                            = azurerm_key_vault.key_vault.id
  principal_id                     = azurerm_automation_account.automation_account.id
  role_definition_id               = "4633458b-17de-408a-b874-0445c86b69e6"
  skip_service_principal_aad_check = true
}
#endregion