provider "azurerm" {
  alias           = "key_vault"
  tenant_id       = var.tenant_id
  subscription_id = var.key_vault_subscription_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  features {}
}

data "azurerm_client_config" "client_config_azurerm_key_vault" {
  provider = azurerm.key_vault
}

data "azurerm_resource_group" "resource_group_key_vault" {
  provider = azurerm.key_vault
  name     = var.key_vault_resource_group_name
}

resource "azurerm_key_vault" "key_vault" {
  provider                   = azurerm.key_vault
  resource_group_name        = data.azurerm_resource_group.resource_group_key_vault.name
  name                       = "kv-${var.solution_name}"
  location                   = data.azurerm_resource_group.resource_group_key_vault.location
  sku_name                   = "standard"
  tenant_id                  = var.tenant_id
  enable_rbac_authorization  = true
  access_policy              = []
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault_certificate" "key_vault_certificate" {
  depends_on = [
    azurerm_role_assignment.role_assignment_key_vault_certificates_officer
  ]
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

data "azurerm_role_definition" "role_definition_key_vault_certificates_officer" {
  # Role: Key Vault Certificates Officer
  provider           = azurerm.key_vault
  role_definition_id = "a4417e6f-fecd-4de8-b567-7b0420556985"
}

resource "azurerm_role_assignment" "role_assignment_key_vault_certificates_officer" {
  provider           = azurerm.key_vault
  scope              = azurerm_key_vault.key_vault.id
  principal_id       = data.azurerm_client_config.client_config_azurerm_key_vault.object_id
  role_definition_id = data.azurerm_role_definition.role_definition_key_vault_certificates_officer.id
}

data "azurerm_role_definition" "role_definition_key_vault_secrets_user" {
  # Role: Key Vault Secrets User
  provider           = azurerm.key_vault
  role_definition_id = "4633458b-17de-408a-b874-0445c86b69e6"
}

resource "azurerm_role_assignment" "role_assignment_key_vault_secrets_user" {
  provider           = azurerm.key_vault
  scope              = azurerm_key_vault.key_vault.id
  principal_id       = azurerm_automation_account.automation_account.identity[0].principal_id
  role_definition_id = data.azurerm_role_definition.role_definition_key_vault_secrets_user.id
}