#region: Connection variables
variable "tenant_id" {
  type = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.tenant_id)) > 0
    error_message = "'tenant_id' needs to be a GUID"
  }
}

variable "azuread_client_id" {
  type = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.azuread_client_id)) > 0
    error_message = "'client_id' needs to be a GUID"
  }
}

variable "azuread_client_secret" {
  type      = string
  sensitive = true
}

variable "azurerm_client_id" {
  type = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.azurerm_client_id)) > 0
    error_message = "'client_id' needs to be a GUID"
  }
}

variable "azurerm_client_secret" {
  type      = string
  sensitive = true
}
#endregion

#region: Deployment variables
variable "automation_account_subscription_id" {
  type = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.automation_account_subscription_id)) > 0
    error_message = "'subscription_id' needs to be a GUID"
  }
}

variable "automation_account_resource_group_name" {
  type = string
}

variable "automation_account_name" {
  type = string
}

variable "key_vault_subscription_id" {
  type = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.key_vault_subscription_id)) > 0
    error_message = "'subscription_id' needs to be a GUID"
  }
}

variable "key_vault_resource_group_name" {
  type = string
}

variable "key_vault_name" {
  type = string
}

variable "solution_name" {
  type    = string
  default = "azure-ad-license-status"
}
#endregion

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
  features {}
  alias           = "automation_account"
  tenant_id       = var.tenant_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  subscription_id = var.automation_account_subscription_id
}

provider "azurerm" {
  features {}
  alias           = "key_vault"
  tenant_id       = var.tenant_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  subscription_id = var.key_vault_subscription_id
}
#endregion

#region: 'azurerm' configuration
data "azurerm_resource_group" "automation_account_resource_group" {
  provider = azurerm.automation_account
  name     = var.automation_account_resource_group_name
}

data "azurerm_automation_account" "automation_account" {
  provider            = azurerm.automation_account
  resource_group_name = var.automation_account_resource_group_name
  name                = var.automation_account_name
}

resource "azurerm_automation_runbook" "automation_runbook" {
  name                    = "Get-AzureADLicenseStatus"
  location                = data.azurerm_resource_group.automation_account_resource_group.location
  resource_group_name     = data.azurerm_automation_account.automation_account.resource_group_name
  automation_account_name = data.azurerm_automation_account.automation_account.name
  runbook_type            = "PowerShell"
  log_progress            = true
  log_verbose             = true
  publish_content_link {
    uri = "https://raw.githubusercontent.com/DMoenks/azure-ad-license-status/main/azure-ad-license-status.psm1"
  }
}

data "azurerm_resource_group" "key_vault_resource_group" {
  provider = azurerm.key_vault
  name     = var.key_vault_resource_group_name
}

data "azurerm_key_vault" "key_vault" {
  provider            = azurerm.key_vault
  resource_group_name = data.azurerm_resource_group.key_vault_resource_group.name
  name                = var.key_vault_name
}

resource "azurerm_key_vault_certificate" "key_vault_certificate" {
  name         = var.solution_name
  key_vault_id = data.azurerm_key_vault.key_vault.id
  certificate_policy {
    issuer_parameters {
      name = "Self"
    }
    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }
    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      trigger {
        days_before_expiry = 30
      }
    }
    secret_properties {
      content_type = "application/x-pkcs12"
    }
    x509_certificate_properties {
      extended_key_usage = ["1.3.6.1.5.5.7.3.2"]
      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]
      subject            = "CN=${var.solution_name}"
      validity_in_months = 12
    }
  }
}
#endregion

#region: 'azuread' configuration
resource "azuread_application" "application" {
  display_name = var.solution_name
  required_resource_access {
    # Microsoft Graph
    resource_app_id = "00000003-0000-0000-c000-000000000000"
    resource_access {
      # AuditLog.Read.All
      id   = "246dd0d5-5bd0-4def-940b-0421030a5b68"
      type = "Role"
    }
    resource_access {
      # Mail.Send
      id   = "b0afded3-3588-46d8-8b3d-9842eff778da"
      type = "Role"
    }
    resource_access {
      # Policy.Read.All
      id   = "b633e1c5-b582-4048-a93e-9f11b44c7e96"
      type = "Role"
    }
    resource_access {
      # RoleManagement.Read.All
      id   = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4"
      type = "Role"
    }
  }
  required_resource_access {
    # Office 365 Exchange Online
    resource_app_id = "00000002-0000-0ff1-ce00-000000000000"
    resource_access {
      # Exchange.ManageAsApp
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
  # Global Reader
  role_id             = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
  principal_object_id = azuread_application.application.object_id
}
#endregion