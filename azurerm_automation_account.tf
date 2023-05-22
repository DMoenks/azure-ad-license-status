provider "azurerm" {
  alias           = "automation_account"
  tenant_id       = var.tenant_id
  subscription_id = var.automation_account_subscription_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  features {}
}

data "azurerm_resource_group" "resource_group_automation_account" {
  provider = azurerm.automation_account
  name     = var.automation_account_resource_group_name
}

resource "azurerm_automation_account" "automation_account" {
  provider            = azurerm.automation_account
  resource_group_name = data.azurerm_resource_group.resource_group_automation_account.name
  name                = "aa-${var.solution_name}"
  location            = data.azurerm_resource_group.resource_group_automation_account.location
  sku_name            = "Basic"
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_automation_module" "automation_module_az_accounts" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Az.Accounts"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/Az.Accounts/2.12.1"
  }
}

resource "azurerm_automation_module" "automation_module_az_keyvault" {
  depends_on = [
    azurerm_automation_module.automation_module_az_accounts
  ]
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Az.KeyVault"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/Az.KeyVault/4.9.2"
  }
}

resource "azurerm_automation_module" "automation_module_packagemanagement" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "PackageManagement"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/PackageManagement/1.4.8.1"
  }
}
resource "azurerm_automation_module" "automation_module_powershellget" {
  depends_on = [
    azurerm_automation_module.automation_module_packagemanagement
  ]
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "PowerShellGet"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/PowerShellGet/2.2.5"
  }
}

resource "azurerm_automation_module" "automation_module_exchangeonlinemanagement" {
  depends_on = [
    azurerm_automation_module.automation_module_packagemanagement,
    azurerm_automation_module.automation_module_powershellget
  ]
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "ExchangeOnlineManagement"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/ExchangeOnlineManagement/3.1.0"
  }
}

resource "azurerm_automation_module" "automation_module_microsoft_graph_authentication" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Microsoft.Graph.Authentication"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/1.27.0"
  }
}

resource "azurerm_automation_module" "automation_module_azure_ad_license_status" {
  depends_on = [
    azurerm_automation_module.automation_module_exchangeonlinemanagement,
    azurerm_automation_module.automation_module_microsoft_graph_authentication
  ]
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "azure-ad-license-status"
  module_link {
    uri = "https://www.powershellgallery.com/api/v2/package/azure-ad-license-status/1.2.6"
  }
}

resource "azurerm_automation_runbook" "automation_runbook" {
  provider                = azurerm.automation_account
  resource_group_name     = data.azurerm_resource_group.resource_group_automation_account.name
  automation_account_name = azurerm_automation_account.automation_account.name
  name                    = "Run-AzureADLicenseStatus"
  location                = data.azurerm_resource_group.resource_group_automation_account.location
  runbook_type            = "PowerShell"
  log_progress            = false
  log_verbose             = false
  publish_content_link {
    uri = "https://raw.githubusercontent.com/DMoenks/azure-ad-license-status/main/Run-AzureADLicenseStatus.ps1"
  }
}