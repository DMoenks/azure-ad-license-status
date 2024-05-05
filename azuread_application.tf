provider "azuread" {
  tenant_id     = var.tenant_id
  client_id     = var.azuread_client_id
  client_secret = var.azuread_client_secret
}

data "azuread_client_config" "client_config_azuread_application" {}

resource "azuread_application" "application" {
  display_name = var.solution_name
  required_resource_access {
    resource_app_id = data.azuread_service_principal.service_principal_graph.client_id
    resource_access {
      id   = data.azuread_service_principal.service_principal_graph.app_role_ids["DeviceManagementManagedDevices.Read.All"]
      type = "Role"
    }
    resource_access {
      id   = data.azuread_service_principal.service_principal_graph.app_role_ids["Mail.Send"]
      type = "Role"
    }
    resource_access {
      id   = data.azuread_service_principal.service_principal_graph.app_role_ids["Policy.Read.All"]
      type = "Role"
    }
    resource_access {
      id   = data.azuread_service_principal.service_principal_graph.app_role_ids["Reports.Read.All"]
      type = "Role"
    }
    resource_access {
      id   = data.azuread_service_principal.service_principal_graph.app_role_ids["RoleManagement.Read.All"]
      type = "Role"
    }
  }
  required_resource_access {
    resource_app_id = data.azuread_service_principal.service_principal_exchange_online.client_id
    resource_access {
      id   = data.azuread_service_principal.service_principal_exchange_online.app_role_ids["Exchange.ManageAsApp"]
      type = "Role"
    }
  }
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_devicemanagementmanageddevices_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = data.azuread_service_principal.service_principal_graph.object_id
  app_role_id         = data.azuread_service_principal.service_principal_graph.app_role_ids["DeviceManagementManagedDevices.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_mail_send" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = data.azuread_service_principal.service_principal_graph.object_id
  app_role_id         = data.azuread_service_principal.service_principal_graph.app_role_ids["Mail.Send"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_policy_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = data.azuread_service_principal.service_principal_graph.object_id
  app_role_id         = data.azuread_service_principal.service_principal_graph.app_role_ids["Policy.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_reports_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = data.azuread_service_principal.service_principal_graph.object_id
  app_role_id         = data.azuread_service_principal.service_principal_graph.app_role_ids["Reports.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_rolemanagement_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = data.azuread_service_principal.service_principal_graph.object_id
  app_role_id         = data.azuread_service_principal.service_principal_graph.app_role_ids["RoleManagement.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_exchange_online_exchange_manageasapp" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = data.azuread_service_principal.service_principal_exchange_online.object_id
  app_role_id         = data.azuread_service_principal.service_principal_exchange_online.app_role_ids["Exchange.ManageAsApp"]
}

resource "azuread_application_certificate" "application_certificate" {
  application_id = azuread_application.application.client_id
  encoding       = "hex"
  type           = "AsymmetricX509Cert"
  value          = azurerm_key_vault_certificate.key_vault_certificate.certificate_data
  start_date     = azurerm_key_vault_certificate.key_vault_certificate.certificate_attribute[0].not_before
  end_date       = azurerm_key_vault_certificate.key_vault_certificate.certificate_attribute[0].expires
}

data "azuread_service_principal" "service_principal_graph" {
  # Provider: Microsoft Graph
  client_id = "00000003-0000-0000-c000-000000000000"
}

data "azuread_service_principal" "service_principal_exchange_online" {
  # Provider: Office 365 Exchange Online
  client_id = "00000002-0000-0ff1-ce00-000000000000"
}

resource "azuread_service_principal" "service_principal_azure_ad_license_status" {
  client_id = azuread_application.application.client_id
  owners = [
    data.azuread_client_config.client_config_azuread_application.object_id
  ]
}

resource "azuread_directory_role_assignment" "directory_role_assignment" {
  # Role: Global Reader
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  role_id             = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
}