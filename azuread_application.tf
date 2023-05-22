provider "azuread" {
  tenant_id     = var.tenant_id
  client_id     = var.azuread_client_id
  client_secret = var.azuread_client_secret
}

data "azuread_client_config" "client_config" {

}

resource "azuread_application" "application_azure_ad_license_status" {
  display_name = var.solution_name
  required_resource_access {
    resource_app_id = azuread_service_principal.service_principal_graph.application_id
    resource_access {
      id   = azuread_service_principal.service_principal_graph.app_role_ids["AuditLog.Read.All"]
      type = "Role"
    }
    resource_access {
      id   = azuread_service_principal.service_principal_graph.app_role_ids["Mail.Send"]
      type = "Role"
    }
    resource_access {
      id   = azuread_service_principal.service_principal_graph.app_role_ids["Policy.Read.All"]
      type = "Role"
    }
    resource_access {
      id   = azuread_service_principal.service_principal_graph.app_role_ids["RoleManagement.Read.All"]
      type = "Role"
    }
  }
  required_resource_access {
    resource_app_id = azuread_service_principal.service_principal_exchange_online.application_id
    resource_access {
      id   = azuread_service_principal.service_principal_exchange_online.app_role_ids["Exchange.ManageAsApp"]
      type = "Role"
    }
  }
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_auditlog_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = azuread_service_principal.service_principal_graph.object_id
  app_role_id         = azuread_service_principal.service_principal_graph.app_role_ids["AuditLog.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_mail_send" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = azuread_service_principal.service_principal_graph.object_id
  app_role_id         = azuread_service_principal.service_principal_graph.app_role_ids["Mail.Send"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_policy_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = azuread_service_principal.service_principal_graph.object_id
  app_role_id         = azuread_service_principal.service_principal_graph.app_role_ids["Policy.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_graph_rolemanagement_read_all" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = azuread_service_principal.service_principal_graph.object_id
  app_role_id         = azuread_service_principal.service_principal_graph.app_role_ids["RoleManagement.Read.All"]
}

resource "azuread_app_role_assignment" "app_role_assignment_exchange_online_exchange_manageasapp" {
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  resource_object_id  = azuread_service_principal.service_principal_exchange_online.object_id
  app_role_id         = azuread_service_principal.service_principal_exchange_online.app_role_ids["Exchange.ManageAsApp"]
}

resource "azuread_application_certificate" "application_certificate" {
  application_object_id = azuread_application.application_azure_ad_license_status.object_id
  encoding              = "hex"
  type                  = "AsymmetricX509Cert"
  value                 = azurerm_key_vault_certificate.key_vault_certificate.certificate_data
  start_date            = azurerm_key_vault_certificate.key_vault_certificate.certificate_attribute[0].not_before
  end_date              = azurerm_key_vault_certificate.key_vault_certificate.certificate_attribute[0].expires
}

resource "azuread_service_principal" "service_principal_graph" {
  # Provider: Microsoft Graph
  application_id = "00000003-0000-0000-c000-000000000000"
  use_existing   = true
}

resource "azuread_service_principal" "service_principal_exchange_online" {
  # Provider: Office 365 Exchange Online
  application_id = "00000002-0000-0ff1-ce00-000000000000"
  use_existing   = true
}

resource "azuread_service_principal" "service_principal_azure_ad_license_status" {
  application_id = azuread_application.application_azure_ad_license_status.application_id
  owners = [
    data.azuread_client_config.client_config.object_id
  ]
}

resource "azuread_directory_role_assignment" "directory_role_assignment_global_reader" {
  # Role: Global Reader
  principal_object_id = azuread_service_principal.service_principal_azure_ad_license_status.object_id
  role_id             = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
}