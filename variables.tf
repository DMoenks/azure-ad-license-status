#region: Connection variables
variable "tenant_id" {
  description = "Specifies the tenant"
  type        = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.tenant_id)) > 0
    error_message = "'tenant_id' needs to be a GUID"
  }
}

variable "azuread_client_id" {
  description = "Specifies the application ID for the 'azuread' provider"
  type        = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.azuread_client_id)) > 0
    error_message = "'azuread_client_id' needs to be a GUID"
  }
}

variable "azuread_client_secret" {
  description = "Specifies the application secret for the 'azuread' provider"
  type        = string
  sensitive   = true
}

variable "azurerm_client_id" {
  description = "Specifies the application ID for the 'azurerm' provider"
  type        = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.azurerm_client_id)) > 0
    error_message = "'azurerm_client_id' needs to be a GUID"
  }
}

variable "azurerm_client_secret" {
  description = "Specifies the application secret for the 'azurerm' provider"
  type        = string
  sensitive   = true
}
#endregion

#region: Deployment variables
variable "automation_account_subscription_id" {
  description = "Specifies the subscription for the automation account"
  type        = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.automation_account_subscription_id)) > 0
    error_message = "'automation_account_subscription_id' needs to be a GUID"
  }
}

variable "automation_account_resource_group_name" {
  description = "Specifies the resource group for the automation account"
  type        = string
}

variable "key_vault_subscription_id" {
  description = "Specifies the subscription for the key vault"
  type        = string
  validation {
    condition     = length(regexall("^[[:alnum:]]{8}(?:-[[:alnum:]]{4}){3}-[[:alnum:]]{12}$", var.key_vault_subscription_id)) > 0
    error_message = "'key_vault_subscription_id' needs to be a GUID"
  }
}

variable "key_vault_resource_group_name" {
  description = "Specifies the resource group for the key vault"
  type        = string
}

variable "solution_name" {
  description = "Specifies the name used for the Azure AD application, the automation account and both the keyvault and the certificate"
  type        = string
  default     = "azure-ad-license-status"
}
#endregion