# azure-ad-license-status

[![DevSkim](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/devskim.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/devskim.yml)
[![PSScriptAnalyzer](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/powershell.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/powershell.yml)
[![tfsec](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/tfsec.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/tfsec.yml)
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/azure-ad-license-status?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/azure-ad-license-status)

## 1 Use case description

The main motivation for this report was to conquer side-effects of manual or semi-automatic license assignments for Microsoft services in Azure AD, e.g. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any overlapping license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The report can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

> HINT: Most of the requirements and preparations for Azure execution mentioned below can be deployed by using the provided Terraform module, the exception being an Exchange Online application access policy.

## 2 Feature overview

### 2.1 Organization level

#### 2.1.1 Basic

:heavy_check_mark: Check for license availability based on Azure AD license information

:heavy_check_mark: Calculate report importance based on organization's thresholds

#### 2.1.2 Advanced

Check for license need based on Azure AD and Office feature information:

:x: Azure Active Directory Premium P1 based on applications using application proxy

:heavy_check_mark: Azure Active Directory Premium P1 based on groups using dynamic user membership

:heavy_check_mark: Azure Active Directory Premium P1 based on applications using group-based assignment

:heavy_check_mark: Azure Active Directory Premium P1/P2 based on users covered by Conditional Access

> DISCLAIMER: For performance reasons, Conditional Access coverage calculation only considers two separate 5-day time slots. The first being the most recent full Monday-Friday slot, the second being the same slot two weeks earlier. Although this should result in a mostly accurate coverage calculation, taking at least 4-day time slots into account for each time zone, it will inevitably disregard users with irregular access patterns.

:heavy_check_mark: Azure Active Directory Premium P2 based on users in scope of Privileged Identity Management

:heavy_check_mark: Defender for Office 365 P1/P2 based on protected Exchange Online recipients

:x: Intune Device based on devices managed by Intune and used by unlicensed users

### 2.2 User level

#### 2.2.1 Basic

:heavy_check_mark: Check for Microsoft's mutually exclusive licenses

:x: Check for Microsoft's interchangeable licenses

:heavy_check_mark: Check for organization's interchangeable licenses

:heavy_check_mark: Calculate optimizable licenses based on available features

:heavy_check_mark: Calculate removable licenses based on enabled features

#### 2.2.2 Advanced

:heavy_check_mark: Check for organization's preferable licenses

## 3 Requirements

### 3.1 Modules

#### 3.1.1 Basic

- _Microsoft.Graph.Authentication_  
  [![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Microsoft.Graph.Authentication?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication)

#### 3.1.2 Advanced

- _ExchangeOnlineManagement_  
  [![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/ExchangeOnlineManagement?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)

#### 3.1.3 For Azure execution

- _Az.Accounts_  
  [![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Az.Accounts?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/Az.Accounts)
- _Az.KeyVault_  
  [![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/Az.KeyVault?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/Az.KeyVault)

### 3.2 Permissions

#### 3.2.1 Basic

- Microsoft Graph permission _Mail.Send_
- Microsoft Graph permission _Organization.Read.All_
- Microsoft Graph permission _User.Read.All_

#### 3.2.2 Advanced

- Microsoft Graph permission _AuditLog.Read.All_
- Microsoft Graph permission _Policy.Read.All_
- Microsoft Graph permission _Reports.Read.All_
- Microsoft Graph permission _RoleManagement.Read.All_
- Office 365 Exchange Online permission _Exchange.ManageAsApp_
- Azure AD role _Global Reader_

> HINT: When granting the _Global Reader_ role to the application, the following Microsoft Graph permissions can be revoked, as they are already included in the role's permissions.
>
>- _Organization.Read.All_
>- _User.Read.All_

## 4 Preparations

1. Prepare execution
   - For local execution
     1. Install required modules
     2. Install this module
     3. Create self-signed certificate
   - For Azure execution
     1. Create Azure automation account
        1. Add required modules
        2. Add this module
        3. Enable system-assigned managed identity
     2. Create Azure key vault
        1. Create self-signed certificate
        2. Grant role _Key Vault Secrets User_ to automation account's managed identity
2. Prepare authentication
   1. Create Azure AD application
   2. Add required permissions
   3. Add certificate
3. (optional) Limit permissions
   1. Create Exchange Online application access policy to restrict Azure AD application's _Mail.Send_ permission to intended sender mailbox

## 5 Result

An example report might look like follows:

<p>
    <style>
        table, th, td {
            border: none;
            border-collapse: collapse;
        }
        th, td {
            padding: 5px;
            text-align: left;
            vertical-align: top;
        }
        .gray {
            border-left: 4pt solid darkslategray;
            padding-left: 4pt;
            background-color: lightslategray
        }
        .green {
            border-left: 4pt solid darkgreen;
            padding-left: 4pt;
            background-color: lightgreen
        }
        .yellow {
            border-left: 4pt solid darkgoldenrod;
            padding-left: 4pt;
            background-color: lightgoldenrodyellow
        }
        .red {
            border-left: 4pt solid darkred;
            padding-left: 4pt;
            background-color: lightcoral
        }
    </style>
    <p class=gray>Basic checkup - Products</p>
    <p>Please check license counts for the following product SKUs and reserve additional licenses:</p>
    <p>
        <table>
            <tr>
                <th>License type</th>
                <th>Available count</th>
                <th>Minimum count</th>
                <th>Difference</th>
            </tr>
            <tr>
                <td>Office 365 F3</td>
                <td>9</td>
                <td>10</td>
                <td class=green>10</td>
            </tr>
            <tr>
                <td>Office 365 E1</td>
                <td>40</td>
                <td>50</td>
                <td class=green>10</td>
            </tr>
            <tr>
                <td>Office 365 E3</td>
                <td>30</td>
                <td>50</td>
                <td class=yellow>10</td>
            </tr>
            <tr>
                <td>Office 365 E5</td>
                <td>1</td>
                <td>10</td>
                <td class=red>10</td>
            </tr>
        </table>
    </p>
    <p>The following criteria were used during the checkup:
        <ul>
            <li>Check products with >$SKUIgnoreThreshold total licenses</li>
            <li>Report normal products having both &lt10 licenses and &lt90% of their total licenses available</li>
            <li>Report important products having both &lt50 licenses and &lt90% of their total licenses available</li>
        </ul>
    </p>
</p>

## 6 Links

- [Azure automation account](https://learn.microsoft.com/azure/automation/automation-create-standalone-account)
- [Azure key vault](https://learn.microsoft.com/azure/key-vault/general/quick-create-portal)
- [Azure AD application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Exchange Online application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)
