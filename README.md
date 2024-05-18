# azure-ad-license-status

[![DevSkim](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/devskim.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/devskim.yml)
[![PSScriptAnalyzer](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/powershell.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/powershell.yml)
[![tfsec](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/tfsec.yml/badge.svg)](https://github.com/DMoenks/azure-ad-license-status/actions/workflows/tfsec.yml)
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/azure-ad-license-status?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/azure-ad-license-status)

The main motivation for this report was to conquer side-effects of manual or semi-automatic license assignments for Microsoft services in Entra ID, e.g. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any overlapping license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The report can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

For further details, please refer to the [manual](https://dmoenks.github.io/azure-ad-license-status/).
