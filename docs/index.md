---
layout: default
permalink: /
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Usage](/azure-ad-license-status/usage) \| [6 Examples](/azure-ad-license-status/examples)

[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/azure-ad-license-status?label=PowerShell%20Gallery&logo=powershell&style=flat)](https://www.powershellgallery.com/packages/azure-ad-license-status)

# 1 Introduction

The main motivation for this report was to conquer side-effects of manual or semi-automatic license assignments for Microsoft services in Azure AD, e.g. the combination of group-based licensing with manual group membership management, by regularly reporting both on the amount of available licenses per SKU and any overlapping license assignments per user account. This allows for somewhat easier license management without either implementing a full-fledged software asset management solution or hiring a licensing service provider.

> DISCLAIMER: The report can merely aid in complying with license terms and agreements. It cannot and never will lower or replace the liability to actually comply with any default or individually negotiated license terms and agreements applying to your organization.

The report has surpassed its initially intended purpose in a few directions by now, e.g. by taking a specific set of soft-licensed products into account, i.e. products that only require licenses to be available instead of them being assigned to users, such as Conditional Access. For a full overview, please refer to the list of [features](/azure-ad-license-status/features).
