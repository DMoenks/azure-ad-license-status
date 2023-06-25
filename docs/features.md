---
layout: default
permalink: /features
---

[1 Introduction](/azure-ad-license-status/) \| [2 Features](/azure-ad-license-status/features) \| [3 Requirements](/azure-ad-license-status/requirements) \| [4 Preparations](/azure-ad-license-status/preparations) \| [5 Examples](/azure-ad-license-status/examples)

# 2 Feature overview

## 2.1 Organization level

### 2.1.1 Basic

&#x2714; Check for license availability based on Azure AD license information

&#x2714; Calculate report importance based on organization's thresholds

### 2.1.2 Advanced

Check for license need based on Azure AD and Office feature information:

&#x2716; _Azure Active Directory Premium P1_ based on applications using application proxy

&#x2714; _Azure Active Directory Premium P1_ based on groups using dynamic user membership

&#x2714; _Azure Active Directory Premium P1_ based on applications using group-based assignment

&#x2714; _Azure Active Directory Premium P1/P2_ based on users covered by Conditional Access

> DISCLAIMER: For performance reasons, Conditional Access coverage calculation only considers two separate 5-day time slots. The first being the most recent full Monday-Friday slot, the second being the same slot two weeks earlier. Although this should result in a mostly accurate coverage calculation, taking at least 4-day time slots into account for each time zone, it will inevitably disregard users with irregular access patterns.

&#x2714; _Azure Active Directory Premium P2_ based on users in scope of Privileged Identity Management

&#x2714; _Defender for Office 365 P1/P2_ based on protected Exchange Online recipients

&#x2714; _Intune Device_ based on devices managed by Intune and used by unlicensed users

## 2.2 User level

### 2.2.1 Basic

&#x2714; Check for Microsoft's mutually exclusive licenses

&#x2716; Check for Microsoft's interchangeable licenses

&#x2714; Check for organization's interchangeable licenses

&#x2714; Calculate optimizable licenses based on available features

&#x2714; Calculate removable licenses based on enabled features

### 2.2.2 Advanced

Check for organization's preferable licenses, based on multiple criteria:

&#x2714;  Whether a user is enabled

&#x2714; When a user was created

&#x2714; When a user was last active

&#x2714; How much OneDrive storage a user has used

&#x2714; How much mailbox storage a user has used and whether the mailbox has an archive

&#x2714; Whether a user has used Windows/Mac/mobile/web versions of Office applications

&#x2716; Whether a user has enrolled a device in Intune
