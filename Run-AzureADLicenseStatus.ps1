using module 'azure-ad-license-status'

param (
    [Parameter(Mandatory = $true)]
    [string]$DirectoryID,
    [Parameter(Mandatory = $true)]
    [string]$ApplicationID,
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionID,
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,
    [Parameter(Mandatory = $true)]
    [string]$CertificateName,
    [Parameter(Mandatory = $true)]
    [string]$SenderAddress,
    [Parameter(Mandatory = $true)]
    [string[]]$RecipientAddresses_normal,
    [string[]]$RecipientAddresses_critical
)

Get-AzureADLicenseStatus -DirectoryID $DirectoryID -ApplicationID $ApplicationID -SubscriptionID $SubscriptionID -KeyVaultName $KeyVaultName -CertificateName $CertificateName -SenderAddress $SenderAddress -RecipientAddresses_normal $RecipientAddresses_normal -RecipientAddresses_critical $RecipientAddresses_critical