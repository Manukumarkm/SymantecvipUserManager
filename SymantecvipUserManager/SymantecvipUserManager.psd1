@{
    RootModule        = 'SymantecvipUserManager.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1f4a1a1-6a35-4e4f-8b5a-3b0f1a1b2c33'
    Author            = 'manukumarkm'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 SymantecvipUserManager contributors. Licensed under the MIT License.'
    Description       = 'PowerShell alternative to the Symantec VIP User Manager Java tool. Provides bulk-friendly user, credential and token management against the Symantec VIP User Services and legacy Management SOAP APIs using client-certificate (mTLS) authentication.'
    PowerShellVersion = '5.1'
    FormatsToProcess  = @('SymantecvipUserManager.format.ps1xml')
    FunctionsToExport = @(
        'Connect-SymantecVip'
        'Disconnect-SymantecVip'
        'Get-SymantecVipContext'
        'Get-SymantecVipUser'
        'New-SymantecVipUser'
        'Set-SymantecVipUser'
        'Remove-SymantecVipUser'
        'Restore-SymantecVipUser'
        'Add-SymantecVipCredential'
        'Remove-SymantecVipCredential'
        'Get-SymantecVipTokenInformation'
        'Enable-SymantecVipToken'
        'Disable-SymantecVipToken'
        'Approve-SymantecVipToken'
        'Unlock-SymantecVipToken'
        'Invoke-SymantecVipBulkOperation'
        'Test-SymantecVipConnection'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @(
        'Activate-SymantecVipToken'
        'Get-SymantecVipTokenInfo'
        'Update-SymantecVipUser'
    )
    PrivateData       = @{
        PSData = @{
            Tags         = @('Symantec', 'VIP', 'Broadcom', 'MFA', 'SOAP',
                             'UserServices', 'mTLS', 'ClientCertificate',
                             'BulkOperations', 'Windows', 'Linux', 'macOS',
                             'PSEdition_Desktop', 'PSEdition_Core')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = ''
            ReleaseNotes = @'
1.0.0
    - First public release.
    - User CRUD: Get / New / Set / Remove-SymantecVipUser (with -BackupPath /
      -SkipBackup, restore via Restore-SymantecVipUser).
    - Credential binding: Add / Remove-SymantecVipCredential.
    - Legacy token operations: Get / Enable / Disable / Approve / Unlock
      -SymantecVipToken.
    - Bulk-friendly Invoke-SymantecVipBulkOperation with per-row backup.
    - Test-SymantecVipConnection diagnostic cmdlet for mTLS troubleshooting.
'@
        }
    }
}
