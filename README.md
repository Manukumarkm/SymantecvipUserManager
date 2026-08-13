# SymantecvipUserManager – PowerShell alternative to `SymantecUserManager.jar`

This module is a like-for-like PowerShell replacement for the Java based
`SymantecUserManager.jar` bulk operation tool. It calls the same public
Symantec VIP User Services SOAP endpoints with the same request payloads, so
behaviour and responses are identical.

## Contents

- `SymantecvipUserManager/` – the PowerShell module (drop it in `$env:PSModulePath`).
- `examples/` – ready-to-run sample scripts and CSV templates.
- `tests/SymantecvipUserManager.Tests.ps1` – Pester tests that verify the generated SOAP
  bodies match the templates extracted from the JAR.
- `docs/java-engineering.md` – notes on how the JAR was analysed and every
  operation / endpoint it exposes.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.x.
- A valid Symantec VIP client certificate in **PKCS#12** (`.p12` / `.pfx`) form,
  with its private key. This is the same certificate the Java tool asks for.
- Network egress to `services-auth.vip.symantec.com` and
  `userservices-auth.vip.symantec.com` on TCP 443.

## Install

```powershell
# from the repo root
Copy-Item -Recurse .\SymantecvipUserManager "$HOME\Documents\PowerShell\Modules\"
Import-Module SymantecvipUserManager
```

## Quick start

```powershell
Import-Module SymantecvipUserManager

$pw = Read-Host -AsSecureString -Prompt 'PFX password'
Connect-SymantecVip -CertificatePath 'C:\vip\vip-cert.p12' -CertificatePassword $pw

# Single-user calls -----------------------------------------------------------
# The Symantec VIP tenant identifier (a numeric value, sometimes called
# "Jurisdiction Hash", "onBehalfOfAccountId" or "authorizerAccountId" in the
# raw SOAP schema) is passed as -JurisdictionHash on every cmdlet. The old
# names still work as aliases.
$jh = '1234567890'

Get-SymantecVipUser        -JurisdictionHash $jh -UserId 'jdoe'
New-SymantecVipUser        -JurisdictionHash $jh -UserId 'jdoe'
Add-SymantecVipCredential  -JurisdictionHash $jh -UserId 'jdoe' `
                           -CredentialId 'SYMC12345678' -CredentialType 'STANDARD_OTP'

# Token calls (legacy /mgmt/soap endpoint) -----------------------------------
Get-SymantecVipTokenInformation -JurisdictionHash $jh -TokenId 'SYMC12345678'
Enable-SymantecVipToken         -JurisdictionHash $jh -TokenId 'SYMC12345678'
Unlock-SymantecVipToken         -JurisdictionHash $jh -TokenId 'SYMC12345678' -Type SMS

# Bulk from CSV --------------------------------------------------------------
# CSVs should have a JurisdictionHash column; OnBehalfOfAccountId /
# AuthorizerAccountId columns are still accepted (parameter aliases).
Import-Csv .\examples\bulk-delete-users.csv |
    Invoke-SymantecVipBulkOperation -Operation DeleteUser -ThrottleSeconds 0.2 |
    Export-Csv .\delete-results.csv -NoTypeInformation

Disconnect-SymantecVip
```

## Output shape of `Get-SymantecVipUser`

By default the cmdlet returns a flat user object (SOAP envelope noise is
hidden). The full envelope is on the `Raw` property, and `-Raw` returns it
directly if you need `Endpoint`, `HttpStatus`, `RawXml`, ...

```powershell
$u = Get-SymantecVipUser -JurisdictionHash 1234567890 -UserId 'jdoe'

$u.UserId                                # JDOE
$u.UserStatus                            # ACTIVE
$u.UserCreationTime                      # [datetime]
$u.NumBindings                           # 1
$u.CredentialBindings[0].CredentialId    # SYMC12345678
$u.CredentialBindings[0].LastAuthnTime   # [datetime]

# Envelope / RawXml only if you want it:
$u.Raw.RawXml
Get-SymantecVipUser -JurisdictionHash 1234567890 -UserId 'jdoe' -Raw
```

## Cmdlets and their JAR counterparts

| PowerShell cmdlet                | Java controller / SOAP op          | Endpoint host / path                                                     |
| -------------------------------- | ---------------------------------- | ------------------------------------------------------------------------ |
| `Get-SymantecVipUser`            | `GetUserInfoController`            | `userservices-auth.../vipuserservices/QueryService_1_7`                  |
| `New-SymantecVipUser`            | `AddUserController` / CreateUser   | `userservices-auth.../vipuserservices/ManagementService_1_7`             |
| `Set-SymantecVipUser`            | `UpdateUserController`             | `userservices-auth.../vipuserservices/ManagementService_1_7`             |
| `Remove-SymantecVipUser`         | `DeleteUserController`             | `userservices-auth.../vipuserservices/ManagementService_1_7`             |
| `Add-SymantecVipCredential`      | `AddCredentialController`          | `userservices-auth.../vipuserservices/ManagementService_1_7`             |
| `Remove-SymantecVipCredential`   | `RemoveCredentialController`       | `userservices-auth.../vipuserservices/ManagementService_1_7`             |
| `Get-SymantecVipTokenInformation`| `TokenInformationController`       | `services-auth.vip.symantec.com/mgmt/soap`                               |
| `Enable-SymantecVipToken`        | `EnableTokenController`            | `services-auth.vip.symantec.com/mgmt/soap`                               |
| `Disable-SymantecVipToken`       | `DisableTokenController`           | `services-auth.vip.symantec.com/mgmt/soap`                               |
| `Approve-SymantecVipToken`       | `ActivateTokenController`          | `services-auth.vip.symantec.com/mgmt/soap`                               |
| `Unlock-SymantecVipToken`        | `Unlock*Controller` (Token/SMS/Voice) | `services-auth.vip.symantec.com/mgmt/soap`                            |
| `Invoke-SymantecVipBulkOperation`| top-level Angular UI batch flow    | any of the above                                                         |

Aliases: `Activate-SymantecVipToken`, `Update-SymantecVipUser`,
`Get-SymantecVipTokenInfo`.

## Notes on parity with the Java tool

- The SOAP templates are copied verbatim from the `.class` files (including
  quirks like the undeclared `vips:` prefix used by the legacy service on
  Activate/Disable/Enable/UnlockToken – Symantec accepts these unchanged).
- `requestId` is a 12-digit numeric value, mirroring
  `com.tangynt.shared.ApiInterface`.
- Authentication is **client-certificate (mTLS)**. No API key or password is
  ever sent over the wire.
- Responses are parsed into rich PowerShell objects (`StatusCode`,
  `StatusMessage`, `Body`, `RawXml`, ...) so pipelining and CSV export "just
  work".
- Override the endpoints (for dev / test tenants) with
  `Connect-SymantecVip -EndpointOverrides @{ CreateUser = 'https://...' }`.
- `-SkipCertificateCheck` is available for lab use only. Do not enable it in
  production.

## Security

- The private key is loaded into memory only for the duration of the session.
  `Disconnect-SymantecVip` disposes the underlying `X509Certificate2`.
- Never commit `.p12` / `.pfx` files to source control.
- Prefer storing PFX passwords in a secret manager (Secret Management,
  Key Vault, etc.) and passing them as `SecureString` values.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This project is a **community** PowerShell client for the publicly documented
Symantec / Broadcom VIP User Services SOAP API. It is **not** affiliated
with, endorsed by, or sponsored by Broadcom Inc. or Symantec. "Symantec",
"VIP", and related marks are trademarks of their respective owners and are
used here only to describe the third-party service this module interoperates
with.

Test everything against a non-production tenant before running bulk
destructive operations in production.

