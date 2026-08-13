# Engineering notes for `SymantecUserManager.jar`

The JAR is a Spring Boot 2.4.4 fat-jar that serves an Angular single-page
front-end (`BOOT-INF/classes/static/*`) and a REST controller layer that
translates each UI action into a SOAP request against the public Symantec /
Broadcom VIP web services.

Source packages inside `BOOT-INF/classes/com/tangynt/`:

```
SymantecUserManager            – Spring Boot entry point
shared/ApiInterface            – SOAP transport (SOAPConnection, PKCS12 keystore)
shared/ApiOperation            – per-op descriptor (name, url, required fields)
shared/RequestProperties       – request DTO (certPath, certPassword, property1..4)
shared/RequestResponse         – response DTO (status, statusMessage, requestId, ...)
controllers/OperationController – lists operations to the UI
controllers/*Controller        – one per SOAP op, holds endpoint + template
```

## Authentication

`ApiInterface.setUpSSL` sets JVM-wide SSL system properties:

- `javax.net.ssl.keyStore` = the PKCS#12 file
- `javax.net.ssl.keyStorePassword` = the file's password
- `javax.net.ssl.keyStoreType` = `PKCS12`

It also installs a permissive `HostnameVerifier`
(`getAllIgnoringHostnameVerifier`) that returns `true` for every hostname –
i.e. it disables hostname verification. The PowerShell module keeps hostname
verification **on** by default and only bypasses it when
`-SkipCertificateCheck` is supplied.

## Request pipeline

For every controller:

1. Load PKCS12 client cert.
2. Take the SOAP template literal from the controller class file.
3. Replace `__request_id__` with a random 12-digit numeric id (Java uses
   `new Random().nextInt(999999)` twice, concatenated).
4. Replace `__cred_id__`, `__cred_2_id__`, `__cred_3_id__`, `__cred_4_id__`
   with property1 .. property4 supplied in the REST body.
5. `SOAPConnectionFactory.newInstance().createConnection().call(msg, url)`.
6. Serialize the response with a JAXP `Transformer`, convert to JSON via
   `org.json.XML.toJSONObject`, extract `Status` / `statusMessage`, return.

The PowerShell module keeps the templates byte-for-byte identical (including
whitespace) and reproduces the same numeric-id shape and property substitution
so the on-wire requests are indistinguishable.

## Operation inventory

| Operation             | Endpoint (host + path)                                                          | Required properties (positional)                          |
| --------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `ActivateToken`       | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `DisableToken`        | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `EnableToken`         | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `GetTokenInformation` | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `UnlockToken`         | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `UnlockSms`           | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `UnlockVoice`         | `https://services-auth.vip.symantec.com/mgmt/soap`                              | authorizerAccountId, tokenId                              |
| `CreateUser`          | `https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7` | onBehalfOfAccountId, userId                            |
| `DeleteUser`          | `https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7` | onBehalfOfAccountId, userId                            |
| `UpdateUser`          | `https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7` | onBehalfOfAccountId, userId, newUserId, newUserStatus  |
| `AddCredential`       | `https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7` | onBehalfOfAccountId, userId, credentialId, credentialType |
| `RemoveCredential`    | `https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7` | onBehalfOfAccountId, userId, credentialId, credentialType |
| `GetUserInfo`         | `https://userservices-auth.vip.symantec.com/vipuserservices/QueryService_1_7`      | onBehalfOfAccountId, userId                             |

## Quirks preserved for compatibility

- The legacy `/mgmt/soap` templates for `ActivateToken`, `DisableToken`,
  `EnableToken` and `UnlockToken` reference an undeclared `vips:` prefix on the
  `AuthorizerAccountId` element. The `GetTokenInformation`, `UnlockSms` and
  `UnlockVoice` templates use `vip:` for the same element. Both are reproduced
  as-is – Symantec ignores the prefix mismatch.
- The Java tool disables hostname verification globally. The PowerShell module
  is stricter by default.
- Java uses two random six-digit ints concatenated for the request id; the
  module does the same.

