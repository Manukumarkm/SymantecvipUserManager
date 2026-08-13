#Requires -Version 5.1
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# SymantecvipUserManager module
# Reverse engineered from SymantecUserManager.jar (com.tangynt.*).
# Preserves the exact SOAP envelopes, endpoints and placeholders used by the
# original Java tool so responses are byte-for-byte compatible with what the
# Symantec / Broadcom VIP service expects.
# ---------------------------------------------------------------------------

# region: SOAP templates copied verbatim from the JAR ------------------------
# Each template uses the tokens __request_id__, __cred_id__, __cred_2_id__,
# __cred_3_id__ and __cred_4_id__ exactly as the Java tool does (see
# com.tangynt.shared.ApiInterface).

$script:VipOperations = @{
    ActivateToken       = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice">   <soapenv:Header/>   <soapenv:Body>      <vip:ActivateToken Version="3.0" Id="__request_id__">         <vips:AuthorizerAccountId>__cred_id__</vips:AuthorizerAccountId>         <vip:TokenId>__cred_2_id__</vip:TokenId>      </vip:ActivateToken>   </soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    DisableToken        = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><soapenv:Header/><soapenv:Body><vip:DisableToken Version="3.0" Id="__request_id__"><vips:AuthorizerAccountId>__cred_id__</vips:AuthorizerAccountId><vip:TokenId>__cred_2_id__</vip:TokenId></vip:DisableToken></soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    EnableToken         = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><soapenv:Header/><soapenv:Body><vip:EnableToken Version="3.0" Id="__request_id__"><vips:AuthorizerAccountId>__cred_id__</vips:AuthorizerAccountId><vip:TokenId>__cred_2_id__</vip:TokenId></vip:EnableToken></soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    GetTokenInformation = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><soapenv:Header/><soapenv:Body><vip:GetTokenInformation Version="3.0" Id="__request_id__"><vip:AuthorizerAccountId>__cred_id__</vip:AuthorizerAccountId><vip:TokenId>__cred_2_id__</vip:TokenId></vip:GetTokenInformation></soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    UnlockToken         = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><soapenv:Header/><soapenv:Body><vip:UnlockToken Version="3.0" Id="__request_id__"><vips:AuthorizerAccountId>__cred_id__</vips:AuthorizerAccountId><vip:TokenId>__cred_2_id__</vip:TokenId></vip:UnlockToken></soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    UnlockSmsToken      = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><soapenv:Header/><soapenv:Body><vip:UnlockToken Version="3.0" Id="__request_id__"><vip:AuthorizerAccountId>__cred_id__</vip:AuthorizerAccountId><vip:TokenId type="SMS">__cred_2_id__</vip:TokenId></vip:UnlockToken></soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    UnlockVoiceToken    = @{
        Endpoint = 'https://services-auth.vip.symantec.com/mgmt/soap'
        Template = @'
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.vip.symantec.com/2006/08/vipservice" xmlns:xd="http://www.w3.org/2000/09/xmldsig#"><soapenv:Header/><soapenv:Body><vip:UnlockToken Version="3.0" Id="__request_id__"><vip:AuthorizerAccountId>__cred_id__</vip:AuthorizerAccountId><vip:TokenId type="Voice">__cred_2_id__</vip:TokenId></vip:UnlockToken></soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    CreateUser          = @{
        Endpoint = 'https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7'
        Template = @'
<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>  <soapenv:Body>    <vip:CreateUserRequest xmlns:vip='https://schemas.symantec.com/vip/2011/04/vipuserservices'>      <vip:requestId>__request_id__</vip:requestId>      <vip:onBehalfOfAccountId>__cred_id__</vip:onBehalfOfAccountId>      <vip:userId>__cred_2_id__</vip:userId>    </vip:CreateUserRequest>  </soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    DeleteUser          = @{
        Endpoint = 'https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7'
        Template = @'
<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>  <soapenv:Body>    <vip:DeleteUserRequest xmlns:vip='https://schemas.symantec.com/vip/2011/04/vipuserservices'>      <vip:requestId>__request_id__</vip:requestId>      <vip:onBehalfOfAccountId>__cred_id__</vip:onBehalfOfAccountId>      <vip:userId>__cred_2_id__</vip:userId>    </vip:DeleteUserRequest>  </soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
    UpdateUser          = @{
        Endpoint = 'https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7'
        Template = @'
<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>
  <soapenv:Body>
    <vip:UpdateUserRequest xmlns:vip='https://schemas.symantec.com/vip/2011/04/vipuserservices'>
      <vip:requestId>__request_id__</vip:requestId>
      <vip:onBehalfOfAccountId>__cred_id__</vip:onBehalfOfAccountId>
      <vip:userId>__cred_2_id__</vip:userId>
      <vip:newUserId>__cred_3_id__</vip:newUserId>
      <vip:newUserStatus>__cred_4_id__</vip:newUserStatus>
    </vip:UpdateUserRequest>
  </soapenv:Body>
</soapenv:Envelope>
'@
        Required = 4
    }
    AddCredential       = @{
        Endpoint = 'https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7'
        Template = @'
<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>  <soapenv:Body>    <vip:AddCredentialRequest xmlns:vip='https://schemas.symantec.com/vip/2011/04/vipuserservices'>      <vip:requestId>__request_id__</vip:requestId>      <vip:onBehalfOfAccountId>__cred_id__</vip:onBehalfOfAccountId>      <vip:userId>__cred_2_id__</vip:userId>      <vip:credentialDetail>        <vip:credentialId>__cred_3_id__</vip:credentialId>        <vip:credentialType>__cred_4_id__</vip:credentialType>      </vip:credentialDetail>    </vip:AddCredentialRequest>  </soapenv:Body></soapenv:Envelope>
'@
        Required = 4
    }
    RemoveCredential    = @{
        Endpoint = 'https://userservices-auth.vip.symantec.com/vipuserservices/ManagementService_1_7'
        Template = @'
<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>  <soapenv:Body>    <vip:RemoveCredentialRequest xmlns:vip='https://schemas.symantec.com/vip/2011/04/vipuserservices'>      <vip:requestId>__request_id__</vip:requestId>      <vip:onBehalfOfAccountId>__cred_id__</vip:onBehalfOfAccountId>      <vip:userId>__cred_2_id__</vip:userId>      <vip:credentialId>__cred_3_id__</vip:credentialId>      <vip:credentialType>__cred_4_id__</vip:credentialType>    </vip:RemoveCredentialRequest>  </soapenv:Body></soapenv:Envelope>
'@
        Required = 4
    }
    GetUserInfo         = @{
        Endpoint = 'https://userservices-auth.vip.symantec.com/vipuserservices/QueryService_1_7'
        Template = @'
<soapenv:Envelope xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>  <soapenv:Body>    <vip:GetUserInfoRequest xmlns:vip='https://schemas.symantec.com/vip/2011/04/vipuserservices'>      <vip:requestId>__request_id__</vip:requestId>      <vip:onBehalfOfAccountId>__cred_id__</vip:onBehalfOfAccountId>      <vip:userId>__cred_2_id__</vip:userId>    </vip:GetUserInfoRequest>  </soapenv:Body></soapenv:Envelope>
'@
        Required = 2
    }
}

# endregion ------------------------------------------------------------------

# Module-scope session state (mirrors the JAR's per-request cert loading).
$script:VipSession = $null

# region: private helpers ----------------------------------------------------

function Get-VipRequestId {
    # 12-digit numeric request id, same shape as the Java tool.
    ('{0}{1}' -f (Get-Random -Minimum 100000 -Maximum 999999), (Get-Random -Minimum 100000 -Maximum 999999))
}

function Assert-VipSession {
    if (-not $script:VipSession -or -not $script:VipSession.Certificate) {
        throw "No Symantec VIP session. Call Connect-SymantecVip first."
    }
}

function Resolve-VipEndpoint {
    param(
        [Parameter(Mandatory)] [string]$Operation,
        [string]$Endpoint
    )
    if ($Endpoint) { return $Endpoint }
    if ($script:VipSession -and $script:VipSession.EndpointOverrides -and
        $script:VipSession.EndpointOverrides.ContainsKey($Operation)) {
        return $script:VipSession.EndpointOverrides[$Operation]
    }
    return $script:VipOperations[$Operation].Endpoint
}

function ConvertTo-VipHashtable {
    param([Parameter(Mandatory)] [System.Xml.XmlNode]$Node)

    $obj = [ordered]@{}
    foreach ($attr in $Node.Attributes) {
        $obj["@$($attr.LocalName)"] = $attr.Value
    }
    foreach ($child in $Node.ChildNodes) {
        switch ($child.NodeType) {
            'Text'  { return $child.Value }
            'CDATA' { return $child.Value }
            'Element' {
                $childValue = ConvertTo-VipHashtable -Node $child
                $name = $child.LocalName
                if ($obj.Contains($name)) {
                    $existing = $obj[$name]
                    if ($existing -is [System.Collections.Generic.List[object]]) {
                        [void]$existing.Add($childValue)
                    } else {
                        # Promote fixed-size arrays / scalars to a growable list
                        $list = [System.Collections.Generic.List[object]]::new()
                        if ($existing -is [System.Collections.IEnumerable] -and $existing -isnot [string]) {
                            foreach ($e in $existing) { [void]$list.Add($e) }
                        } else {
                            [void]$list.Add($existing)
                        }
                        [void]$list.Add($childValue)
                        $obj[$name] = $list
                    }
                } else {
                    $obj[$name] = $childValue
                }
            }
        }
    }
    if ($obj.Count -eq 0) { return $null }
    return [pscustomobject]$obj
}

function ConvertFrom-VipSoapResponse {
    param(
        [Parameter(Mandatory)] [string]$Xml,
        [Parameter(Mandatory)] [string]$Endpoint,
        [Parameter(Mandatory)] [string]$RequestId,
        [Parameter(Mandatory)] [int]$HttpStatus
    )

    [xml]$doc = $Xml
    $body = $null
    $bodyNode = $doc.GetElementsByTagName('Body', 'http://schemas.xmlsoap.org/soap/envelope/') |
                Select-Object -First 1
    if ($bodyNode -and $bodyNode.HasChildNodes) {
        $inner = $bodyNode.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | Select-Object -First 1
        if ($inner) { $body = ConvertTo-VipHashtable -Node $inner }
    }

    $status = $null; $statusMessage = $null; $respRequestId = $null
    # Try modern vipuserservices response
    foreach ($tag in 'status', 'statusMessage', 'requestId', 'Status', 'StatusMessage', 'RequestId') {
        $node = $doc.GetElementsByTagName($tag) | Select-Object -First 1
        if ($node) {
            switch -Regex ($tag) {
                '^status$|^Status$'               { if (-not $status)         { $status = $node.InnerText } }
                '^statusMessage$|^StatusMessage$' { if (-not $statusMessage)  { $statusMessage = $node.InnerText } }
                '^requestId$|^RequestId$'         { if (-not $respRequestId)  { $respRequestId = $node.InnerText } }
            }
        }
    }

    [pscustomobject]@{
        Endpoint       = $Endpoint
        HttpStatus     = $HttpStatus
        StatusCode     = $status
        StatusMessage  = $statusMessage
        RequestId      = $RequestId
        ResponseId     = $respRequestId
        Body           = $body
        RawXml         = $Xml
        Success        = ($status -eq '0000' -or $status -eq '6009')
        Timestamp      = (Get-Date)
    }
}

function ConvertTo-VipDateTime {
    param([string]$Value)
    if (-not $Value) { return $null }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) {
        return $dt
    }
    return $Value
}

function ConvertTo-VipUserObject {
    <#
        Projects a GetUserInfoResponse (as returned by Invoke-VipSoapRequest)
        into a flat, user-facing object. Handles zero, one or many credential
        bindings. Original SOAP envelope is preserved on the .Raw property.
    #>
    param(
        [Parameter(Mandatory)] $Response,
        [string]$JurisdictionHash
    )

    $body = $Response.Body
    $safe = { param($node, $name) if ($node -and $node.PSObject.Properties[$name]) { $node.$name } }

    $bindings = @()
    if ($body -and ($body.PSObject.Properties['credentialBindingDetail'])) {
        $raw = $body.credentialBindingDetail
        if ($raw -is [System.Collections.IList]) { $items = $raw } else { $items = @($raw) }
        foreach ($c in $items) {
            if (-not $c) { continue }
            $bind = & $safe $c 'bindingDetail'
            $bindings += [pscustomobject]@{
                CredentialId     = & $safe $c 'credentialId'
                CredentialType   = & $safe $c 'credentialType'
                CredentialStatus = & $safe $c 'credentialStatus'
                BindStatus       = & $safe $bind 'bindStatus'
                FriendlyName     = & $safe $bind 'friendlyName'
                LastBindTime     = ConvertTo-VipDateTime (& $safe $bind 'lastBindTime')
                LastAuthnTime    = ConvertTo-VipDateTime (& $safe $bind 'lastAuthnTime')
                LastAuthnId      = & $safe $bind 'lastAuthnId'
            }
        }
    }

    $numBindingsRaw = & $safe $body 'numBindings'
    $obj = [pscustomobject]@{
        JurisdictionHash    = $JurisdictionHash
        UserId              = & $safe $body 'userId'
        UserStatus          = & $safe $body 'userStatus'
        UserCreationTime    = ConvertTo-VipDateTime (& $safe $body 'userCreationTime')
        NumBindings         = if ($numBindingsRaw) { [int]$numBindingsRaw } else { 0 }
        CredentialBindings  = $bindings
        Status              = & $safe $body 'status'
        StatusMessage       = & $safe $body 'statusMessage'
        RequestId           = & $safe $body 'requestId'
        Success             = [bool]$Response.Success
        Raw                 = $Response
    }
    $obj.PSObject.TypeNames.Insert(0, 'SymantecVip.User')
    $obj
}

function ConvertTo-VipActionResult {
    <#
        Projects a write-op SOAP response (CreateUser, DeleteUser, UpdateUser,
        Add/RemoveCredential, Enable/Disable/Activate/Unlock token, ...) into a
        common, envelope-free result object. Target-specific fields (UserId,
        TokenId, ...) are attached via -Target so each cmdlet's result shows
        the identifiers relevant to that operation.
    #>
    param(
        [Parameter(Mandatory)] $Response,
        [Parameter(Mandatory)] [string]$Operation,
        [string]$JurisdictionHash,
        [System.Collections.IDictionary]$Target
    )
    $get = { param($name, $default) if ($Response.PSObject.Properties[$name]) { $Response.$name } else { $default } }
    $props = [ordered]@{
        Operation        = $Operation
        JurisdictionHash = $JurisdictionHash
    }
    if ($Target) {
        foreach ($k in $Target.Keys) { $props[$k] = $Target[$k] }
    }
    $props.StatusCode    = & $get 'StatusCode'    $null
    $props.StatusMessage = & $get 'StatusMessage' $null
    $props.Success       = [bool](& $get 'Success' $false)
    $props.RequestId     = & $get 'RequestId'     $null
    $props.Timestamp     = & $get 'Timestamp'     (Get-Date)
    $props.Raw           = $Response
    $out = [pscustomobject]$props
    $out.PSObject.TypeNames.Insert(0, 'SymantecVip.ActionResult')
    $out
}

function Export-VipUserBackup {
    <#
        Fetches a user's current state via GetUserInfo and writes one CSV
        (one row per credential binding, or one blank-cred row if the user has
        none). Returns the resolved absolute path to the file it wrote.
        Throws if the user cannot be fetched or has a non-success status,
        so callers can abort the destructive action safely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$JurisdictionHash,
        [Parameter(Mandatory)] [string]$UserId,
        [Parameter(Mandatory)] [string]$Directory
    )
    $u = Get-SymantecVipUser -JurisdictionHash $JurisdictionHash -UserId $UserId
    if (-not $u.Success) {
        throw "GetUserInfo for '$UserId' returned status $($u.Status) '$($u.StatusMessage)' - refusing to back up an unreadable user."
    }

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        [void](New-Item -ItemType Directory -Force -Path $Directory -ErrorAction Stop)
    }
    $dir = (Resolve-Path -LiteralPath $Directory).ProviderPath

    $safeId = ($UserId -replace '[^\w.\-]', '_')
    $file   = Join-Path $dir ("{0}-{1}.csv" -f $safeId, (Get-Date -Format 'yyyyMMdd-HHmmss'))

    $rows = @()
    $baseFields = [ordered]@{
        JurisdictionHash = $JurisdictionHash
        UserId           = $u.UserId
        UserStatus       = $u.UserStatus
        UserCreationTime = $u.UserCreationTime
        NumBindings      = $u.NumBindings
        BackedUpAt       = (Get-Date).ToString('o')
    }
    if ($u.CredentialBindings -and @($u.CredentialBindings).Count -gt 0) {
        foreach ($c in $u.CredentialBindings) {
            $row = [ordered]@{}
            foreach ($k in $baseFields.Keys) { $row[$k] = $baseFields[$k] }
            $row.CredentialId     = $c.CredentialId
            $row.CredentialType   = $c.CredentialType
            $row.CredentialStatus = $c.CredentialStatus
            $row.BindStatus       = $c.BindStatus
            $row.FriendlyName     = $c.FriendlyName
            $row.LastBindTime     = $c.LastBindTime
            $row.LastAuthnTime    = $c.LastAuthnTime
            $row.LastAuthnId      = $c.LastAuthnId
            $rows += [pscustomobject]$row
        }
    } else {
        $row = [ordered]@{}
        foreach ($k in $baseFields.Keys) { $row[$k] = $baseFields[$k] }
        foreach ($k in 'CredentialId','CredentialType','CredentialStatus','BindStatus','FriendlyName','LastBindTime','LastAuthnTime','LastAuthnId') {
            $row[$k] = $null
        }
        $rows += [pscustomobject]$row
    }

    $rows | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8
    $file
}

function New-VipSoapBody {
    <#
        Renders a SOAP body from the templates extracted from the JAR by
        substituting __request_id__ and the __cred_*_id__ placeholders. Exposed
        for testability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Operation,
        [Parameter(Mandatory)] [string[]]$Properties,
        [string]$RequestId
    )
    $spec = $script:VipOperations[$Operation]
    if (-not $spec) { throw "Unknown operation '$Operation'." }
    if ($Properties.Count -lt $spec.Required) {
        throw "Operation '$Operation' requires $($spec.Required) properties, only $($Properties.Count) supplied."
    }
    if (-not $RequestId) { $RequestId = Get-VipRequestId }

    $body = $spec.Template
    $body = $body -replace '__request_id__', $RequestId
    for ($i = 0; $i -lt $Properties.Count; $i++) {
        $token = if ($i -eq 0) { '__cred_id__' } else { '__cred_{0}_id__' -f ($i + 1) }
        $body = $body.Replace($token, [System.Security.SecurityElement]::Escape([string]$Properties[$i]))
    }
    [pscustomobject]@{
        Operation = $Operation
        RequestId = $RequestId
        Endpoint  = $spec.Endpoint
        Body      = $body
    }
}

function Invoke-VipSoapRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Operation,
        [Parameter(Mandatory)] [string[]]$Properties,
        [string]$Endpoint,
        [string]$SoapAction = ''
    )

    Assert-VipSession
    $url       = Resolve-VipEndpoint -Operation $Operation -Endpoint $Endpoint
    $rendered  = New-VipSoapBody -Operation $Operation -Properties $Properties
    $requestId = $rendered.RequestId
    $body      = $rendered.Body

    Write-Verbose "[$Operation] POST $url (requestId=$requestId)"
    Write-Debug   "[$Operation] Request body: $body"

    # Belt-and-suspenders TLS 1.2/1.3 for Windows PowerShell 5.1 (WinPS defaults
    # to TLS 1.0/1.1 which Symantec VIP rejects, producing an opaque
    # "SSL connection could not be established" error).
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.ServicePointManager]::SecurityProtocol -bor
            [System.Net.SecurityProtocolType]::Tls12
    } catch { }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    try {
        $tls12 = [System.Security.Authentication.SslProtocols]::Tls12
        $tls13 = [System.Security.Authentication.SslProtocols]::Tls13
        $handler.SslProtocols = $tls12 -bor $tls13
    } catch {
        $handler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
    }
    [void]$handler.ClientCertificates.Add($script:VipSession.Certificate)
    if ($script:VipSession.SkipCertificateCheck) {
        $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    }
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($script:VipSession.TimeoutSeconds)

    try {
        $content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, 'text/xml')
        if ($SoapAction) {
            [void]$content.Headers.TryAddWithoutValidation('SOAPAction', $SoapAction)
        }
        try {
            $response = $client.PostAsync($url, $content).GetAwaiter().GetResult()
        } catch [System.AggregateException] {
            throw $_.Exception.Flatten().InnerException
        } catch {
            $ex = $_.Exception
            while ($ex.InnerException) { $ex = $ex.InnerException }
            throw $ex
        }
        $respText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $httpStatus = [int]$response.StatusCode

        Write-Debug "[$Operation] HTTP $httpStatus Response: $respText"
        return ConvertFrom-VipSoapResponse -Xml $respText -Endpoint $url `
                                           -RequestId $requestId -HttpStatus $httpStatus
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

# endregion ------------------------------------------------------------------

# region: public functions ---------------------------------------------------

function Connect-SymantecVip {
    <#
    .SYNOPSIS
        Opens a Symantec VIP session using a PKCS#12 client certificate.
    .DESCRIPTION
        Loads the client certificate that will be presented for mTLS on every
        subsequent call. Certificates are held in memory only. Use
        Disconnect-SymantecVip to clear the session.

        The Java tool uses a PKCS12 keystore (see com.tangynt.shared.ApiInterface
        setUpSSL). This function accepts a .p12 / .pfx file at -CertificatePath
        with -CertificatePassword, or a pre-loaded X509Certificate2 via
        -Certificate.
    .EXAMPLE
        $pw = Read-Host -AsSecureString -Prompt 'PFX password'
        Connect-SymantecVip -CertificatePath 'C:\vip\vip-cert.p12' -CertificatePassword $pw
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$CertificatePath,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [securestring]$CertificatePassword,

        [Parameter(Mandatory, ParameterSetName = 'Cert')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [hashtable]$EndpointOverrides,

        [int]$TimeoutSeconds = 60,

        [switch]$SkipCertificateCheck
    )

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        # On Windows SChannel cannot consume EphemeralKeySet private keys for
        # client-cert TLS (SEC_E_UNKNOWN_CREDENTIALS). Persist the key on
        # Windows; only fall back to Ephemeral on non-Windows.
        $isWindows = if ($PSVersionTable.PSEdition -eq 'Desktop') { $true } else { [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows) }
        $baseFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
                     [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        $flagOptions = @()
        $flagOptions += ($baseFlags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
        $flagOptions += $baseFlags
        if (-not $isWindows) {
            try {
                $ephem = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
                $flagOptions += ($baseFlags -bor $ephem)
            } catch { }
        }

        $pfxPath = (Resolve-Path -LiteralPath $CertificatePath).ProviderPath
        $lastError = $null
        foreach ($flags in $flagOptions) {
            try {
                $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    $pfxPath, $CertificatePassword, $flags)
                $lastError = $null
                break
            } catch {
                $lastError = $_.Exception
            }
        }
        if ($lastError) {
            throw "Could not load PKCS#12 certificate '$CertificatePath': $($lastError.Message)"
        }
    }

    if (-not $Certificate.HasPrivateKey) {
        throw "Certificate '$($Certificate.Subject)' has no private key; mTLS to Symantec VIP will fail."
    }

    # Verify the private key is actually usable in this process. On some hosts
    # the PFX loads but the CNG/CAPI key handle is unreachable, which shows up
    # later as a generic "SSL connection could not be established" error.
    try {
        $null = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    } catch {
        Write-Warning "Certificate private key present but not accessible: $($_.Exception.Message). The TLS handshake will likely fail."
    }

    $script:VipSession = [pscustomobject]@{
        Certificate          = $Certificate
        EndpointOverrides    = $EndpointOverrides
        TimeoutSeconds       = $TimeoutSeconds
        SkipCertificateCheck = [bool]$SkipCertificateCheck
        ConnectedAt          = Get-Date
        Subject              = $Certificate.Subject
        Thumbprint           = $Certificate.Thumbprint
        Expires              = $Certificate.NotAfter
    }

    Write-Verbose "Symantec VIP session opened with certificate $($Certificate.Subject) (thumb $($Certificate.Thumbprint), expires $($Certificate.NotAfter))."
    [pscustomobject]@{
        Subject     = $Certificate.Subject
        Thumbprint  = $Certificate.Thumbprint
        Expires     = $Certificate.NotAfter
        ConnectedAt = $script:VipSession.ConnectedAt
    }
}

function Disconnect-SymantecVip {
    <#
    .SYNOPSIS
        Clears the in-memory Symantec VIP session and deletes the persisted
        private key container that Connect-SymantecVip created for SChannel.
    #>
    [CmdletBinding()]
    param()
    if ($script:VipSession -and $script:VipSession.Certificate) {
        $cert = $script:VipSession.Certificate
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($rsa -and $rsa.Key -and $rsa.Key.UniqueName) {
                try { $rsa.Key.Delete() } catch { }
            }
            if ($rsa) { $rsa.Dispose() }
        } catch { }
        try { $cert.Dispose() } catch { }
    }
    $script:VipSession = $null
    Write-Verbose "Symantec VIP session closed."
}

function Get-SymantecVipContext {
    <#
    .SYNOPSIS
        Returns metadata about the current VIP session (no private key material).
    #>
    [CmdletBinding()]
    param()
    if (-not $script:VipSession) { return }
    $script:VipSession | Select-Object Subject, Thumbprint, Expires, ConnectedAt,
                                       TimeoutSeconds, SkipCertificateCheck, EndpointOverrides
}

function Get-SymantecVipUser {
    <#
    .SYNOPSIS
        Calls GetUserInfo on the VIP QueryService and returns a friendly user
        object. Use -Raw for the full SOAP envelope response.
    .PARAMETER JurisdictionHash
        The Symantec VIP tenant / jurisdiction hash (numeric). Also known as
        onBehalfOfAccountId / authorizerAccountId in the raw SOAP schema.
    .PARAMETER UserId
        The VIP userId to look up.
    .PARAMETER Raw
        Return the untouched SOAP envelope object (Endpoint, HttpStatus,
        RawXml, ...) instead of the flattened user object.
    .OUTPUTS
        PSCustomObject with JurisdictionHash, UserId, UserStatus,
        UserCreationTime, NumBindings, CredentialBindings,
        Status, StatusMessage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)]
        [string]$UserId,
        [switch]$Raw
    )
    process {
        $resp = Invoke-VipSoapRequest -Operation GetUserInfo -Properties $JurisdictionHash, $UserId
        if ($Raw) { return $resp }
        ConvertTo-VipUserObject -Response $resp -JurisdictionHash $JurisdictionHash
    }
}

function New-SymantecVipUser {
    <#
    .SYNOPSIS
        Calls CreateUser on the VIP ManagementService, optionally followed by
        AddCredential in the same call. Returns one SymantecVip.ActionResult
        per SOAP step (two objects when a credential is bound); use -Raw for
        the full SOAP envelopes.
    .PARAMETER CredentialId
        Optional. If provided together with -CredentialType, binds that
        credential to the user immediately after CreateUser succeeds.
    .PARAMETER CredentialType
        Required whenever -CredentialId is used. Same enum as
        Add-SymantecVipCredential.
    .EXAMPLE
        New-SymantecVipUser -JurisdictionHash $jh -UserId 'jdoe'
    .EXAMPLE
        New-SymantecVipUser -JurisdictionHash $jh -UserId 'jdoe' `
                            -CredentialId 'VSST12345678' -CredentialType STANDARD_OTP
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium',
                   DefaultParameterSetName = 'User')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,

        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)]
        [string]$UserId,

        [Parameter(Mandatory, ParameterSetName = 'UserWithCredential', ValueFromPipelineByPropertyName)]
        [string]$CredentialId,

        [Parameter(Mandatory, ParameterSetName = 'UserWithCredential', ValueFromPipelineByPropertyName)]
        [ValidateSet('STANDARD_OTP','SMS_OTP','VOICE_OTP','SERVICE_OTP','CERTIFICATE')]
        [string]$CredentialType,

        [switch]$Raw
    )
    process {
        $withCred = $PSCmdlet.ParameterSetName -eq 'UserWithCredential'
        $action   = if ($withCred) { "CreateUser + AddCredential ($CredentialType)" } else { 'CreateUser' }
        if (-not $PSCmdlet.ShouldProcess("$UserId (tenant $JurisdictionHash)", $action)) { return }

        $resp = Invoke-VipSoapRequest -Operation CreateUser -Properties $JurisdictionHash, $UserId
        if ($Raw) { $resp } else {
            ConvertTo-VipActionResult -Response $resp -Operation CreateUser `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{ UserId = $UserId })
        }

        if (-not $withCred) { return }
        if (-not $resp.Success) {
            Write-Warning "Skipping AddCredential for '$UserId' because CreateUser failed (StatusCode $($resp.StatusCode) $($resp.StatusMessage))."
            return
        }
        Add-SymantecVipCredential -JurisdictionHash $JurisdictionHash -UserId $UserId `
            -CredentialId $CredentialId -CredentialType $CredentialType `
            -Confirm:$false -Raw:$Raw
    }
}

function Set-SymantecVipUser {
    <#
    .SYNOPSIS
        Calls UpdateUser on the VIP ManagementService.
    .DESCRIPTION
        UpdateUser can rename a userId and/or change its status. Provide the
        current userId in -UserId, then the target values in -NewUserId and
        -NewUserStatus. Valid VIP user statuses include ENABLED and DISABLED.
        Returns a friendly SymantecVip.ActionResult; use -Raw for the full
        SOAP envelope.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string]$UserId,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string]$NewUserId,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [ValidateSet('ENABLED', 'DISABLED')] [string]$NewUserStatus,
        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ShouldProcess("$UserId -> $NewUserId ($NewUserStatus)", 'UpdateUser')) {
            $resp = Invoke-VipSoapRequest -Operation UpdateUser `
                -Properties $JurisdictionHash, $UserId, $NewUserId, $NewUserStatus
            if ($Raw) { return $resp }
            ConvertTo-VipActionResult -Response $resp -Operation UpdateUser `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{
                    UserId        = $UserId
                    NewUserId     = $NewUserId
                    NewUserStatus = $NewUserStatus
                })
        }
    }
}

function Remove-SymantecVipUser {
    <#
    .SYNOPSIS
        Calls DeleteUser on the VIP ManagementService. Returns a friendly
        SymantecVip.ActionResult; use -Raw for the full SOAP envelope.
    .DESCRIPTION
        The user is always backed up to CSV before deletion so the whole
        record (user + all credential bindings) can be restored later with
        Restore-SymantecVipUser. Use -BackupPath to control where the CSV
        is written (defaults to '.\vip-user-backups' under the current
        directory). Use -SkipBackup to explicitly bypass the safety net
        and delete without a snapshot.
    .PARAMETER BackupPath
        Directory that the pre-deletion snapshot is written into. Ignored
        when -SkipBackup is present. Default: '.\vip-user-backups'.
    .PARAMETER SkipBackup
        Skip the pre-deletion snapshot entirely. Use only when you already
        have a backup or the user has no bound credentials worth preserving.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)] [string]$UserId,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$BackupPath = '.\vip-user-backups',
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$SkipBackup,
        [switch]$Raw
    )
    process {
        if ($SkipBackup -and $PSBoundParameters.ContainsKey('BackupPath')) {
            Write-Warning "-BackupPath is ignored when -SkipBackup is present."
        }

        $shouldProcessDesc = if ($SkipBackup) {
            "$UserId (tenant $JurisdictionHash) [no backup]"
        } else {
            "$UserId (tenant $JurisdictionHash) [backup -> $BackupPath]"
        }
        if (-not $PSCmdlet.ShouldProcess($shouldProcessDesc, 'DeleteUser')) { return }

        $backupFile = $null
        if (-not $SkipBackup) {
            try {
                $backupFile = Export-VipUserBackup -JurisdictionHash $JurisdictionHash `
                                                  -UserId $UserId -Directory $BackupPath
                Write-Verbose "Backed up '$UserId' to '$backupFile' before deletion."
            } catch {
                Write-Warning "Aborting DeleteUser for '$UserId': backup failed - $($_.Exception.Message). Pass -SkipBackup to delete anyway."
                # Emit a real result so bulk callers see the skipped row instead
                # of crashing on $null; type-tagged as SymantecVip.ActionResult
                # so the table view renders it consistently.
                $abort = [pscustomobject]@{
                    Operation        = 'DeleteUser'
                    JurisdictionHash = $JurisdictionHash
                    UserId           = $UserId
                    StatusCode       = 'BACKUP_ABORTED'
                    StatusMessage    = "Backup failed: $($_.Exception.Message.TrimEnd('.'))"
                    Success          = $false
                    RequestId        = $null
                    Timestamp        = (Get-Date)
                    Raw              = $null
                    BackupFile       = $null
                }
                $abort.PSObject.TypeNames.Insert(0, 'SymantecVip.ActionResult')
                return $abort
            }
        }

        $resp = Invoke-VipSoapRequest -Operation DeleteUser -Properties $JurisdictionHash, $UserId
        if ($Raw) {
            if ($backupFile) { $resp | Add-Member -NotePropertyName BackupFile -NotePropertyValue $backupFile -Force }
            return $resp
        }
        $result = ConvertTo-VipActionResult -Response $resp -Operation DeleteUser `
            -JurisdictionHash $JurisdictionHash -Target ([ordered]@{ UserId = $UserId })
        if ($backupFile) {
            $result | Add-Member -NotePropertyName BackupFile -NotePropertyValue $backupFile -Force
        }
        $result
    }
}

function Restore-SymantecVipUser {
    <#
    .SYNOPSIS
        Rebuilds a VIP user (and re-binds their credentials) from a backup CSV
        produced by Remove-SymantecVipUser -BackupPath / Invoke-SymantecVipBulkOperation.
    .DESCRIPTION
        Reads the CSV, calls CreateUser once, then AddCredential for each row
        that has a CredentialId / CredentialType. Returns one
        SymantecVip.ActionResult per SOAP step so the restore trail is visible.
    .PARAMETER Path
        A single backup CSV file (as produced by the backup helper).
    .PARAMETER Directory
        A directory containing backup CSVs; every *.csv inside is restored.
    .PARAMETER JurisdictionHash
        Overrides the tenant recorded in the CSV. Useful when restoring into
        a different tenant than the one the user was backed up from.
    .EXAMPLE
        Restore-SymantecVipUser -Path .\backups\jdoe-20260101-000000.csv
    .EXAMPLE
        Restore-SymantecVipUser -Directory .\backups -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium',
                   DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'File',
                   ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName', 'PSPath')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Directory')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
        [string]$Directory,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,

        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Directory') {
            $files = Get-ChildItem -LiteralPath $Directory -Filter *.csv -File | Sort-Object Name
            foreach ($f in $files) {
                Restore-SymantecVipUser -Path $f.FullName -JurisdictionHash $JurisdictionHash -Raw:$Raw
            }
            return
        }

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Backup file '$Path' not found."
        }
        $rows = @(Import-Csv -LiteralPath $Path)
        if ($rows.Count -eq 0) {
            Write-Warning "Backup file '$Path' has no rows; skipping."
            return
        }
        $u   = $rows[0]
        $jh  = if ($JurisdictionHash) { $JurisdictionHash } else { $u.JurisdictionHash }
        $uid = $u.UserId
        if (-not $jh -or -not $uid) {
            throw "Backup file '$Path' is missing JurisdictionHash or UserId."
        }

        $credRows = @($rows | Where-Object { $_.CredentialId -and $_.CredentialType })
        $action = if ($credRows.Count -gt 0) {
            "CreateUser + $($credRows.Count) x AddCredential from '$([IO.Path]::GetFileName($Path))'"
        } else {
            "CreateUser from '$([IO.Path]::GetFileName($Path))'"
        }
        if (-not $PSCmdlet.ShouldProcess("$uid (tenant $jh)", $action)) { return }

        $createResp = Invoke-VipSoapRequest -Operation CreateUser -Properties $jh, $uid
        if ($Raw) { $createResp } else {
            ConvertTo-VipActionResult -Response $createResp -Operation CreateUser `
                -JurisdictionHash $jh -Target ([ordered]@{ UserId = $uid; RestoredFrom = $Path })
        }

        if (-not $createResp.Success) {
            Write-Warning "CreateUser failed for '$uid' (StatusCode $($createResp.StatusCode) $($createResp.StatusMessage)); skipping credential restore."
            return
        }

        foreach ($row in $credRows) {
            Add-SymantecVipCredential -JurisdictionHash $jh -UserId $uid `
                -CredentialId $row.CredentialId -CredentialType $row.CredentialType `
                -Confirm:$false -Raw:$Raw
        }
    }
}

function Add-SymantecVipCredential {
    <#
    .SYNOPSIS
        Binds a credential to a VIP user. Returns a friendly
        SymantecVip.ActionResult; use -Raw for the full SOAP envelope.
    .PARAMETER CredentialType
        VIP User Services credentialType enum. Must be one of:
          STANDARD_OTP  - VIP hardware / VIP Access soft tokens (VSST*, SYMC*)
          SMS_OTP       - SMS-delivered OTP
          VOICE_OTP     - Voice-call OTP
          SERVICE_OTP   - Service-provisioned OTP
          CERTIFICATE   - Client certificate
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string]$UserId,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string]$CredentialId,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('STANDARD_OTP','SMS_OTP','VOICE_OTP','SERVICE_OTP','CERTIFICATE')]
        [string]$CredentialType,
        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ShouldProcess("$UserId <- $CredentialId ($CredentialType)", 'AddCredential')) {
            $resp = Invoke-VipSoapRequest -Operation AddCredential `
                -Properties $JurisdictionHash, $UserId, $CredentialId, $CredentialType
            if ($Raw) { return $resp }
            ConvertTo-VipActionResult -Response $resp -Operation AddCredential `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{
                    UserId         = $UserId
                    CredentialId   = $CredentialId
                    CredentialType = $CredentialType
                })
        }
    }
}

function Remove-SymantecVipCredential {
    <#
    .SYNOPSIS
        Unbinds a credential from a VIP user. Returns a friendly
        SymantecVip.ActionResult; use -Raw for the full SOAP envelope.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string]$UserId,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)] [string]$CredentialId,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('STANDARD_OTP','SMS_OTP','VOICE_OTP','SERVICE_OTP','CERTIFICATE')]
        [string]$CredentialType,
        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ShouldProcess("$UserId x $CredentialId ($CredentialType)", 'RemoveCredential')) {
            $resp = Invoke-VipSoapRequest -Operation RemoveCredential `
                -Properties $JurisdictionHash, $UserId, $CredentialId, $CredentialType
            if ($Raw) { return $resp }
            ConvertTo-VipActionResult -Response $resp -Operation RemoveCredential `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{
                    UserId         = $UserId
                    CredentialId   = $CredentialId
                    CredentialType = $CredentialType
                })
        }
    }
}

function Get-SymantecVipTokenInformation {
    <#
    .SYNOPSIS
        Retrieves token metadata via the legacy VIP management SOAP endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)]
        [string]$TokenId
    )
    process {
        Invoke-VipSoapRequest -Operation GetTokenInformation `
            -Properties $JurisdictionHash, $TokenId
    }
}

function Enable-SymantecVipToken {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)] [string]$TokenId,
        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ShouldProcess($TokenId, 'EnableToken')) {
            $resp = Invoke-VipSoapRequest -Operation EnableToken -Properties $JurisdictionHash, $TokenId
            if ($Raw) { return $resp }
            ConvertTo-VipActionResult -Response $resp -Operation EnableToken `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{ TokenId = $TokenId })
        }
    }
}

function Disable-SymantecVipToken {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)] [string]$TokenId,
        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ShouldProcess($TokenId, 'DisableToken')) {
            $resp = Invoke-VipSoapRequest -Operation DisableToken -Properties $JurisdictionHash, $TokenId
            if ($Raw) { return $resp }
            ConvertTo-VipActionResult -Response $resp -Operation DisableToken `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{ TokenId = $TokenId })
        }
    }
}

function Approve-SymantecVipToken {
    <#
    .SYNOPSIS
        Activates a newly-issued VIP token (ActivateToken). Alias: Activate-SymantecVipToken.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)] [string]$TokenId,
        [switch]$Raw
    )
    process {
        if ($PSCmdlet.ShouldProcess($TokenId, 'ActivateToken')) {
            $resp = Invoke-VipSoapRequest -Operation ActivateToken -Properties $JurisdictionHash, $TokenId
            if ($Raw) { return $resp }
            ConvertTo-VipActionResult -Response $resp -Operation ActivateToken `
                -JurisdictionHash $JurisdictionHash -Target ([ordered]@{ TokenId = $TokenId })
        }
    }
}

function Unlock-SymantecVipToken {
    <#
    .SYNOPSIS
        Unlocks a VIP token. Use -Type SMS or Voice to unlock the phone-based
        variants that the JAR exposed as UnlockSms / UnlockVoice.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [Alias('OnBehalfOfAccountId', 'AuthorizerAccountId')]
        [string]$JurisdictionHash,
        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)] [string]$TokenId,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Default', 'SMS', 'Voice')]
        [string]$Type = 'Default',
        [switch]$Raw
    )
    process {
        $op = switch ($Type) {
            'SMS'   { 'UnlockSmsToken' }
            'Voice' { 'UnlockVoiceToken' }
            default { 'UnlockToken' }
        }
        if ($PSCmdlet.ShouldProcess($TokenId, $op)) {
            $resp = Invoke-VipSoapRequest -Operation $op -Properties $JurisdictionHash, $TokenId
            if ($Raw) { return $resp }
            $target = [ordered]@{ TokenId = $TokenId }
            if ($Type -ne 'Default') { $target.Type = $Type }
            ConvertTo-VipActionResult -Response $resp -Operation $op `
                -JurisdictionHash $JurisdictionHash -Target $target
        }
    }
}

function Invoke-SymantecVipBulkOperation {
    <#
    .SYNOPSIS
        Runs one VIP operation against a set of rows piped in or read from CSV.
    .DESCRIPTION
        Convenience wrapper for CSV-driven bulk jobs. Rows must contain columns
        matching the parameter names of the corresponding cmdlet (case
        insensitive). Errors are captured per-row so a single failure does not
        abort the batch.
    .PARAMETER Operation
        Which VIP operation to perform for each row.
    .PARAMETER InputObject
        Rows to process; typically the result of Import-Csv.
    .PARAMETER Path
        CSV file to import (alternative to piping -InputObject).
    .PARAMETER ThrottleSeconds
        Optional delay (seconds) between rows to avoid rate limits.
    .PARAMETER BackupPath
        Only used with -Operation DeleteUser. Directory where a per-user CSV
        snapshot is written before deletion, so Restore-SymantecVipUser can
        rebuild the user later. Defaults to '.\vip-user-backups'.
    .PARAMETER SkipBackup
        Only used with -Operation DeleteUser. Skip the pre-deletion backup.
    .EXAMPLE
        Import-Csv .\users.csv |
            Invoke-SymantecVipBulkOperation -Operation DeleteUser `
                -BackupPath .\vip-user-backups -OutVariable results
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Pipeline')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('CreateUser', 'DeleteUser', 'UpdateUser', 'GetUserInfo',
                     'AddCredential', 'RemoveCredential',
                     'ActivateToken', 'EnableToken', 'DisableToken',
                     'UnlockToken', 'UnlockSmsToken', 'UnlockVoiceToken',
                     'GetTokenInformation')]
        [string]$Operation,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Pipeline')]
        [psobject[]]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$Path,

        [double]$ThrottleSeconds = 0,

        [string]$BackupPath,

        [switch]$SkipBackup
    )

    begin {
        Assert-VipSession
        if ($PSCmdlet.ParameterSetName -eq 'File') {
            $InputObject = @(Import-Csv -LiteralPath $Path)
        }
        if (($BackupPath -or $SkipBackup) -and $Operation -ne 'DeleteUser') {
            Write-Warning "-BackupPath / -SkipBackup are only used with -Operation DeleteUser; they will be ignored for '$Operation'."
        }
        $rowIndex = 0
    }

    process {
        foreach ($row in $InputObject) {
            $rowIndex++
            $target = "row #$rowIndex"
            $ht = @{}
            foreach ($p in $row.PSObject.Properties) { $ht[$p.Name] = $p.Value }

            if ($Operation -eq 'DeleteUser') {
                if ($BackupPath -and -not $ht.ContainsKey('BackupPath')) {
                    $ht['BackupPath'] = $BackupPath
                }
                if ($SkipBackup -and -not $ht.ContainsKey('SkipBackup')) {
                    $ht['SkipBackup'] = $true
                }
            }

            if (-not $PSCmdlet.ShouldProcess($target, $Operation)) { continue }

            $result = $null
            $errText = $null
            try {
                switch ($Operation) {
                    'CreateUser'         { $result = New-SymantecVipUser         @ht -Confirm:$false }
                    'DeleteUser'         { $result = Remove-SymantecVipUser      @ht -Confirm:$false }
                    'UpdateUser'         { $result = Set-SymantecVipUser         @ht -Confirm:$false }
                    'GetUserInfo'        { $result = Get-SymantecVipUser         @ht }
                    'AddCredential'      { $result = Add-SymantecVipCredential   @ht -Confirm:$false }
                    'RemoveCredential'   { $result = Remove-SymantecVipCredential @ht -Confirm:$false }
                    'GetTokenInformation'{ $result = Get-SymantecVipTokenInformation @ht }
                    'EnableToken'        { $result = Enable-SymantecVipToken     @ht -Confirm:$false }
                    'DisableToken'       { $result = Disable-SymantecVipToken    @ht -Confirm:$false }
                    'ActivateToken'      { $result = Approve-SymantecVipToken    @ht -Confirm:$false }
                    'UnlockToken'        { $result = Unlock-SymantecVipToken     @ht -Confirm:$false }
                    'UnlockSmsToken'     { $result = Unlock-SymantecVipToken     @ht -Type SMS   -Confirm:$false }
                    'UnlockVoiceToken'   { $result = Unlock-SymantecVipToken     @ht -Type Voice -Confirm:$false }
                }
            } catch {
                $errText = $_.Exception.Message
                Write-Warning "[$Operation row #$rowIndex] $errText"
            }

            # Defensive readers so a $null result or missing property never
            # aborts the batch under Set-StrictMode.
            $get = { param($obj, $name, $default = $null)
                if ($obj -and $obj.PSObject.Properties[$name]) { $obj.$name } else { $default }
            }

            [pscustomobject]@{
                Row            = $rowIndex
                Operation      = $Operation
                Input          = [pscustomobject]$ht
                StatusCode     = & $get $result 'StatusCode'
                StatusMessage  = & $get $result 'StatusMessage'
                Success        = [bool](& $get $result 'Success' $false)
                RequestId      = & $get $result 'RequestId'
                BackupFile     = & $get $result 'BackupFile'
                Error          = $errText
                Result         = $result
            }

            if ($ThrottleSeconds -gt 0) { Start-Sleep -Milliseconds ([int]($ThrottleSeconds * 1000)) }
        }
    }
}

function Test-SymantecVipConnection {
    <#
    .SYNOPSIS
        Diagnoses why an mTLS call to Symantec VIP is failing.
    .DESCRIPTION
        Runs a series of local checks (TLS version, proxy, private-key
        accessibility) and then attempts a raw TLS handshake against the
        selected Symantec VIP endpoint. Prints the *actual* inner exception
        instead of the generic "SSL connection could not be established"
        message.
    .PARAMETER Endpoint
        Which endpoint to probe. Defaults to the User Services host used by
        Get-SymantecVipUser / New-SymantecVipUser etc.
    .EXAMPLE
        Test-SymantecVipConnection -Verbose
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('UserServices', 'Legacy')]
        [string]$Endpoint = 'UserServices'
    )

    Assert-VipSession

    $host = if ($Endpoint -eq 'Legacy') { 'services-auth.vip.symantec.com' } else { 'userservices-auth.vip.symantec.com' }
    $port = 443
    $findings = [ordered]@{}

    # 1. PS + framework versions.
    $findings.PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    $findings.PSEdition         = $PSVersionTable.PSEdition
    $findings.ClrVersion        = [System.Environment]::Version.ToString()

    # 2. TLS defaults.
    try {
        $findings.ServicePointManagerProtocols = [System.Net.ServicePointManager]::SecurityProtocol.ToString()
    } catch { $findings.ServicePointManagerProtocols = 'unavailable' }

    # 3. Certificate summary and private-key sanity.
    $cert = $script:VipSession.Certificate
    $findings.CertSubject     = $cert.Subject
    $findings.CertIssuer      = $cert.Issuer
    $findings.CertThumbprint  = $cert.Thumbprint
    $findings.CertNotAfter    = $cert.NotAfter
    $findings.CertHasKey      = $cert.HasPrivateKey
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        $findings.PrivateKeyUsable = [bool]$rsa
        if ($rsa) { $rsa.Dispose() }
    } catch {
        $findings.PrivateKeyUsable = "no: $($_.Exception.Message)"
    }

    # 4. Proxy in effect for the target URL.
    try {
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy([Uri]("https://$host"))
        $findings.SystemProxy = if ($proxy.AbsoluteUri -eq "https://$host/") { 'none' } else { $proxy.AbsoluteUri }
    } catch { $findings.SystemProxy = 'unknown' }

    # 5. Raw TCP + TLS handshake, no HTTP payload. Reveals the true handshake
    # error (bad client cert, TLS version mismatch, proxy MITM, ...).
    $tcp = $null; $ssl = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.SendTimeout    = 10000
        $tcp.ReceiveTimeout = 10000
        $tcp.Connect($host, $port)
        $findings.TcpConnect = 'ok'

        $validate = if ($script:VipSession.SkipCertificateCheck) {
            [System.Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$ch,$e) $true }
        } else {
            [System.Net.Security.RemoteCertificateValidationCallback]{
                param($s,$c,$ch,$e)
                if ($e -ne [System.Net.Security.SslPolicyErrors]::None) {
                    Write-Verbose "Server cert policy errors: $e"
                }
                $e -eq [System.Net.Security.SslPolicyErrors]::None
            }
        }
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $validate)

        $clientCerts = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new()
        [void]$clientCerts.Add($cert)

        $tls = try {
            [System.Security.Authentication.SslProtocols]::Tls12 -bor
            [System.Security.Authentication.SslProtocols]::Tls13
        } catch { [System.Security.Authentication.SslProtocols]::Tls12 }

        $ssl.AuthenticateAsClient($host, $clientCerts, $tls, $false)

        $findings.TlsHandshake      = 'ok'
        $findings.NegotiatedTls     = $ssl.SslProtocol.ToString()
        $findings.NegotiatedCipher  = $ssl.CipherAlgorithm.ToString()
        $findings.ServerCertSubject = $ssl.RemoteCertificate.Subject
    } catch {
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        $findings.TlsHandshake = "failed: $($ex.GetType().Name): $($ex.Message)"
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }

    [pscustomobject]$findings
}

# endregion ------------------------------------------------------------------

Set-Alias -Name Activate-SymantecVipToken -Value Approve-SymantecVipToken -Force
Set-Alias -Name Get-SymantecVipTokenInfo  -Value Get-SymantecVipTokenInformation -Force
Set-Alias -Name Update-SymantecVipUser    -Value Set-SymantecVipUser -Force

Export-ModuleMember -Function Connect-SymantecVip, Disconnect-SymantecVip, Get-SymantecVipContext,
                              Get-SymantecVipUser, New-SymantecVipUser, Set-SymantecVipUser, Remove-SymantecVipUser,
                              Restore-SymantecVipUser,
                              Add-SymantecVipCredential, Remove-SymantecVipCredential,
                              Get-SymantecVipTokenInformation,
                              Enable-SymantecVipToken, Disable-SymantecVipToken,
                              Approve-SymantecVipToken, Unlock-SymantecVipToken,
                              Invoke-SymantecVipBulkOperation,
                              Test-SymantecVipConnection `
                    -Alias    Activate-SymantecVipToken, Get-SymantecVipTokenInfo, Update-SymantecVipUser
