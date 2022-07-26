Function ConvertFrom-Base64JWTLengthHelper {
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        $String
    )

    Process {
        $Length = $String.Length
        if ($String.Length % 4 -ne 0) {
            $Length += 4 - ($String.Length % 4)
        }
        return $String.PadRight($Length, "=")
    }
}

Function ConvertFrom-Base64JWT {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        $Base64JWT
    )

    Begin {
    }
    Process {
        $Spl = $Base64JWT.Split(".")
        [PSCustomObject] @{
            Header  = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((ConvertFrom-Base64JWTLengthHelper $Spl[0]))) | ConvertFrom-Json
            Payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((ConvertFrom-Base64JWTLengthHelper $Spl[1]))) | ConvertFrom-Json
        }
    }
    End {
    }
}

<#
.Synopsis
   Returns MSI access token
.DESCRIPTION
   Returns MSI access token
.EXAMPLE
   Get-MSIMSGraphAccessToken
#>
Function Get-MSIMSGraphAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$endpoint
    )

    Process {
        try {
            $ErrorVar = $null
            switch ($endpoint) {
                "Azure" {
                    $resourceUri = 'https://management.azure.com/'
                }
                "AzureAd" {
                    $resourceUri = 'https://graph.microsoft.com/'
                }
                "KeyVault" {
                    $resourceUri = 'https://graph.microsoft.com/'
                }
                Default {
                    return 'https://graph.microsoft.com/'
                }
            }

            $_accessToken = Invoke-RestMethod ($env:MSI_ENDPOINT + "?resource=$resourceUri&api-version=2017-09-01") `
                -Headers @{"Secret" = "$env:MSI_SECRET" } `
                -Verbose:$false `
                -ErrorVariable "ErrorVar"

            if ($ErrorVar) {
                Write-Error "Error when getting MSI access token: $ErrorVar"
            }
            else {
                Write-Debug "Got access token: $($_accessToken.access_token)"
                return $_accessToken.access_token
            }
        }
        catch {
            Write-Error "Error when getting MSI access token" -Exception $_
        }
    }
}

Function Get-GraphPermissions {
    [CmdletBinding()]
    [OutputType([string])]

    param(
        [Parameter(Mandatory = $true)]
        [string]$accessToken
    )

    $JWT = ConvertFrom-Base64JWT $accessToken
    if ($JWT.Payload.roles -notcontains "Group.Read.All") {
        Write-Warning "Could not find Group.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added."
    }

    if ($JWT.Payload.roles -notcontains "User.Read.All") {
        Write-Warning "Could not find User.Read.All in access token roles. Things might not work as intended. Make sure you have the correct scopes added."
    }

    if ($jwt.Payload.aud) {
        Write-Verbose " - oid:             $($jwt.payload.oid)"
        Write-Verbose " - aud:             $($jwt.payload.aud)"
        Write-Verbose " - iss:             $($jwt.payload.iss)"
        Write-Verbose " - appid:           $($jwt.payload.appid)"
        Write-Verbose " - app_displayname: $($jwt.payload.app_displayname)"
        Write-Verbose " - roles:           $($jwt.payload.roles)"
    }
}

Function New-UserAccount {
    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $false)]
        [string]$Country = 'NL'
    )

    # Create User Account
    Write-Host '[+] Creating User Account'
    try {
        $user = (Invoke-RestMethod -uri https://randomuser.me/api/?nat=$Country).results
    }
    catch {
        Write-Host '    [-] Server busy, wating 30 seconds'
        Start-Sleep 30
        $user = (Invoke-RestMethod -uri https://randomuser.me/api/?nat=$Country).results
    }

    $userObject = @{
        'accountEnabled'    = $true
        'displayName'       = "$($user.name.first) $($user.name.last)"
        'GivenName'         = "$($user.name.first)"
        'Surname'           = "$($user.name.last)"
        'UserPrincipalName' = "$($user.login.username)@securehats.nl"
        'City'              = "$($user.Location.city)"
        'Country'           = "$($user.location.country)"
        'PostalCode'        = "$($user.location.postcode)"
        'mailNickname'      = "$($user.login.username)"
        "passwordProfile"   = @{
            "forceChangePasswordNextSignIn" = $false
            'Password'                      = "_$($user.login.salt)"
        }
    }
    return New-AzureAdUser -UserObject $userObject

}

Function New-AzureResourceGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Location = 'westeurope',

        [Parameter(Mandatory = $false)]
        [string]$SubscriptionId = '1c4767b1-2a41-41da-8273-b5ec9fca09df'

    )

        Write-Host "[+] Creating Azure Resource with name [$Name]"
        $deployment = Invoke-RestMethod @azHeaders `
            -Uri https://management.azure.com/subscriptions/$($SubscriptionId)/resourceGroups/$($Name)?api-version=2021-04-01 `
            -body ( @{ 'location' = "$Location" } | ConvertTo-Json ) `
            -ContentType 'application/json' `
            -Method 'PUT'

        return $deployment
}

Function New-AzureAdUser {
    param (
        [Parameter(Mandatory = $true)]
        [object]$UserObject
    )

    $params = @{
        'URI' = 'https://graph.microsoft.com/beta/users'
        'ContentType' = 'application/json'
        'Method' = 'POST'
        'Body' = ($UserObject | ConvertTo-Json)
    }

    try {
        Write-Host 'Creating Azure AD header'

            $aadHeaders = @{
            "Authentication" = "Bearer"
            "Token"          = (Get-MSIMSGraphAccessToken -endpoint 'AzureAd') | ConvertTo-SecureString -AsPlainText -Force
        }

        $deployment = Invoke-RestMethod @params @aadHeaders

        if (!($null -eq $deployment)) {
            $result = [ordered]@{
                'id'                = $deployment.id
                'Username'           = $deployment.UserPrincipalName
                'Password'           = "_$($userObject.passwordProfile.Password)"
            }

            return $result
        }
    } catch {
        return 'Unable to create user'
    }
}

Function New-RoleAssignment {
    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [array]$RoleGuid,

        [Parameter(Mandatory = $true)]
        [string]$ResourceId
    )

    Write-Host "[+] Creating Role Assignments"
    $uri = 'https://management.azure.com{0}/providers/microsoft.authorization/roleassignments/{1}?api-version=2015-07-01' -f $ResourceId, (New-Guid).guid

    foreach ($id in $RoleGuid) {
        Write-Host "    [-] Assigning Role with Id [$($id)]"
        $body = @{
            "properties" = @{
                "roleDefinitionId" = "/providers/Microsoft.Authorization/roleDefinitions/$($id)"
                "principalId" = "$($UserId)"
                "scope" = $ResourceId
            }
        } | ConvertTo-Json

        $deployment = Invoke-RestMethod @azHeaders `
            -Uri $uri `
            -Method 'PUT' `
            -ContentType 'application/json' `
            -body $body
    }

    return $deployment
}

Function New-ResourceDeployment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupId,

        [Parameter(Mandatory = $true)]
        [object]$Payload,

        [Parameter(Mandatory = $true)]
        [string]$cthCode

        )

    $params = @{
        "Method"  = "PUT"
        "Uri"     = "https://management.azure.com$($ResourceGroupId)/providers/Microsoft.Resources/deployments/$($Name)?api-version=2020-06-01"
        "ContentType" = 'application/json'
        "Body"    = $payload | ConvertTo-Json -Depth 10 -Compress
    }

    Write-Host "[+] Start deployment"
    $deployment = Invoke-RestMethod @params @azHeaders -UseBasicParsing

    $params = @{
        "Method"  = "GET"
        "Uri"     = "https://management.azure.com$($ResourceGroupId)/providers/Microsoft.Resources/deployments/$($Name)?api-version=2020-10-01"
    }

    do {
        Start-Sleep -Seconds 10
        $deployment = Invoke-RestMethod @params @azHeaders -UseBasicParsing
        Write-Host "    [-] Deployment status: $($deployment.properties.provisioningState)"
    } while ($deployment.properties.provisioningState -in @("Accepted", "Created", "Creating", "Running", "Updating"))

        $uri = "https://management.azure.com$($rg.id)/providers/Microsoft.Resources/deployments/$($cthCode)?api-version=2021-04-01"
        Invoke-RestMethod -Uri $uri @azHeaders -Method 'DELETE'

    return $deployment
}

Function New-Content {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$cthCode
    )

    $tempfile = '{0}\{1}' -f $env:temp, 'function.zip'

    $params = @{
        "Uri" = "https://github.com/SecureHats/capture-the-hat/raw/main/scenarios/Azure/$($cthCode)/function.zip"
        'Method' = 'GET'
        'ContentType' = 'application/json'
    }

    Write-Host "[+] Downloading challenge package"
    Invoke-RestMethod @params -OutFile "$tempfile"

    Write-Host "    [-] Starting challenge deployment"
    Publish-AzWebapp `
        -ResourceGroupName "$guid" `
        -Name "$guid" `
        -ArchivePath "$tempfile" `
        -Force
}

Function Invoke-Challenge {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$flagCode
    )

    $script:azHeaders = @{
        "Authentication" = "Bearer"
        "Token"          = (Get-MSIMSGraphAccessToken -endpoint 'Azure') | ConvertTo-SecureString -AsPlainText -Force
    }

    switch ($flagCode) {
        '{cth-$3cureY0ur5@S}' {
            $cthCode = 'SH-002'
            Write-Host "[+] Deploying new challenge"

            $guid = ('cth-sh002-{0}' -f (new-guid).guid).Substring(0, 18)

            $payload = @{
                'properties' = @{
                    'templateLink' = @{
                        'uri' = "https://raw.githubusercontent.com/SecureHats/capture-the-hat/main/scenarios/Azure/$($cthCode)/templates/azuredeploy.json"
                    }
                    'parameters'   = @{
                        'functionName'      = @{
                            "value" = "$guid"
                        }
                        'applicationId'     = @{
                            "value" = "(new-guid).guid"
                        }
                        'applicationSecret' = @{
                            "value" = "(new-guid).guid"
                        }
                    }
                    'mode'         = 'Incremental'
                }
            }

            #region Create Challenge
            $rg         = New-AzureResourceGroup -Name $guid
            $user       = New-UserAccount -Country 'NL'
            $roles      = New-RoleAssignment -UserId "$($user.id)" -ResourceId $rg.id -RoleGuid @('acdd72a7-3385-48ef-bd42-f606fba81ae7', '17d1049b-9a84-46fb-8f53-869881c3d3ab')
            $resources  = New-ResourceDeployment -Name $cthCode -ResourceGroupId $rg.id $Payload -cthCode $cthCode
            $cth        = New-Content -cthCode $cthCode

            $params = @{
                "Method"  = "PUT"
                "Uri"     = "https://management.azure.com$($ResourceGroupId)/providers/Microsoft.Resources/tags/default?api-version=2021-04-01"
            } | ConvertTo-Json

            $body = @{
                "properties" = @{
                  "tags" = @{
                    "CreateDate"    = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    "Expire"        = (Get-Date).AddHours(72).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    "Account"       = "$($user.mailNickname)"
                }
              }
            } | ConvertTo-Json

            Write-Host "[+] Deploying tags"
            Invoke-RestMethod @azHeaders @params -Body $body
            #endregion Create Challenge

        }
        Default {}
    }

    $result = @{
        'UserAccount'       = "$($user.UserName)"
        'Password'          = "$($user.Password)"
    }

    return $result
}