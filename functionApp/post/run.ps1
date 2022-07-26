using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

Write-Host 'Creating Azure AD header'
$token = Get-MSIMSGraphAccessToken -endpoint 'AzureAd'
Write-Host $token

$global:aadHeaders = @{
    "Authentication" = "Bearer"
    "Token"          = $($token) | ConvertTo-SecureString -AsPlainText -Force
}

Write-Host 'Creating resource header'
$token = Get-MSIMSGraphAccessToken -endpoint 'Azure'

Write-Host $token

$global:azHeaders = @{
    "Authentication" = "Bearer"
    "Token"          = $($token) | ConvertTo-SecureString -AsPlainText -Force
}

Write-Host "flag [$($Request.Query.code)]"
Invoke-Challenge -flagCode "$($Request.Query.code)"

$result = [ordered]@{
    'UserAccount'       = "$($user.UserName)"
    'Password'          = "$($user.Password)"
    'Storage Account'   = "$($resources.properties.outputs.storageAccountName.value)"
}

    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $result
        })
# }
