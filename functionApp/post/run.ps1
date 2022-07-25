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
#Invoke-Challenge -flagCode "$($Request.Query.code)"

switch ($($Request.Query.code)) {
    '{cth-$3cureY0ur5@S}' {
        $cthCode = 'SH-002'
        Write-Host "Challenge 1 completed, deploying scenario II"

        $guid = ('cth-sh002-{0}' -f (new-guid).guid).Substring(0, 18)

        Write-Host 'Creating deployment Payload'
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
        $resources  = New-ResourceDeployment -Name $cthCode -ResourceGroupId $rg.id $Payload  -Hidden
        $cth        = New-Content -Name $cthCode
        #endregion Create Challenge
    }
    Default {}
}

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
