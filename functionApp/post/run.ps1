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

$result = @{
    'UserAccount'       = "$($user.UserName)"
    'Password'          = "$($user.Password)"
    'Storage Account'   = "$($resources.properties.outputs.storageAccountName.value)"
}

# if ($Request.Query.code -eq '{cth-$3cureY0ur5@S}') {
#     $body = "You have completed the challenge! New challege will be provisioned in 5 min. Don't close this screen"
#     Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
#             StatusCode = [HttpStatusCode]::OK
#             Body       = $body
#         })

#     $guid = ('cth-sh002-{0}' -f (new-guid).guid).Substring(0, 18)
#     $rg = New-AzureResourceGroup -Name $guid

#     Write-Host 'Creating deployment Payload'
#     $payload = @{
#         'properties' = @{
#             'templateLink' = @{
#                 'uri' = 'https://raw.githubusercontent.com/SecureHats/capture-the-hat/main/scenarios/Azure/SH-002/templates/azuredeploy.json'
#             }
#             'parameters'   = @{
#                 'functionName'      = @{
#                     "value" = "$guid"
#                 }
#                 'applicationId'     = @{
#                     "value" = "(new-guid).guid"
#                 }
#                 'applicationSecret' = @{
#                     "value" = "(new-guid).guid"
#                 }
#             }
#             'mode'         = 'Incremental'
#         }
#     }

#     $user = New-UserAccount -Country 'NL'

    #    'StorageAccountName' = $guid.replace('-', '')

    # Write-Host 'Assigning RBAC Roles'
    # New-RoleAssignment -UserId "$($user.id)" -ResourceId $rg.id -RoleGuid @('acdd72a7-3385-48ef-bd42-f606fba81ae7', '17d1049b-9a84-46fb-8f53-869881c3d3ab')

    # New-ResourceGroupDeployment -Name $deploymentName -ResourceGroupId "$($rg.id)" -Payload $payload -Hidden

    # $tempfile = '{0}\{1}' -f $env:temp, 'function.zip'

    # Write-Host "Downloading file to [$tempfile]"
    # Invoke-RestMethod 'https://github.com/SecureHats/capture-the-hat/raw/main/scenarios/Azure/SH-002/function.zip' `
    #     -ContentType 'application/zip' `
    #     -Method 'GET' `
    #     -OutFile "$tempfile"

    # Publish-AzWebapp `
    #     -ResourceGroupName "$guid" `
    #     -Name "$guid" `
    #     -ArchivePath "$tempfile" `
    #     -Force

    # $deployment.properties.outputs.storageAccountName.value

    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $result
        })
# }
