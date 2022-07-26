using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$result = Invoke-Challenge -flagCode "$($Request.Query.code)"

Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body       = $result
})
