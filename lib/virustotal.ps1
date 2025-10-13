# Library for VirusTotal API integration
# Functions to check file hashes and URLs against VirusTotal

# Error codes for VirusTotal operations
$Script:_ERR_UNSAFE = 2       # Security issue detected
$Script:_ERR_EXCEPTION = 4    # Exception while processing
$Script:_ERR_NO_INFO = 8      # Information not found
$Script:_ERR_NO_API_KEY = 16  # API key not configured

<#
.SYNOPSIS
    Converts a URL to a VirusTotal-compatible URL ID.
.DESCRIPTION
    Encodes a URL into the base64 format used by VirusTotal's API,
    with necessary character replacements.
.PARAMETER Url
    The URL to convert.
.EXAMPLE
    ConvertTo-VirusTotalUrlId "https://example.com"
#>
Function ConvertTo-VirusTotalUrlId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url
    )

    $url_id = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Url))
    $url_id = $url_id -replace '\+', '-'
    $url_id = $url_id -replace '/', '_'
    $url_id = $url_id -replace '=', ''
    return $url_id
}

<#
.SYNOPSIS
    Gets the size of a remote file without downloading it.
.DESCRIPTION
    Performs a HEAD request to determine the size of a remote file.
.PARAMETER Url
    The URL of the file to check.
.EXAMPLE
    Get-RemoteFileSize "https://example.com/file.zip"
#>
Function Get-RemoteFileSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url
    )

    try {
        $response = Invoke-WebRequest -Uri $Url -Method HEAD -UseBasicParsing
        return [int]($response.Headers.'Content-Length' | ForEach-Object { [System.Convert]::ToInt32($_) })
    }
    catch {
        warn "Could not determine file size for $Url`: $($_.Exception.Message)"
        return 0
    }
}

<#
.SYNOPSIS
    Tests if a file is safe by checking its hash on VirusTotal.
.DESCRIPTION
    Submits a file hash to VirusTotal and returns safety information.
.PARAMETER Hash
    The hash of the file to check (SHA256, SHA1, or MD5).
.PARAMETER Url
    The URL where the file can be found (for reporting).
.PARAMETER AppName
    The name of the app associated with the file.
.PARAMETER ReturnObject
    If set, returns a rich object instead of a numeric code.
.OUTPUTS
    By default, returns an integer indicating the number of security vendors that flagged the file.
    When ReturnObject is used, returns a PSObject with detailed information.
.EXAMPLE
    Test-VirusTotalHash -Hash "5f8d01ed18cda5c2bb9a78f9b3589170e2d27c8c" -AppName "example" -Url "https://example.com/file.exe"
#>
Function Test-VirusTotalHash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Hash,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Url,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]$AppName,

        [Parameter()]
        [switch]$ReturnObject
    )

    $hash = $hash.ToLower()
    $api_url = "https://www.virustotal.com/api/v3/files/$hash"

    # Get API key from Scoop config
    $api_key = get_config VIRUSTOTAL_API_KEY
    if (!$api_key) {
        abort ("VirusTotal API key is not configured`n" +
            "  You could get one from https://www.virustotal.com/gui/my-apikey and set with`n" +
            "  scoop config virustotal_api_key <API key>") $Script:_ERR_NO_API_KEY
    }

    # Prepare headers for VirusTotal API
    $headers = @{
        'Accept' = 'application/json'
        'x-apikey' = $api_key
    }

    try {
        $response = Invoke-WebRequest -Uri $api_url -Method GET -Headers $headers -UseBasicParsing
        $result = $response.Content

        # Parse statistics from response
        $stats = json_path $result '$.data.attributes.last_analysis_stats'
        [int]$malicious = json_path $stats '$.malicious'
        [int]$suspicious = json_path $stats '$.suspicious'
        [int]$timeout = json_path $stats '$.timeout'
        [int]$undetected = json_path $stats '$.undetected'
        [int]$unsafe = $malicious + $suspicious
        [int]$total = $unsafe + $undetected
        [int]$fileSize = json_path $result '$.data.attributes.size'
        $report_hash = json_path $result '$.data.attributes.sha256'
        $report_url = "https://www.virustotal.com/gui/file/$report_hash"

        # Different display message based on analysis status
        if ($total -eq 0) {
            info "$AppName`: Analysis in progress."
            $reportObj = [PSCustomObject]@{
                'App.Name'        = $AppName
                'App.Url'         = $Url
                'App.Hash'        = $hash
                'App.HashType'    = $null
                'App.Size'        = filesize $fileSize
                'FileReport.Url'  = $report_url
                'FileReport.Hash' = $report_hash
                'UrlReport.Url'   = $null
                'Result.Unsafe'   = 0
                'Result.Total'    = 0
            }
        }
        else {
            # Get detailed results from security vendors
            $vendorResults = (ConvertFrom-Json((json_path $result '$.data.attributes.last_analysis_results'))).PSObject.Properties.Value

            # Display appropriate warning level based on security findings
            switch ($unsafe) {
                0 { info "$AppName`: $total security vendors found this file safe." }
                1 { warn "$AppName`: $unsafe of $total security vendors found this file unsafe." }
                2 { warn "$AppName`: $unsafe of $total security vendors found this file unsafe." }
                Default { warn "$AppName`: $unsafe of $total security vendors found this file unsafe!" }
            }

            # Get specific vendor results
            $maliciousResults = $vendorResults |
                Where-Object -Property category -EQ 'malicious' |
                Select-Object -ExpandProperty engine_name

            $suspiciousResults = $vendorResults |
                Where-Object -Property category -EQ 'suspicious' |
                Select-Object -ExpandProperty engine_name

            # Create rich report object
            $reportObj = [PSCustomObject]@{
                'App.Name'              = $AppName
                'App.Url'               = $Url
                'App.Hash'              = $hash
                'App.HashType'          = $null
                'App.Size'              = filesize $fileSize
                'FileReport.Url'        = $report_url
                'FileReport.Hash'       = $report_hash
                'UrlReport.Url'         = $null
                'Result.Unsafe'         = $unsafe
                'Result.Total'          = $total
                'Result.MaliciousCount' = $malicious
                'Result.Malicious'      = $maliciousResults
                'Result.SuspiciousCount' = $suspicious
                'Result.Suspicious'     = $suspiciousResults
            }
        }

        # Return either the object or the number of unsafe findings
        if ($ReturnObject) {
            return $reportObj
        }
        return [int]$unsafe
    }
    catch {
        # warn "$AppName`: Exception while checking hash on VirusTotal`: $($_.Exception.Message)"
        throw $_
        # if ($ReturnObject) {
        #     return [PSCustomObject]@{
        #         'App.Name'   = $AppName
        #         'App.Url'    = $Url
        #         'App.Hash'   = $hash
        #         'ErrorMsg'   = $_.Exception.Message
        #         'StatusCode' = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
        #     }
        # }
        # return $Script:_ERR_EXCEPTION
    }
}

<#
.SYNOPSIS
    Tests if a URL is safe according to VirusTotal.
.DESCRIPTION
    Checks a URL against VirusTotal and returns safety information.
.PARAMETER Url
    The URL to check.
.PARAMETER AppName
    The name of the app associated with the URL.
.PARAMETER ReturnObject
    If set, returns a rich object instead of a numeric code.
.OUTPUTS
    By default, returns an integer indicating safety status.
    When ReturnObject is used, returns a PSObject with detailed information.
.EXAMPLE
    Test-VirusTotalUrl -Url "https://example.com/file.exe" -AppName "example"
#>
Function Test-VirusTotalUrl {
    # returns (ok, errcode), or object if -ReturnObject is used
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$AppName,

        [Parameter()]
        [switch]$ReturnObject
    )

    # Convert URL to VirusTotal ID format
    $id = ConvertTo-VirusTotalUrlId $Url
    $api_url = "https://www.virustotal.com/api/v3/urls/$id"

    # Get API key from Scoop config
    $api_key = get_config VIRUSTOTAL_API_KEY
    if (!$api_key) {
        abort ("VirusTotal API key is not configured`n" +
            "  You could get one from https://www.virustotal.com/gui/my-apikey and set with`n" +
            "  scoop config virustotal_api_key <API key>") $Script:_ERR_NO_API_KEY
    }

    # Prepare headers for VirusTotal API
    $headers = @{
        'Accept' = 'application/json'
        'x-apikey' = $api_key
    }

    try {
        $response = Invoke-WebRequest -Uri $api_url -Method GET -Headers $headers -UseBasicParsing
        $result = $response.Content

        # Extract information from response
        $id = json_path $result '$.data.id'
        $hash = json_path $result '$.data.attributes.last_http_response_content_sha256' 6>$null
        $last_analysis_date = json_path $result '$.data.attributes.last_analysis_date' 6>$null
        $url_report_url = "https://www.virustotal.com/gui/url/$id"

        info "$AppName`: URL report found."

        if (!$hash) {
            # No file hash found - either analysis in progress or no file analyzed
            if (!$last_analysis_date) {
                info "$AppName`: Analysis in progress."
            }
            else {
                info "$AppName`: No file analyzed at this URL."
            }

            $reportObj = [PSCustomObject]@{
                'App.Name'         = $AppName
                'App.Url'          = $Url
                'App.Hash'         = $null
                'App.HashType'     = $null
                'App.Size'         = $null
                'FileReport.Url'   = $null
                'FileReport.Hash'  = $null
                'UrlReport.Url'    = $url_report_url
                'Result.Unsafe'    = 0
                'Result.Total'     = 0
            }

            if ($ReturnObject) {
                return $true, $reportObj
            }
            return $true, 0
        }
        else {
            # Related file found - check its report
            info "$AppName`: Related file report found."

            $reportObj = [PSCustomObject]@{
                'App.Name'         = $AppName
                'App.Url'          = $Url
                'App.Hash'         = $hash
                'App.HashType'     = 'sha256'
                'App.Size'         = $null
                'FileReport.Url'   = "https://www.virustotal.com/gui/file/$hash"
                'FileReport.Hash'  = $hash
                'UrlReport.Url'    = $url_report_url
            }

            if ($ReturnObject) {
                # If returning object, merge with file report details
                $fileReport = Test-VirusTotalHash -Hash $hash -Url $Url -AppName $AppName -ReturnObject
                foreach ($prop in $fileReport.PSObject.Properties) {
                    if (!$reportObj.PSObject.Properties[$prop.Name]) {
                        $reportObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value
                    }
                }
                return $true, $reportObj
            }

            # Otherwise return numeric status
            return [int](Test-VirusTotalHash -Hash $hash -Url $Url -AppName $AppName)
        }
    }
    catch {
        # warn "$AppName`: Exception while checking URL on VirusTotal`: $($_.Exception.Message)"
        throw $_
        # if ($ReturnObject) {
        #     return $false, [PSCustomObject]@{
        #         'App.Name'    = $AppName
        #         'App.Url'     = $Url
        #         'ErrorMsg'    = $_.Exception.Message
        #         'StatusCode'  = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
        #     }
        # }
        # return $false, $Script:_ERR_EXCEPTION
    }
}

<#
.SYNOPSIS
    Submits a URL to VirusTotal for analysis.
.DESCRIPTION
    Sends a URL to VirusTotal for scanning and analysis.
.PARAMETER Url
    The URL to submit for analysis.
.PARAMETER AppName
    The name of the app associated with the URL.
.PARAMETER DoScan
    Whether to actually submit the URL or just show a warning.
.PARAMETER Retrying
    Internal parameter for retry logic.
.EXAMPLE
    Submit-ToVirusTotal -Url "https://example.com/file.exe" -AppName "example" -DoScan $true
#>
Function Submit-ToVirusTotal {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Url,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$AppName,

        [Parameter(Mandatory = $true, Position = 2)]
        [bool]$DoScan,

        [Parameter()]
        [bool]$Retrying = $false
    )

    if (!$DoScan) {
        warn "$AppName`: not found`: you can manually submit $Url"
        return
    }

    # Get API key from Scoop config
    $api_key = get_config VIRUSTOTAL_API_KEY
    if (!$api_key) {
        abort ("VirusTotal API key is not configured`n" +
            "  You could get one from https://www.virustotal.com/gui/my-apikey and set with`n" +
            "  scoop config virustotal_api_key <API key>") $Script:_ERR_NO_API_KEY
    }

    try {
        # URL encode the submission
        $encoded_url = [System.Web.HttpUtility]::UrlEncode($Url)
        $api_url = 'https://www.virustotal.com/api/v3/urls'
        $content_type = 'application/x-www-form-urlencoded'

        # Prepare headers and body
        $headers = @{
            'Accept' = 'application/json'
            'x-apikey' = $api_key
            'Content-Type' = $content_type
        }
        $body = "url=$encoded_url"

        # Submit to VirusTotal
        $result = Invoke-WebRequest -Uri $api_url -Method POST -Headers $headers -ContentType $content_type -Body $body -UseBasicParsing

        # Handle successful submission
        if ($result.StatusCode -eq 200) {
            info "$AppName`: Successfully submitted to VirusTotal!"
            $id = json_path $result.content '$.data.id'

            if ($id) {
                info "$AppName`: Check $Url later at:"
                info "$AppName`: https://www.virustotal.com/gui/url-analysis/$id"
            }
            else {
                info "$AppName`: Check $Url later at https://www.virustotal.com/"
            }

            # Check if file size might require manual upload
            $fileSize = Get-RemoteFileSize $Url
            if ($fileSize -gt 80000000) {
                info "$AppName`: Remote file size: $(filesize $fileSize). Large files might require manual upload."
            }

            return
        }

        # Handle API rate limiting with retry logic
        if (!$Retrying) {
            warn "$AppName`: VirusTotal submission failed, rate limited. Retrying..."
            warn "$AppName`: (VirusTotal rate limiting: sleeping for 60s)"
            Start-Sleep -s 60
            Submit-ToVirusTotal -Url $Url -AppName $AppName -DoScan $DoScan -Retrying $true
        }
        else {
            warn "$AppName`: VirusTotal submission failed again: API returned $($result.StatusCode)"
        }
    }
    catch {
        # warn "$AppName`: VirusTotal submission failed`: $($_.Exception.Message)"
        throw $_
    }
}
