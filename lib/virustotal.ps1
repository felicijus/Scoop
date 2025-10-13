# Library for VirusTotal API integration
# Functions to check file hashes and URLs against VirusTotal

$_ERR_UNSAFE = 2
$_ERR_EXCEPTION = 4
$_ERR_NO_INFO = 8
$_ERR_NO_API_KEY = 16

Function ConvertTo-VirusTotalUrlId ($url) {
    $url_id = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($url))
    $url_id = $url_id -replace '\+', '-'
    $url_id = $url_id -replace '/', '_'
    $url_id = $url_id -replace '=', ''
    $url_id
}

Function Get-RemoteFileSize ($url) {
    $response = Invoke-WebRequest -Uri $url -Method HEAD -UseBasicParsing
    $response.Headers.'Content-Length' | ForEach-Object { [System.Convert]::ToInt32($_) }
}

Function Get-VirusTotalResultByHash ($hash, $url, $app) {
    $hash = $hash.ToLower()
    $api_url = "https://www.virustotal.com/api/v3/files/$hash"

    $api_key = get_config VIRUSTOTAL_API_KEY
    if (!$api_key) {
        abort ("VirusTotal API key is not configured`n" +
            "  You could get one from https://www.virustotal.com/gui/my-apikey and set with`n" +
            "  scoop config virustotal_api_key <API key>") $_ERR_NO_API_KEY
    }

    $headers = @{}
    $headers.Add('Accept', 'application/json')
    $headers.Add('x-apikey', $api_key)
    $response = Invoke-WebRequest -Uri $api_url -Method GET -Headers $headers -UseBasicParsing
    $result = $response.Content
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
    if ($total -eq 0) {
        info "$app`: Analysis in progress."
        # Create the object for reference but ensure we return an integer
        $reportObj = [PSCustomObject] @{
            'App.Name'        = $app
            'App.Url'         = $url
            'App.Hash'        = $hash
            'App.HashType'    = $null
            'App.Size'        = filesize $fileSize
            'FileReport.Url'  = $report_url
            'FileReport.Hash' = $report_hash
            'UrlReport.Url'   = $null
        }
    } else {
        $vendorResults = (ConvertFrom-Json((json_path $result '$.data.attributes.last_analysis_results'))).PSObject.Properties.Value
        switch ($unsafe) {
            0 { info "$app`: $total security vendors found this file safe." }
            1 { warn "$app`: $unsafe of $total security vendors found this file unsafe." }
            2 { warn "$app`: $unsafe of $total security vendors found this file unsafe." }
            Default { warn "$app`: $unsafe of $total security vendors found this file unsafe!" }
        }
        $maliciousResults = $vendorResults |
            Where-Object -Property category -EQ 'malicious' |
            Select-Object -ExpandProperty engine_name
        $suspiciousResults = $vendorResults |
            Where-Object -Property category -EQ 'suspicious' |
            Select-Object -ExpandProperty engine_name
        # Create the object for reference but ensure we return an integer
        $reportObj = [PSCustomObject] @{
            'App.Name'              = $app
            'App.Url'               = $url
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

    # Always return an integer value
    return [int]$unsafe
}

Function Get-VirusTotalResultByUrl ($url, $app) {
    $id = ConvertTo-VirusTotalUrlId $url
    $api_url = "https://www.virustotal.com/api/v3/urls/$id"

    $api_key = get_config VIRUSTOTAL_API_KEY
    if (!$api_key) {
        abort ("VirusTotal API key is not configured`n" +
            "  You could get one from https://www.virustotal.com/gui/my-apikey and set with`n" +
            "  scoop config virustotal_api_key <API key>") $_ERR_NO_API_KEY
    }

    $headers = @{}
    $headers.Add('Accept', 'application/json')
    $headers.Add('x-apikey', $api_key)
    $response = Invoke-WebRequest -Uri $api_url -Method GET -Headers $headers -UseBasicParsing
    $result = $response.Content
    $id = json_path $result '$.data.id'
    $hash = json_path $result '$.data.attributes.last_http_response_content_sha256' 6>$null
    $last_analysis_date = json_path $result '$.data.attributes.last_analysis_date' 6>$null
    $url_report_url = "https://www.virustotal.com/gui/url/$id"
    info "$app`: Url report found."
    if (!$hash) {
        if (!$last_analysis_date) {
            info "$app`: Analysis in progress."
        } else {
            info "$app`: No file analyzed at this URL."
        }
        # Create the object for reference but return a numeric result
        $reportObj = [PSCustomObject] @{
            'App.Name'         = $app
            'App.Url'          = $url
            'App.Hash'         = $null
            'App.HashType'     = $null
            'App.Size'         = $null
            'FileReport.Url'   = $null
            'FileReport.Hash'  = $null
            'UrlReport.Url'    = $url_report_url
        }
        return 0
    } else {
        info "$app`: Related file report found."
        # Create the object for reference but return only the numeric unsafe count
        $reportObj = [PSCustomObject] @{
            'App.Name'         = $app
            'App.Url'          = $url
            'App.Hash'         = $hash
            'App.HashType'     = 'sha256'
            'App.Size'         = $null
            'FileReport.Url'   = "https://www.virustotal.com/gui/file/$hash"
            'FileReport.Hash'  = $hash
            'UrlReport.Url'    = $url_report_url
        }
        # Call Get-VirusTotalResultByHash but ensure we're returning an integer
        return [int](Get-VirusTotalResultByHash $hash $url $app)
    }
}

Function Submit-ToVirusTotal ($url, $app, $do_scan, $retrying = $False) {
    if (!$do_scan) {
        warn "$app`: not found`: you can manually submit $url"
        return
    }

    $api_key = get_config VIRUSTOTAL_API_KEY
    if (!$api_key) {
        abort ("VirusTotal API key is not configured`n" +
            "  You could get one from https://www.virustotal.com/gui/my-apikey and set with`n" +
            "  scoop config virustotal_api_key <API key>") $_ERR_NO_API_KEY
    }

    try {
        $encoded_url = [System.Web.HttpUtility]::UrlEncode($url)
        $api_url = 'https://www.virustotal.com/api/v3/urls'
        $content_type = 'application/x-www-form-urlencoded'
        $headers = @{}
        $headers.Add('Accept', 'application/json')
        $headers.Add('x-apikey', $api_key)
        $headers.Add('Content-Type', $content_type)
        $body = "url=$encoded_url"
        $result = Invoke-WebRequest -Uri $api_url -Method POST -Headers $headers -ContentType $content_type -Body $body -UseBasicParsing
        if ($result.StatusCode -eq 200) {
            info "$app`: Successfully submitted to VirusTotal!"
            $id = json_path $result.content '$.data.id'
            if ($id) {
                info "$app`: Check $url later at:"
                info "$app`: https://www.virustotal.com/gui/url-analysis/$id"
            } else {
                info "$app`: Check $url later at https://www.virustotal.com/"
            }
            return
        }

        # EAFP: submission failed -> sleep, then retry
        if (!$retrying) {
            warn "$app`: VirusTotal submission failed, rate limited. Retrying..."
            warn "$app`: (VirusTotal rate limiting: sleeping for 60s)"
            Start-Sleep -s 60
            Submit-ToVirusTotal $url $app $do_scan $True
        } else {
            warn "$app`: VirusTotal submission failed again"
        }
    } catch [Exception] {
        warn "$app`: VirusTotal submission failed`: $($_.Exception.Message)"
        return
    }
}
