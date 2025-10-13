# Usage: scoop virustotal [* | app1 app2 ...] [options]
# Summary: Look for app's hash or url on virustotal.com
# Help: Look for app's hash or url on virustotal.com
#
# Use a single '*' or the '-a/--all' switch to check all installed apps.
#
# To use this command, you have to sign up to VirusTotal's community,
# and get an API key. Then, tell scoop about your API key with:
#
#   scoop config virustotal_api_key <your API key: 64 lower case hex digits>
#
# Exit codes:
#  0 -> success
#  1 -> problem parsing arguments
#  2 -> at least one package was marked unsafe by VirusTotal
#  4 -> at least one exception was raised while looking for info
#  8 -> at least one package couldn't be queried because the manifest couldn't be found
# 16 -> VirusTotal API key is not configured
# Note: the exit codes (2, 4 & 8) may be combined, e.g. 6 -> exit codes
#       2 & 4 combined
#
# Options:
#   -a, --all                 Check for all installed apps
#   -s, --scan                For packages where VirusTotal has no information, send download URL
#                             for analysis (and future retrieval). This requires you to configure
#                             your virustotal_api_key.
#   -n, --no-depends          By default, all dependencies are checked too. This flag avoids it.
#   -u, --no-update-scoop     Don't update Scoop before checking if it's outdated
#   -p, --passthru            Return reports as objects

. "$PSScriptRoot\..\lib\getopt.ps1"
. "$PSScriptRoot\..\lib\versions.ps1" # 'Select-CurrentVersion'
. "$PSScriptRoot\..\lib\manifest.ps1" # 'Get-Manifest'
. "$PSScriptRoot\..\lib\json.ps1" # 'json_path'
. "$PSScriptRoot\..\lib\download.ps1" # 'hash_for_url'
. "$PSScriptRoot\..\lib\depends.ps1" # 'Get-Dependency'
. "$PSScriptRoot\..\lib\virustotal.ps1" # VirusTotal functions

$opt, $apps, $err = getopt $args 'asnup' @('all', 'scan', 'no-depends', 'no-update-scoop', 'passthru')
if ($err) { "scoop virustotal: $err"; exit 1 }
$all = $apps -eq '*' -or $opt.a -or $opt.all
if (!$apps -and !$all) { my_usage; exit 1 }
$architecture = Get-DefaultArchitecture

if (is_scoop_outdated) {
    if ($opt.u -or $opt.'no-update-scoop') {
        warn 'Scoop is out of date.'
    } else {
        & "$PSScriptRoot\scoop-update.ps1"
    }
}

if ($all) {
    $apps = (installed_apps $false) + (installed_apps $true)
}

if (!$opt.n -and !$opt.'no-depends') {
    $apps = $apps | Get-Dependency -Architecture $architecture | Select-Object -Unique
}

$exit_code = 0

# Global flag to explain only once about sleep between requests
$explained_rate_limit_sleeping = $False

# Requests counter to slow down requests submitted to VirusTotal as
# script execution progresses
$requests = 0
$reports = $apps | ForEach-Object {
    $app = $_
    $null, $manifest, $bucket, $null = Get-Manifest $app
    if (!$manifest) {
        $exit_code = $exit_code -bor $_ERR_NO_INFO
        warn "$app`: manifest not found"
        return
    }

    [int]$index = 0
    $urls = script:url $manifest $architecture
    $urls | ForEach-Object {
        $url = $_
        $index++
        if ($urls.GetType().IsArray) {
            info "$app`: url $index"
        }
        $hash = hash_for_url $manifest $url $architecture

        try {
            $isHashUnsupported = $false
            if ($hash -match '(?<algo>[^:]+):(?<hash>.*)') {
                $algo = $matches.algo
                $hash = $matches.hash
                if ($matches.algo -inotin 'md5', 'sha1', 'sha256') {
                    $hash = $null
                    $isHashUnsupported = $true
                    warn "$app`: Unsupported hash $($matches.algo). Will search by url instead."
                }
            } elseif ($hash) {
                $algo = 'sha256'
            }
            if ($hash) {
                $file_report = Test-VirusTotalHash $hash $url $app -ReturnObject
                $file_report.'App.HashType' = $algo
                $file_report
                return
            } elseif (!$isHashUnsupported) {
                warn "$app`: Hash not found. Will search by url instead."
            }
        } catch [Exception] {
            $exit_code = $exit_code -bor $_ERR_EXCEPTION
            if ($_.Exception.Response.StatusCode -eq 404) {
                $file_report_not_found = $true
                warn "$app`: File report not found. Will search by url instead."
            } else {
                if ($_.Exception.Response.StatusCode -in 204, 429) {
                    abort "$app`: VirusTotal request failed`: $($_.Exception.Message)" $exit_code
                }
                warn "$app`: VirusTotal request failed`: $($_.Exception.Message)"
                return
            }
        }

        try {
            $ok, $url_report = Test-VirusTotalUrl $url $app -ReturnObject
            if (-not $ok) {
                warn "$app`: Unable to get url report for $url, $url_report"
                throw $url_report.ErrorMsg
            }
            $url_report.'App.Hash' = $hash
            $url_report.'App.HashType' = $algo
            if ($url_report.'UrlReport.Hash' -and ($file_report_not_found -eq $true) -and $hash) {
                if ($algo -eq 'sha256') {
                    if ($url_report.'UrlReport.Hash' -eq $hash) {
                        warn "$app`: Manual file upload is required (instead of url submission) for $url"
                    } else {
                        error "$app`: Hash not matched for $url"
                    }
                } else {
                    error "$app`: Hash not matched or manual file upload is required (instead of url submission) for $url"
                }
                $url_report
                return
            }
            if (!$url_report.'UrlReport.Hash') {
                $url_report
                return
            }
        } catch [Exception] {
            $exit_code = $exit_code -bor $_ERR_EXCEPTION
            if ($_.Exception.Response.StatusCode -eq 404) {
                warn "$app`: Url report not found. Will submit $url"
                Submit-ToVirusTotal $url $app ($opt.scan -or $opt.s)
                return
            } else {
                if ($_.Exception.Response.StatusCode -in 204, 429) {
                    abort "$app`: VirusTotal request failed`: $($_.Exception.Message)" $exit_code
                }
                warn "$app`: VirusTotal request failed`: $($_.Exception.Message)"
                return
            }
        }

        try {
            $file_report = Test-VirusTotalHash $url_report.'UrlReport.Hash' $url $app -ReturnObject
            $file_report.'App.Hash' = $hash
            $file_report.'App.HashType' = $algo
            $file_report.'UrlReport.Url' = $url_report.'UrlReport.Url'
            $file_report
            warn "$app`: Unable to check hash match for $url"
        } catch [Exception] {
            $exit_code = $exit_code -bor $_ERR_EXCEPTION
            if ($_.Exception.Response.StatusCode -eq 404) {
                warn "$app`: File report not found for unknown reason. Manual file upload is required (instead of url submission)."
                $url_report
            } else {
                if ($_.Exception.Response.StatusCode -in 204, 429) {
                    abort "$app`: VirusTotal request failed`: $($_.Exception.Message)" $exit_code
                }
                warn "$app`: VirusTotal request failed`: $($_.Exception.Message)"
                return
            }
        }
    }
}
if ($opt.p -or $opt.'passthru') {
    $reports
}

exit $exit_code
