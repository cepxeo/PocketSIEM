Function Get-WinEventData {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0 )]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]
        $Event,

        [string]$Prefix = 'e_'
    )

    Process
    {
        #Loop through provided events
        foreach($entry in $event)
        {
            #Get the XML...
            $XML = [xml]$entry.ToXml()

            #Some events use other nodes, like 'UserData' on Applocker events...
            $XMLData = $null
            if( $XMLData = @( $XML.Event.EventData.Data ) )
            {
                For( $i=0; $i -lt $XMLData.count; $i++ )
                {
                    #We don't want to overwrite properties that might be on the original object, or in another event node.
                    $Entry = Add-Member -InputObject $entry -MemberType NoteProperty -Name "$Prefix$($XMLData[$i].name)" -Value $XMLData[$i].'#text' -Force -Passthru
                }
            }
            $Entry
        }
    }
}

# !! Specify the host to upload logs !!
# Example $url = 'https://mydomain.com'

$url = '<DOMAIN>'
$hostname = hostname
$DateAfter = (Get-Date).AddDays(-1)
$DateBefore = (Get-Date)

# !! Specify the username and password !!

$user = 'someuser'
$pass = 'somepassword'

$pair = "$($user):$($pass)"

$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))

$basicAuthValue = "Basic $encodedCreds"

$Headers = @{
    Authorization = $basicAuthValue
}

# Change the system time format to conform with SQLite
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy-MM-dd"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"

# Check connectivity

$status = Invoke-WebRequest -Uri $url/logins -Headers $Headers | select-object StatusCode

If ($status.StatusCode -ne 200) {
    Write-Host "Server is not reachable!"
    Exit
}

# Extract events and uploads via POST

# Successful Logins
Get-WinEvent -FilterHashtable @{Logname='security';id=4624; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | ? { ($_.e_TargetUserName -notmatch '^system.*')} | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;user=$_.e_TargetUserName;logon_type=$_.e_LogonType}; Invoke-WebRequest -Uri $url/logins -Method POST -Body $postParams -Headers $Headers}

# Failed Logins (event)
$event = "Login failed"
Get-WinEvent -FilterHashtable @{Logname='security';id=4625; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_TargetUserName;details=$_.e_LogonType}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams}

# Created processes
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=1; StartTime = $DateAfter; EndTime = $DateBefore} -max 1000 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;image=$_.e_Image;company=$_.e_Company;command_line=$_.e_CommandLine}; Invoke-WebRequest -Uri $url/processes -Method POST -Body $postParams -Headers $Headers}

# Network connections
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=3; StartTime = $DateAfter; EndTime = $DateBefore} -max 1000 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;image=$_.e_Image;dest_ip=$_.e_DestinationIP;dest_port=$_.e_DestinationPort}; Invoke-WebRequest -Uri $url/net -Method POST -Body $postParams -Headers $Headers}

# Sysmon state changes (event)
$event = "Sysmon state changed"
$image = ""
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=4; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$image;details=$_.e_State}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Load unsigned drivers (event)
$event = "Not signed driver loaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=6; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | ? { ($_.e_SignatureStatus -notmatch '^valid.*')} | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_ImageLoaded;details=$_.e_Signature}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Load unsigned DLLs (event) - Disabled due to high volume of false positives
# $event = "Not signed DLL loaded"
# Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=7; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | ? { ($_.e_SignatureStatus -notmatch '^valid.*')} | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_Image;details=$_.e_ImageLoaded}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams}

# File created (event)
$event = "File created"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=11; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_Image;details=$_.e_TargetFilename}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Registry object added or deleted (event)
$event = "Registry object added or deleted"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=12; StartTime = $DateAfter; EndTime = $DateBefore} | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_Image;details=$_.e_EventType + $_.e_TargetObject}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Cleaning the logs locally to prevent duplication on upload
WevtUtil cl "Microsoft-Windows-Sysmon/Operational"
WevtUtil cl "Security"