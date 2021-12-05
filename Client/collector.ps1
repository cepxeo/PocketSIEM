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

$hostname = hostname
$url = '<DOMAIN>'
$DateAfter = (Get-Date).AddDays(-1)
$DateBefore = (Get-Date)

Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy-MM-dd"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"

# Successful Logins
Get-WinEvent -FilterHashtable @{Logname='security';id=4624; StartTime = $DateAfter; EndTime = $DateBefore} -max 20 | Get-WinEventData | ? { ($_.e_TargetUserName -notmatch '^system.*')} | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;user=$_.e_TargetUserName;logon_type=$_.e_LogonType}; Invoke-WebRequest -Uri $url/logins -Method POST -Body $postParams}

# Failed Logins (event)
$event = "Login failed"
Get-WinEvent -FilterHashtable @{Logname='security';id=4625; StartTime = $DateAfter; EndTime = $DateBefore} -max 100 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_TargetUserName;details=$_.e_LogonType}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams}

# Created processes
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=1; StartTime = $DateAfter; EndTime = $DateBefore} -max 100 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;image=$_.e_Image;company=$_.e_Company;command_line=$_.e_CommandLine}; Invoke-WebRequest -Uri $url/processes -Method POST -Body $postParams}

# Network connections
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=3; StartTime = $DateAfter; EndTime = $DateBefore} -max 100 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;image=$_.e_Image;dest_ip=$_.e_DestinationIP;dest_port=$_.e_DestinationPort}; Invoke-WebRequest -Uri $url/net -Method POST -Body $postParams}

# Sysmon state changes (event)
$event = "Sysmon state changed"
$image = ""
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=4; StartTime = $DateAfter; EndTime = $DateBefore} -max 10 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$image;details=$_.e_State}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams}

# Load unsigned drivers (event)
$event = "Driver loaded with unvalid signature"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=6; StartTime = $DateAfter; EndTime = $DateBefore} -max 10 | Get-WinEventData | ? { ($_.e_SignatureStatus -notmatch '^valid.*')} | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_ImageLoaded;details=$_.e_Signature}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams}

# Registry object added or deleted (event)
$event = "Registry object added or deleted"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=12; StartTime = $DateAfter; EndTime = $DateBefore} -max 10 | Get-WinEventData | foreach{$postParams = @{date=$_.TimeCreated;host=$hostname;event=$event;;image=$_.e_Image;details=$_.e_EventType + $_.e_TargetObject}; Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams}