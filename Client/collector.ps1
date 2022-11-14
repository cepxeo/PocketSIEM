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

# !! Provide the token value !!

$tokenValue = 'YOUR_TOKEN'

$Headers = @{
    'x-access-tokens' = $tokenValue
}

# Change the system time format to conform with SQLite
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy-MM-dd"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"

# Check connectivity

$status = Invoke-WebRequest -Uri $url/healthcheck -Headers $Headers | select-object StatusCode

If ($status.StatusCode -ne 200) {
    Write-Host "Server is not reachable!"
    Exit
}

## Windows Security events

# Successful Logins
Get-WinEvent -FilterHashtable @{Logname='security';id=4624} -max 1000 | Get-WinEventData `
    | ? { ($_.e_TargetUserName -notmatch '^system.*')}`
    | foreach{$postParams = @{`
        date=$_.TimeCreated;`
        host=$hostname;`
        osuser=$_.e_TargetUserName;`
        logon_type=$_.e_LogonType;`
        process_name=$_.e_ProcessName};`
        Invoke-WebRequest -Uri $url/logins -Method POST -Body $postParams -Headers $Headers}

# Failed Logins (event)
$event = "Login failed"
Get-WinEvent -FilterHashtable @{Logname='security';id=4625} | Get-WinEventData `
    | foreach{$postParams = @{`
        date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_TargetUserName;`
        details=$_.e_LogonType};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Account created (event)
$event = "User Account Created"
Get-WinEvent -FilterHashtable @{Logname='security';id=4720} | Get-WinEventData `
    | foreach{$postParams = @{`
        date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_SubjectDomainName + $_.e_SubjectUserName;`
        details=$_.e_TargetDomainName + $_.e_TargetUserName};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Sched task created
$event = "Scheduled task created"
Get-WinEvent -FilterHashtable @{Logname='security';id=4698} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_TaskName;`
        details=$_.e_SubjectUserName};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Sched task deleted
$event = "Scheduled task deleted"
Get-WinEvent -FilterHashtable @{Logname='security';id=4699} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_TaskName;`
        details=$_.e_SubjectUserName};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

## Sysmon events

# Event ID 1: Created processes
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=1} -max 1000 | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        parent_image=$_.e_ParentImage;`
        parent_command_line=$_.e_ParentCommandLine;`
        image=$_.e_Image;`
        company=$_.e_Company;`
        description=$_.e_Description;`
        product=$_.e_Product;`
        original_file_name=$_.e_OriginalFileName;`
        process_user=$_.e_User;`
        command_line=$_.e_CommandLine};`
        Invoke-WebRequest -Uri $url/processes -Method POST -Body $postParams -Headers $Headers}

# Event ID 3: Network connections
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=3} -max 1000 | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        image=$_.e_Image;`
        dest_ip=$_.e_DestinationIP + $_.e_DestinationHostname;`
        dest_port=$_.e_DestinationPort};`
        Invoke-WebRequest -Uri $url/net -Method POST -Body $postParams -Headers $Headers}

# Event ID 4: Sysmon state changes (event)
$event = "Sysmon state changed"
$image = ""
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=4} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$image;`
        details=$_.e_State};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 6: Load unsigned drivers (event)
$event = "Not signed driver loaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=6} | Get-WinEventData `
    | ? { ($_.e_SignatureStatus -notmatch '^valid.*')} `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_ImageLoaded;`
        details=$_.e_Signature};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 7: Load unsigned DLLs (event) - Disabled due to high volume of false positives
$event = "Not signed DLL loaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=7} | Get-WinEventData `
    | ? { ($_.e_SignatureStatus -notmatch '^valid.*')} `
        | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_Image;`
        details=$_.e_ImageLoaded};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 8: CreateRemoteThread
$event = "Proc Inj CreateRemoteThread"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=8} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_SourceImage;`
        details=$_.e_TargetImage + $_.e_SourceUser};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 11: File created (event)
$event = "File created"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=11} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        image=$_.e_Image;`
        filename=$_.e_TargetFilename;`
        osuser=$_.e_User};`
        Invoke-WebRequest -Uri $url/files -Method POST -Body $postParams -Headers $Headers}

# Event ID 12: Registry object added or deleted (event)
$event = "Registry object added or deleted"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=12} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_Image;`
        details=$_.e_EventType + $_.e_TargetObject};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 13: Registry object modified - Disabled due to high volume of false positives
$event = "Registry object modified"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=13} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_Image;`
        details=$_.e_EventType + $_.e_TargetObject};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 15: Alternate data stream
$event = "File downloaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=15} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.e_Image;`
        details=$_.e_TargetFilename + $_.e_User};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 16: Sysmon ServiceConfigurationChange
$event = "Sysmon config changed"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=16} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image=$_.UserId;`
        details=$_.e_Configuration};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 17: PipeEvent (Pipe Created) TODO
$event = "Pipe Created"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=17} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image="";`
        details=""};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 18: PipeEvent (Pipe Connected) TODO
$event = "Pipe Connected"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=18} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image="";`
        details=""};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 19: WmiEvent (WmiEventFilter activity detected) TODO
$event = "WmiEventFilter activity"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=19} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image="";`
        details=""};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 20: WmiEvent (WmiEventConsumer activity detected) TODO
$event = "WmiEventConsumer activity"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=20} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image="";`
        details=""};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected) TODO
$event = "WmiEventConsumerToFilter activity"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=21} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image="";`
        details=""};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Event ID 25: ProcessTampering (Process image change) TODO
$event = "Process Tampering"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=25} | Get-WinEventData `
    | foreach{$postParams = @{date=$_.TimeCreated;`
        host=$hostname;`
        event=$event;`
        image="";`
        details=""};`
        Invoke-WebRequest -Uri $url/events -Method POST -Body $postParams -Headers $Headers}

# Cleaning the logs locally to prevent duplication on upload
WevtUtil cl "Microsoft-Windows-Sysmon/Operational"
WevtUtil cl "Security"

# To list properties: Get-WinEventData | Format-List -Property *
# Select -Property TimeCreated, e_Image, e_DestinationIP, e_DestinationPort
# Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="2022-10-30 05:10:20"; EndTime="2022-11-10 16:00:00"}