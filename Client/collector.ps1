# ! Specify the domain name to upload logs !
# Example $url = 'https://mydomain.com'
$url = 'MYDOMAIN.COM'

# ! Provide the token value !
$tokenValue = 'YOUR_TOKEN'

$Headers = @{
    'x-access-tokens' = $tokenValue
}

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

# Disables SSL server certificate validation to make use of self signed certs
# Comment out or delete the block below if certificate validation is required
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Change the system time format to conform with DB requirements
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy-MM-dd"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"

# Check connectivity
$status = Invoke-WebRequest -Uri $url/healthcheck -Headers $Headers | select-object StatusCode

If ($status.StatusCode -ne 200) {
    Write-Host "Server is not reachable!"
    Exit
}

$hostname = hostname
Write-Host "Sending logs to the server ..."

$data = [pscustomobject]@{
    logins = @()
    processes = @()
    nets = @()
    files = @()
    events = @()
}
## Windows Security events
# Successful Logins
try { 
$event = "Login successful"
Get-WinEvent -FilterHashtable @{Logname='security';id=4624} -ErrorAction Stop | Get-WinEventData `
    | ? { ($_.e_TargetUserName -notmatch '^system.*') -and ($_.e_LogonType -ne '7')}`
    | foreach {
        $data.logins += @{
            date=$_.TimeCreated
            host=$hostname
            osuser=$_.e_TargetUserName
            logon_type=$_.e_LogonType
            process_name=$_.e_ProcessName
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Failed Logins
try { 
$event = "Login failed"
Get-WinEvent -FilterHashtable @{Logname='security';id=4625} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.logins += @{
            date=$_.TimeCreated
            host=$hostname
            osuser=$_.e_TargetUserName
            logon_type=$_.e_LogonType
            process_name=$_.e_ProcessName
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Account created (event)
try { 
$event = "User Account Created"
Get-WinEvent -FilterHashtable @{Logname='security';id=4720} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_SubjectDomainName + $_.e_SubjectUserName
            details=$_.e_TargetDomainName + $_.e_TargetUserName
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Sched task created
try { 
$event = "Scheduled task created"
Get-WinEvent -FilterHashtable @{Logname='security';id=4698} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_TaskName
            details=$_.e_SubjectUserName
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Sched task deleted
try {
$event = "Scheduled task deleted"
Get-WinEvent -FilterHashtable @{Logname='security';id=4699} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_TaskName
            details=$_.e_SubjectUserName
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# AD object accessed
try {
$event = "AD object accessed"
Get-WinEvent -FilterHashtable @{Logname='security';id=4662} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_SubjectDomainName+$_.e_SubjectUserName
            details=$_.e_ObjectType+$_.e_ObjectName
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 1: Created processes
try { 
$event = "Created processes"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=1} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.processes += @{
            date=$_.TimeCreated
            host=$hostname
            parent_image=$_.e_ParentImage
            parent_command_line=$_.e_ParentCommandLine
            image=$_.e_Image
            company=$_.e_Company
            description=$_.e_Description
            original_file_name=$_.e_OriginalFileName
            process_user=$_.e_User
            command_line=$_.e_CommandLine
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 3: Network connections
try { 
$event = "Network connections"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=3} -max 3000 -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.nets += @{
            date=$_.TimeCreated
            host=$hostname
            image=$_.e_Image
            dest_ip=$_.e_DestinationIP + $_.e_DestinationHostname
            dest_port=$_.e_DestinationPort
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 4: Sysmon state changes (event)
try { 
$event = "Sysmon state changed"
$image = ""
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=4} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$image
            details=$_.e_State
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 6: Load unsigned drivers (event)
try { 
$event = "Not signed driver loaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=6} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_ImageLoaded
            details=$_.e_Signature
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 7: Load unsigned DLLs (event) - Disabled due to high volume of false positives
try { 
$event = "Not signed DLL loaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=7} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_Image
            details=$_.e_ImageLoaded
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 8: CreateRemoteThread
try { 
$event = "Proc Inj CreateRemoteThread"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=8} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_SourceImage
            details=$_.e_TargetImage + $_.e_SourceUser
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 11: File created (event)
try { 
$event = "File created"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=11} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.files += @{
            date=$_.TimeCreated
            host=$hostname
            image=$_.e_Image
            filename=$_.e_TargetFilename
            osuser=$_.e_User
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 12: Registry object added or deleted (event)
try { 
$event = "Registry object added or deleted"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=12} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_Image
            details=$_.e_EventType + $_.e_TargetObject
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 13: Registry object modified
try { 
$event = "Registry object modified"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=13} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_Image
            details=$_.e_EventType + $_.e_TargetObject
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 15: Alternate data stream
try { 
$event = "File downloaded"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=15} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.e_Image
            details=$_.e_TargetFilename + $_.e_User
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 16: Sysmon ServiceConfigurationChange
try { 
$event = "Sysmon config changed"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=16} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=$_.UserId
            details=$_.e_Configuration
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 17: PipeEvent (Pipe Created) TODO
try { 
$event = "Pipe Created"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=17} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=""
            details=""
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 18: PipeEvent (Pipe Connected) TODO
try { 
$event = "Pipe Connected"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=18} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=""
            details=""
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 19: WmiEvent (WmiEventFilter activity detected) TODO
try { 
$event = "WmiEventFilter activity"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=19} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=""
            details=""
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 20: WmiEvent (WmiEventConsumer activity detected) TODO
try { 
$event = "WmiEventConsumer activity"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=20} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=""
            details=""
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 21: WmiEvent (WmiEventConsumerToFilter activity detected) TODO
try { 
$event = "WmiEventConsumerToFilter activity"
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=21} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=""
            details=""
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
# Event ID 25: ProcessTampering (Process image change) TODO
try { 
    $event = "Process Tampering"
    Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-Sysmon/Operational';id=25} -ErrorAction Stop | Get-WinEventData `
    | foreach {
        $data.events += @{
            date=$_.TimeCreated
            host=$hostname
            event=$event
            image=""
            details=""
        }
    }
    Write-Host $event "events parsed"
    }
catch {}
try {
Write-Host "Sending parsed events ..."
Invoke-RestMethod -Uri $url/winlog -Method POST -Body ($data | ConvertTo-Json) -Headers $Headers -ContentType "application/json"
Write-Host "Events successfully sent"

# Cleaning the logs locally to prevent duplication on upload
WevtUtil cl "Microsoft-Windows-Sysmon/Operational"
WevtUtil cl "Security"
    }
catch {}
# To list properties: Get-WinEventData | Format-List -Property *
# Select -Property TimeCreated, e_Image, e_DestinationIP, e_DestinationPort
# Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="2022-10-30 05:10:20"; EndTime="2022-11-10 16:00:00"}