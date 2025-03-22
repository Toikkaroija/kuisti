param (

    [string]$logName,
    [string]$remoteEndpointIpAddress,
    [uint16]$remoteEndpointPort,

    [hashtable]$monitoredEventIds = @{
    
        4624="loggedIn";
        4647="loggedOut";
        4800="lockedManual";
        4801="unlocked";
        4802="lockedAuto"
        
    }

)



function Send-Log([IPAddress]$remoteEndpointIpAddress, [uint16]$remoteEndpointPort, $data) {

    try {

        $tcpClient  = New-Object System.Net.Sockets.TcpClient
        $kuistiEndpoint = New-Object System.Net.IPEndPoint($remoteEndpointIpAddress, $remoteEndpointPort)
        $tcpClient.Connect($kuistiEndpoint)
        $netStream  = $tcpClient.GetStream()
        [Byte[]]$buffer = [System.Text.Encoding]::UTF8.GetBytes($data)
        $netStream.Write($buffer, 0, $buffer.Length)
        $netStream.Flush()

    } finally {

        If ($netStream) { $netStream.Dispose() }
        If ($tcpClient) { $tcpClient.Dispose() }

    }

}



Write-Host "Initializing..."

$computersArray =  Get-ADGroupMember -Identity 'WEFComputers' | % {$_.name + '.' + (Get-ADDomain).DNSRoot} 
$computersHashtable = @{}
$startTime = (Get-Date).ToUniversalTime().ToString('o')

foreach ($computer in $computersArray) {

    $computersHashtable[$computer] = $startTime

    try {

        $lastRecordTime = (Get-WinEvent -LogName $logName -FilterXPath "Event[System[Provider[@Name='Microsoft-Windows-Security-Auditing']]] and Event[System[Computer='$computer']]" -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime().ToString('o')
        $computersHashtable[$computer] = $lastRecordTime

    } catch {
    
        continue

    }

}

Write-Host "Initialization complete."
Write-Host "Starting to follow logfile $logName..."



while ($true) {

    #Get-WinEvent @winEventArgs -ErrorAction SilentlyContinue | ForEach-Object {

    $lastRecordTime = (Get-Date).ToUniversalTime().ToString('o')

    foreach ($computer in $computersArray) {

        $xmlQuery = @"
<QueryList>
  <Query Id="0" Path="$logName">
    <Select Path="$logName">*[System[(Computer='$computer') and ($($($monitoredEventIds.keys | %{"EventID=$_"}) -join ' or ')) and TimeCreated[@SystemTime&gt;'$($computersHashtable[$computer])' and @SystemTime&lt;'$lastRecordTime']]]</Select>
  </Query>
</QueryList>
"@

        $newEvents = Get-WinEvent -FilterXML $xmlQuery -Oldest -ErrorVariable err -ErrorAction SilentlyContinue

        if ($err) { continue }

        if ($newEvents.Length -gt 0) {

            foreach ($newEvent in $newEvents) {

                [xml]$newEventAsXml = $newEvent.ToXml()
                $userName = $newEventAsXml.Event.SelectSingleNode("//*[@Name='TargetUserName']") | select -ExpandProperty '#text'

                try {
            
                    if ((Get-ADUser -Identity "$userName").Enabled -ne $true) { continue }

                    # $computerHostname = $newEventAsXml.Event.SelectSingleNode("//*[@Name='workstationName']") | Select-Object -ExpandProperty '#text'
                    $userUpn = (Get-ADUser -Identity "$userName").userPrincipalName

                    if (($userUpn -eq '') -or ($userUpn -eq $null)) { continue }

                    $computerIpv4Address = (Resolve-DnsName -Name $computer -Type A).IPAddress

                    $log = @{
                
                        user=$userUpn;
                        hostname=$computer;
                        Ipv4Address=$computerIpv4Address;
                        event=$monitoredEventIds[[int]$newEvent.Id]

                    }

                    $log = $log | ConvertTo-Json -Compress

                    #while (-not $tcpConnection.Connected) {
                    
                    #    Write-Host "loop"
                    #    $streamWriter = Connect-Kuisti -remoteEndpointIpAddress $remoteEndpointIpAddress -remoteEndpointPort $remoteEndpointPort

                    #}

                    Send-Log -remoteEndpointIpAddress $remoteEndpointIpAddress -remoteEndpointPort $remoteEndpointPort -data $log

                } catch {
            
                    # Write-Host "Käyttäjää '$userName' ei löydy AD-hakemistosta."
                    continue

                }

            }

            $computersHashtable[$computer] = $newEvents[-1].TimeCreated.ToUniversalTime().ToString('o')

        }

    }

    Start-Sleep -Seconds 1

}