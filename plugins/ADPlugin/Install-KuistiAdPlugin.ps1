param (

    [string]$logName,
    [string]$serviceUserName,
    [string]$remoteEndpointIpAddress,
    [uint16]$remoteEndpointPort

)

$password = Read-Host -Prompt "Write the password for the kuisti service account" -AsSecureString

New-Item -Path "C:\Program Files" -Name "Kuisti" -ItemType "directory" -Force
Copy-Item -Path ".\KuistiAdPlugin.ps1" -Destination "C:\Program Files\Kuisti" -Force

Add-ADGroupMember -Identity "Event Log Readers" -Members "$serviceUserName"


$staArgs = @{

    Execute = "powershell.exe"
    Argument = "-File `"C:\Program Files\Kuisti\KuistiAdPlugin.ps1`" -logName `"$logname`" -remoteEndpointIpAddress `"$remoteEndpointIpAddress`" -remoteEndpointPort $remoteEndpointPort"
    WorkingDirectory = "C:\Program Files\Kuisti"

}

$action = New-ScheduledTaskAction @staArgs
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Delay = "PT1M" # Tarvitsee minuutin viiveen. muutoin suoritus epäonnistuu heti käynnistyksen yhteydessä.
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
$settings.ExecutionTimeLimit = "PT0S" # Määritä tehtävä olemaan päällä ikuisesti.

$rstArgs = @{

    TaskName = "KuistiAdManager"
    Action = $action
    Trigger = $trigger
    User = "$env:USERDOMAIN\$serviceUserName"
    Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    Settings = $settings

}

Register-ScheduledTask @rstArgs