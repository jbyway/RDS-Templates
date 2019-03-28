<#
    Copyright 2018 Microsoft
    Version 1.0 June 2018
    .SYNOPSIS
    This is a sample script for automatically scaling Tenant Environment WVD Host Servers in Micrsoft Azure
    .Description
    This script will automatically start/stop Tenant WVD host VMs based on the number of user sessions and peak/off-peak time period specified in the configuration file.
    During the peak hours, the script will start necessary session hosts in the Hostpool to meet the demands of users.
    During the off-peak hours, the script will shutdown the session hosts and only keep the minimum number of session hosts.
    This script depends on 2 powershell modules: Azure RM and WVD Module to get azurerm module execute following command.
    Use "-AllowClobber" parameter if you have more than one version of PS modules installed.
    PS C:\>Install-Module AzureRM  -AllowClobber
    WVD PowerShell Modules included inside this folder "AutoScale-WVD" with name PowerShellModules.
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

<#
    .SYNOPSIS
    Function for writing the log
#>
function Write-Log
{
    param
    (
        [int]$level,
        [string]$Message,

        [ValidateSet("Info", "Warning", "Error")]
        [string]$severity = 'Info',

        [string]$logname = $rdmiTenantlog,
        [string]$color = "white"
    )

    $time = Get-Date
    Add-Content $logname -Value ("{0} - [{1}] {2}" -f $time, $severity, $Message)

    if ($interactive)
    {
        switch ($severity)
        {
            'Error' { $color = 'Red' }
            'Warning' { $color = 'Yellow' }
        }

        if ($level -le $VerboseLogging)
        {
            if ($color -match "Red|Yellow"
            {
                Write-Host ("{0} - [{1}] {2}" -f $time, $severity, $Message) -ForegroundColor $color -BackgroundColor Black
                if ($severity -eq 'Error')
                {
                    throw $Message
                }
            }
            else
            {
                Write-Host ("{0} - [{1}] {2}" -f $time, $severity, $Message) -ForegroundColor $color
            }
        }
    }
    else
    {
        switch ($severity)
        {
            'Info' { Write-Verbose -Message $Message }
            'Warning' { Write-Warning -Message $Message }
            'Error'
            {
                throw $Message
            }
        }
    }
}

<# 
    .SYNOPSIS
    Function for writing the usage log
#>
function Write-UsageLog
{
    param
    (
        [string]$hostpoolName,
        [int]$corecount,
        [int]$vmcount,
        [bool]$depthBool = $True,
        [string]$logfilename = $RdmiTenantUsagelog
    )

    $time = Get-Date
    if ($depthBool)
    {
        Add-Content $logfilename -Value ("{0}, {1}, {2}" -f $time, $hostpoolName, $vmcount)
    }
    else
    {
        Add-Content $logfilename -Value ("{0}, {1}, {2}, {3}" -f $time, $hostpoolName, $corecount, $vmcount)
    }
}

<#
    .SYNOPSIS
    Function for creating variable from XML
#>
function Set-ScriptVariable ($Name, $Value)
{
    Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}

$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path

# XML path
$XMLPath = "$CurrentPath\Config.xml"

# Log path
$rdmiTenantlog = "$CurrentPath\WVDTenantScale.log"

# Usage log path
$RdmiTenantUsagelog = "$CurrentPath\WVDTenantUsage.log"

# Verify XML file
if (Test-Path $XMLPath)
{
    Write-Verbose "Found $XMLPath"
    Write-Verbose "Validating file..."
    try
    {
        $Variable = [xml](Get-Content $XMLPath)
    }
    catch
    {
        $Validate = $false
        Write-Error "$XMLPath is invalid. Check XML syntax - Unable to proceed"
        Write-Log 3 "$XMLPath is invalid. Check XML syntax - Unable to proceed" "Error"
        exit 1
    }
}
else
{
    $Validate = $false
    Write-Error "Missing $XMLPath - Unable to proceed"
    Write-Log 3 "Missing $XMLPath - Unable to proceed" "Error"
    exit 1
}

# Load XML Configuration values as variables
Write-Verbose "loading values from Config.xml"
$Variable = [xml](Get-Content "$XMLPath")
$Variable.RDMIScale.Azure | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.RDMIScale.RdmiScaleSettings | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.RDMIScale.Deployment | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }

# Load functions/module
. $CurrentPath\Functions-PSStoredCredentials.ps1
Import-Module $CurrentPath\PowershellModules\Microsoft.RdInfra.RdPowershell.dll

# Login with delgated admin
$Credential = Get-StoredCredential -UserName $Username

# Setting RDS Context
$isServicePrincipalBool = ($isServicePrincipal -eq "True")

# WVD Authentication
if (-Not $isServicePrincipalBool)
{
    try
    {
        Add-RdsAccount -DeploymentUrl $RDBroker -Credential $Credential
    }
    catch
    {
        Write-Log 1 "Failed to authenticate with WVD Tenant using standard account: $($_.exception.message)" "Error"
        exit 1
    }
    Write-Log 3 "Authenticated as standard account on WVD." "Info"
}
else
{
    try
    {
        Add-RdsAccount -DeploymentUrl $RDBroker -TenantId $AADTenantId -Credential $Credential -ServicePrincipal
    }
    catch
    {
        Write-Log 1 "Failed to authenticate with WVD Tenant using service principal: $($_.exception.message)" "Error"
        exit 1
    }
    Write-Log 3 "Authenticated as service principal account on WVD." "Info"
}

# Azure Authentication
if (-Not $isServicePrincipalBool)
{
    try
    {
        Add-AzureRmAccount -SubscriptionName $currentAzureSubscriptionName -Credential $Credential
    }
    catch
    {
        Write-Log 1 "Failed to authenticate with Azure with standard account: $($_.exception.message)" "Error"
        exit 1
    }
    Write-Log 3 "Authenticated as standard account on Azure." "Info"
}
else
{
    try
    {
       Add-AzureRmAccount -ServicePrincipal -Credential $Credential -TenantId $AADTenantId
    }
    catch
    {
        Write-Log 1 "Failed to authenticate with Azure with service principal: $($_.exception.message)" "Error"
        exit 1
    }
    Write-Log 3 "Authenticated as service principal account on Azure." "Info"
}

# Set context to the appropriate tenant group
Write-Log  1 "Switching to $tenantGroupName context" "Info"
Set-RdsContext -TenantGroupName $tenantGroupName

# Select the current Azure Subscription specified in the config
Select-AzureRmSubscription -SubscriptionName $currentAzureSubscriptionName

# Construct Begin time and End time for the Peak period
$CurrentDateTime = Get-Date
Write-Log 3 "Starting WVD Tenant Hosts Scale Optimization: Current Date Time is: $CurrentDateTime" "Info"

$BeginPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $BeginPeakTime)
$EndPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $EndPeakTime)

#check the calculated end time is later than begin time in case of time zone
if ($EndPeakDateTime -lt $BeginPeakDateTime)
{
    $EndPeakDateTime = $EndPeakDateTime.AddDays(1)
}

$HPInfo = Get-RdsHostPool -TenantName $tenantName -Name $hostPoolName

if ($HPInfo.LoadBalancerType -eq "DepthFirst")
{
    Write-Log 1 "$hostPoolName hostpool loadbalancer type is $($HPInfo.LoadBalancerType)" "Info"

    if (($CurrentDateTime -ge $BeginPeakDateTime) -and ($CurrentDateTime -le $EndPeakDateTime))
    {
        Write-Log 1  "It is in peak hours now" "Info"
        Write-Log 1 "Peak hours: starting session hosts as needed based on current workloads." "Info"

        #Get the session hosts in the hostpool
        try
        {
          $SessionHosts = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname | Sort-Object $_.SessionHostname
        }
        catch
        {
          Write-Log 1 "Failed to retrieve SessionHost in hostpool $($hostPoolName) : $($_.exception.message)" "Info"
          exit
        }

        # ANCHOR would like to understand the logic behind setting up this sessionLimit var
        if ($HPInfo.MaxSessionLimit -le 10)
        {
            $sessionlimit = $HPInfo.MaxSessionLimit - 1  
        }
        elseif ($HPInfo.MaxSessionLimit -le 50)
        {
            $sessionlimitofhost = $HPInfo.MaxSessionLimit / 4
            $sessionlimit = [math]::Round($HPInfo.MaxSessionLimit - $sessionlimitofhost)
        }
        else
        {
            $sessionlimit = $HPInfo.MaxSessionLimit - 10
        }
 
        Write-Log 1 "Hostpool Maximum Session Limit: $($HPInfo.MaxSessionLimit)"

        #check the number of running session hosts
        $numberOfRunningHost = 0
        foreach ($SessionHost in $SessionHosts)
        {
            Write-Log 1 "Checking session host:$($SessionHost.SessionHostName | Out-String) with sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)" "Info"
            
            # ANCHOR why checking ($sessionlimit -lt $SessionHost.Sessions) ?
            if ($sessionlimit -lt $SessionHost.Sessions -or $SessionHost.Status -ieq "Available")
            {
                $numberOfRunningHost += 1
            }
        }

        # ANCHOR why we should test if the number of SHs is lower than minimun in the first place? Shouldn't we control we control this in the shutdown process?
        Write-Log 1  "Current number of running hosts: $numberOfRunningHost" "Info"
        if ($numberOfRunningHost -lt $MinimumNumberOfRDSH)
        {
            Write-Log 1  "Current number of running session hosts is less than minimum requirements, starting session host ..." "Info"

            foreach ($SessionHost in $SessionHosts)
            {
                if ($numberOfRunningHost -lt $MinimumNumberOfRDSH)
                {
                    $hostsessions = $SessionHost.Sessions

                    # ANCHOR not sure if this code was tested, $hostofsessions is always null, maybe it should be hostsessions, why -ne?
                    if ($HPInfo.MaxSessionLimit -ne $hostofsessions)
                    {
                        if ($SessionHost.Status -ieq "UnAvailable")
                        {
                            $SessionHostname = $SessionHost.SessionHostname
                            #Check session host is in Drain Mode
                            $checkAllowNewSession = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $SessionHostname

                            if (-Not ($checkAllowNewSession.AllowNewSession))
                            {
                                Set-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $SessionHostname -AllowNewSession $true
                            }

                            $VMName = $SessionHostname.Split(".")[0]

                            #start the azureRM VM
                            try
                            {
                                Get-AzureRmVM | Where-Object { $_.Name -eq $VMName } | Start-AzureRmVM

                            }
                            catch
                            {
                                Write-Log 1 "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)" "Info"
                                exit
                            }

                            #wait for the SessionHost is available
                            # ANCHOR why is this code needed for?
                            $IsHostAvailable = $false
                            while (!$IsHostAvailable) {

                                $hoststatus = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $SessionHost.SessionHostname

                                if ($hoststatus.Status -eq "Available") {
                                    $IsHostAvailable = $true
                                }
                            }
                        }
                    }
                    $numberOfRunningHost = $numberOfRunningHost + 1
                }
            }
        }
        else
        {
            $SessionHosts = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname | Sort-Object "Sessions" -Descending | Sort-Object Status
            foreach ($SessionHost in $SessionHosts)
            {
                if (!($SessionHost.Sessions -eq $HPInfo.MaxSessionLimit))
                {
                    if ($SessionHost.Sessions -ge $sessionlimit)
                    {
                        foreach ($sHost in $SessionHosts)
                        {
                            if ($sHost.Status -eq "Available" -and $sHost.Sessions -eq 0) { break }
                            if ($sHost.Status -eq "Unavailable") {
                                Write-Log 1 "Existing SessionHost Sessions value reached near by hostpool maximumsession limit need to start the session host" "Info"
                                $SessionHostname = $sHost.SessionHostname
                                #Check session host is in Drain Mode
                                $checkAllowNewSession = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $SessionHostname
                                if (!($checkAllowNewSession.AllowNewSession)) {
                                    Set-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $SessionHostname -AllowNewSession $true
                                }
                                $VMName = $SessionHostname.Split(".")[0]

                                #start the azureRM VM
                                try {
                                    Get-AzureRmVM | Where-Object { $_.Name -eq $VMName } | Start-AzureRmVM
                                }
                                catch {
                                    Write-Log 1 "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)" "Info"
                                    exit
                                }
                                #wait for the SessionHost is available
                                # ANCHOR why is this code needed for?
                                $IsHostAvailable = $false
                                while (!$IsHostAvailable) {

                                    $hoststatus = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $sHost.SessionHostname

                                    if ($hoststatus.Status -eq "Available") {
                                        $IsHostAvailable = $true
                                    }
                                }
                                $numberOfRunningHost = $numberOfRunningHost + 1
                                break
                            }
                        }
                    }
                }
            }
        }
        Write-Log 1  "HostpoolName:$hostpoolname, NumberofRunnighosts:$numberOfRunningHost" "Info"
        $depthBool = $true
        Write-UsageLog $hostPoolName $numberOfRunningHost $depthBool
    }
    else {
        Write-Log 1  "It is Off-peak hours" "Info"
        Write-Log 1  "It is off-peak hours. Starting to scale down RD session hosts..." "Info"
        Write-Log 1  ("Processing hostPool {0}" -f $hostPoolName) "Info"
        try {
            $SessionHosts = Get-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName | Sort-Object Sessions
        }
        catch {
            Write-Log 1 "Failed to retrieve session hosts in hostPool: $($hostPoolName) with error: $($_.exception.message)" "Info"
            exit
        }
        #check the number of running session hosts
        $numberOfRunningHost = 0
        foreach ($SessionHost in $SessionHosts) {
            if ($SessionHost.Status -eq "Available") {
                $numberOfRunningHost = $numberOfRunningHost + 1
            }
        }
        if ($numberOfRunningHost -gt $MinimumNumberOfRDSH) {
            foreach ($SessionHost in $SessionHosts.SessionHostname) {
                if ($numberOfRunningHost -gt $MinimumNumberOfRDSH) {

                    $SessionHostinfo1 = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname -Name $SessionHost
                    if ($SessionHostinfo1.Status -eq "Available") {

                        #ensure the running Azure VM is set as drain mode
                        try {

                            #setting host in drain mode
                            Set-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -Name $SessionHost -AllowNewSession $false -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Log 1 "Failed to set drain mode on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)" "Info"
                            exit
                        }
                        #notify user to log off session
                        #Get the user sessions in the hostPool
                        try {
                            $hostPoolUserSessions = Get-RdsUserSession -TenantName $tenantName -HostPoolName $hostPoolName
                        }
                        catch {
                            Write-ouput "Failed to retrieve user sessions in hostPool: $($hostPoolName) with error: $($_.exception.message)"
                            exit
                        }
                        $hostUserSessionCount = ($hostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostname -eq $SessionHost }).Count
                        Write-Log 1 "Counting the current sessions on the host $SessionHost...:$hostUserSessionCount" "Info"
            
                        $existingSession = 0
                        foreach ($session in $hostPoolUserSessions) {
                            if ($session.SessionHostname -eq $SessionHost) {
                                if ($LimitSecondsToForceLogOffUser -ne 0) {
                                    #send notification
                                    try {
                                        Send-RdsUserSessionMessage -TenantName $tenantName -HostPoolName $hostPoolName -SessionHostName $session.SessionHostname -SessionId $session.sessionid -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." -NoUserPrompt:$false
                                    }
                                    catch {
                                        Write-Log 1 "Failed to send message to user with error: $($_.exception.message)" "Info"
                                        exit
                                    }
                                }

                                $existingSession = $existingSession + 1
                            }
                        }
                        #wait for n seconds to log off user
                        Start-Sleep -Seconds $LimitSecondsToForceLogOffUser
                        if ($LimitSecondsToForceLogOffUser -ne 0) {
                            #force users to log off
                            Write-Log 1  "Force users to log off..." "Info"
                            try {
                                $hostPoolUserSessions = Get-RdsUserSession -TenantName $tenantName -HostPoolName $hostPoolName

                            }
                            catch {
                                Write-Log 1 "Failed to retrieve list of user sessions in hostPool: $($hostPoolName) with error: $($_.exception.message)" "Info"
                                exit
                            }
                            foreach ($session in $hostPoolUserSessions) {
                                if ($session.SessionHostname -eq $SessionHost) {
                                    #log off user
                                    try {

                                        Invoke-RdsUserSessionLogoff -TenantName $tenantName -HostPoolName $hostPoolName -SessionHostName $session.SessionHostname -SessionId $session.sessionid -NoUserPrompt:$false
                                        $existingSession = $existingSession - 1

                                    }
                                    catch {
                                        Write-ouput "Failed to log off user with error: $($_.exception.message)"
                                        exit
                                    }
                                }
                            }
                        }
                        $VMName = $SessionHost.Split(".")[0]
                        #check the session count before shutting down the VM
                        if ($existingSession -eq 0) {
                            #shutdown the Azure VM
                            try {
                                Write-Log 1 "Stopping Azure VM: $VMName and waiting for it to complete ..." "Info"
                                Get-AzureRmVM | Where-Object { $_.Name -eq $VMName } | Stop-AzureRmVM -Force
                            }
                            catch {
                                Write-Log 1 "Failed to stop Azure VM: $VMName with error: $_.exception.message" "Info"
                                exit
                            }
                        }
                        #decrement the number of running session host
                        $numberOfRunningHost = $numberOfRunningHost - 1
                    }
                }
            }
      
        }
        Write-Log 1  "HostpoolName:$hostpoolname, NumberofRunnighosts:$numberOfRunningHost" "Info"
        $depthBool = $true
        Write-UsageLog $hostPoolName $numberOfRunningHost $depthBool
    }
    Write-Log 3 "End WVD Tenant Scale Optimization." "Info"
}
else {
    Write-Log 3 "$hostPoolName hostpool loadbalancer type is $($HPInfo.LoadBalancerType)" "Info"
    #check if it is during the peak or off-peak time
    if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
        Write-Host "It is in peak hours now"
        Write-Log 3 "Peak hours: starting session hosts as needed based on current workloads." "Info"
        #Get the Session Hosts in the hostPool		
        try {
            $RDSessionHost = Get-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log 1 "Failed to retrieve RDS session hosts in hostPool $($hostPoolName) : $($_.exception.message)" "Error"
            exit 1
        }

        #Get the User Sessions in the hostPool
        try {
            $hostPoolUserSessions = Get-RdsUserSession -TenantName $tenantName -HostPoolName $hostPoolName
        }
        catch {
            Write-Log 1 "Failed to retrieve user sessions in hostPool:$($hostPoolName) with error: $($_.exception.message)" "Error"
            exit 1
        }

        #check the number of running session hosts
        $numberOfRunningHost = 0

        #total of running cores
        $totalRunningCores = 0

        #total capacity of sessions of running VMs
        $AvailableSessionCapacity = 0

        foreach ($SessionHost in $RDSessionHost.SessionHostname) {
            Write-Log 1 "Checking session host: $($SessionHost)" "Info"
           
            $VMName = $SessionHost.Split(".")[0]
            $roleInstance = Get-AzureRmVM -Status | Where-Object { $_.Name.Contains($VMName) }
            if ($SessionHost.ToLower().Contains($roleInstance.Name.ToLower())) {
                #check the azure vm is running or not      
                if ($roleInstance.PowerState -eq "VM running") {
                    $numberOfRunningHost = $numberOfRunningHost + 1
                    #we need to calculate available capacity of sessions						
                    $roleSize = Get-AzureRmVMSize -Location $roleInstance.Location | Where-Object { $_.Name -eq $roleInstance.HardwareProfile.VmSize }
                    $AvailableSessionCapacity = $AvailableSessionCapacity + $roleSize.NumberOfCores * $SessionThresholdPerCPU
                    $totalRunningCores = $totalRunningCores + $roleSize.NumberOfCores
                }

            }

        }
        Write-Log 1 "Current number of running hosts:$numberOfRunningHost" "Info"

        if ($numberOfRunningHost -lt $MinimumNumberOfRDSH) {

            Write-Log 1 "Current number of running session hosts is less than minimum requirements, start session host ..." "Info"

            #start VM to meet the minimum requirement            
            foreach ($SessionHost in $RDSessionHost.SessionHostname) {

                #check whether the number of running VMs meets the minimum or not
                if ($numberOfRunningHost -lt $MinimumNumberOfRDSH) {

                    $VMName = $SessionHost.Split(".")[0]
                    $roleInstance = Get-AzureRmVM -Status | Where-Object { $_.Name.Contains($VMName) }

                    if ($SessionHost.ToLower().Contains($roleInstance.Name.ToLower())) {

                        #check if the azure VM is running or not
                        if ($roleInstance.PowerState -ne "VM running") {
                            $getShsinfo = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostPoolName

                            if ($getShsinfo.AllowNewSession -eq $false) {
                                Set-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -Name $SessionHost -AllowNewSession $true

                            }
                            #start the azure VM
                            try {
                                Start-AzureRmVM -Name $roleInstance.Name -Id $roleInstance.Id -ErrorAction SilentlyContinue
                            }
                            catch {
                                Write-Log 1 "Failed to start Azure VM: $($roleInstance.Name) with error: $($_.exception.message)" "Error"
                                exit 1
                            }
                            #wait for the VM to start
                            $IsVMStarted = $false
                            while (!$IsVMStarted) {

                                $vm = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }

                                if ($vm.PowerState -eq "VM running" -and $vm.ProvisioningState -eq "Succeeded") {
                                    $IsVMStarted = $true
                                    Set-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -Name $SessionHost -AllowNewSession $true
                                }
                            }
                            # we need to calculate available capacity of sessions
                            $vm = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }
                            $roleSize = Get-AzureRmVMSize -Location $roleInstance.Location | Where-Object { $_.Name -eq $roleInstance.HardwareProfile.VmSize }
                            $AvailableSessionCapacity = $AvailableSessionCapacity + $roleSize.NumberOfCores * $SessionThresholdPerCPU
                            $numberOfRunningHost = $numberOfRunningHost + 1
                            $totalRunningCores = $totalRunningCores + $roleSize.NumberOfCores
                            if ($numberOfRunningHost -ge $MinimumNumberOfRDSH) {
                                break;
                            }
                        }
                    }
                }
            }
        }

        else {
            #check if the available capacity meets the number of sessions or not
            Write-Log 1 "Current total number of user sessions: $(($hostPoolUserSessions).Count)" "Info"
            Write-Log 1 "Current available session capacity is: $AvailableSessionCapacity" "Info"
            if ($hostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
                Write-Log 1 "Current available session capacity is less than demanded user sessions, starting session host" "Info"
                #running out of capacity, we need to start more VMs if there are any 
                foreach ($SessionHost in $RDSessionHost.SessionHostname) {
                    if ($hostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
                        $VMName = $SessionHost.Split(".")[0]
                        $roleInstance = Get-AzureRmVM -Status | Where-Object { $_.Name.Contains($VMName) }

                        if ($SessionHost.ToLower().Contains($roleInstance.Name.ToLower())) {
                            #check if the Azure VM is running or not

                            if ($roleInstance.PowerState -ne "VM running") {
                                $getShsinfo = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostPoolName
                                if ($getShsinfo.AllowNewSession -eq $false) {
                                    Set-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -Name $SessionHost -AllowNewSession $true

                                }
                                #start the Azure VM
                                try {
                                    Start-AzureRmVM -Name $roleInstance.Name -Id $roleInstance.Id -ErrorAction SilentlyContinue

                                }
                                catch {
                                    Write-Log 1 "Failed to start Azure VM: $($roleInstance.Name) with error: $($_.exception.message)" "Error"
                                    exit 1
                                }
                                #wait for the VM to start
                                $IsVMStarted = $false
                                while (!$IsVMStarted) {
                                    $vm = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }

                                    if ($vm.PowerState -eq "VM running" -and $vm.ProvisioningState -eq "Succeeded") {
                                        $IsVMStarted = $true
                                        Write-Log 1 "Azure VM has been started: $($roleInstance.Name) ..." "Info"
                                    }
                                    else {
                                        Write-Log 3 "Waiting for Azure VM to start $($roleInstance.Name) ..." "Info"
                                    }
                                }
                                # we need to calculate available capacity of sessions
                                $vm = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }
                                $roleSize = Get-AzureRmVMSize -Location $roleInstance.Location | Where-Object { $_.Name -eq $roleInstance.HardwareProfile.VmSize }
                                $AvailableSessionCapacity = $AvailableSessionCapacity + $roleSize.NumberOfCores * $SessionThresholdPerCPU
                                $numberOfRunningHost = $numberOfRunningHost + 1
                                $totalRunningCores = $totalRunningCores + $roleSize.NumberOfCores
                                Write-Log 1 "new available session capacity is: $AvailableSessionCapacity" "Info"
                                if ($AvailableSessionCapacity -gt $hostPoolUserSessions.Count) {
                                    break
                                }
                            }
                            #Break # break out of the inner foreach loop once a match is found and checked
                        }
                    }
                }
            }
        }
        Write-Log 1 "HostpoolName:$hostpoolName, TotalRunningCores:$totalRunningCores NumberOfRunningHost:$numberOfRunningHost" "Info"
        #write to the usage log
        $depthBool = $false
        Write-UsageLog $hostPoolName $totalRunningCores $numberOfRunningHost $depthBool
    }
    #} #Peak or not peak hour
    else {
        Write-Host "It is Off-peak hours"
        Write-Log 3 "It is off-peak hours. Starting to scale down RD session hosts..." "Info"
        Write-Host ("Processing hostPool {0}" -f $hostPoolName)
        Write-Log 3 "Processing hostPool $($hostPoolName)"
        #Get the Session Hosts in the hostPool
        try {
            $RDSessionHost = Get-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName
        }
        catch {
            Write-Log 1 "Failed to retrieve session hosts in hostPool: $($hostPoolName) with error: $($_.exception.message)" "Error"
            exit 1
        }
        #check the number of running session hosts
        $numberOfRunningHost = 0

        #total of running cores
        $totalRunningCores = 0

        foreach ($SessionHost in $RDSessionHost.SessionHostname) {

            $VMName = $SessionHost.Split(".")[0]
            $roleInstance = Get-AzureRmVM -Status | Where-Object { $_.Name.Contains($VMName) }

            if ($SessionHost.ToLower().Contains($roleInstance.Name.ToLower())) {
                #check if the Azure VM is running or not

                if ($roleInstance.PowerState -eq "VM running") {
                    $numberOfRunningHost = $numberOfRunningHost + 1

                    # we need to calculate available capacity of sessions  
                    $roleSize = Get-AzureRmVMSize -Location $roleInstance.Location | Where-Object { $_.Name -eq $roleInstance.HardwareProfile.VmSize }

                    $totalRunningCores = $totalRunningCores + $roleSize.NumberOfCores
                }
            }
        }
        if ($numberOfRunningHost -gt $MinimumNumberOfRDSH) {
            #shutdown VM to meet the minimum requirement

            foreach ($SessionHost in $RDSessionHost.SessionHostname) {
                if ($numberOfRunningHost -gt $MinimumNumberOfRDSH) {

                    $VMName = $SessionHost.Split(".")[0]
                    $roleInstance = Get-AzureRmVM -Status | Where-Object { $_.Name.Contains($VMName) }

                    if ($SessionHost.ToLower().Contains($roleInstance.Name.ToLower())) {
                        #check if the Azure VM is running or not

                        if ($roleInstance.PowerState -eq "VM running") {
                            #check the role isntance status is ReadyRole or not, before setting the session host
                            $isInstanceReady = $false
                            $numOfRetries = 0

                            while (!$isInstanceReady -and $num -le 3) {
                                $numOfRetries = $numOfRetries + 1
                                $instance = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }
                                if ($instance -ne $null -and $instance.ProvisioningState -eq "Succeeded") {
                                    $isInstanceReady = $true
                                }
            
                            }

                            if ($isInstanceReady) {
                                #ensure the running Azure VM is set as drain mode
                                try {
                                    Set-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -Name $SessionHost -AllowNewSession $false -ErrorAction SilentlyContinue
                                }
                                catch {

                                    Write-Log 1 "Failed to set drain mode on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)" "Error"
                                    exit 1

                                }

                                #notify user to log off session
                                #Get the user sessions in the hostPool
                                try {

                                    $hostPoolUserSessions = Get-RdsUserSession -TenantName $tenantName -HostPoolName $hostPoolName

                                }
                                catch {
                                    Write-Log 1 "Failed to retrieve user sessions in hostPool: $($hostPoolName) with error: $($_.exception.message)" "Error"
                                    exit 1
                                }

                                $hostUserSessionCount = ($hostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostname -eq $SessionHost }).Count
                                Write-Log 1 "Counting the current sessions on the host $SessionHost...:$hostUserSessionCount" "Info"
                                #Write-Log 1 "Counting the current sessions on the host..." "Info"
                                $existingSession = 0

                                foreach ($session in $hostPoolUserSessions) {

                                    if ($session.SessionHostname -eq $SessionHost) {

                                        if ($LimitSecondsToForceLogOffUser -ne 0) {
                                            #send notification
                                            try {

                                                Send-RdsUserSessionMessage -TenantName $tenantName -HostPoolName $hostPoolName -SessionHostName $SessionHost -SessionId $session.sessionid -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." #-NoConfirm:$false

                                            }
                                            catch {

                                                Write-Log 1 "Failed to send message to user with error: $($_.exception.message)" "Error"
                                                exit 1

                                            }
                                        }

                                        $existingSession = $existingSession + 1
                                    }
                                }
                                #wait for n seconds to log off user
                                Start-Sleep -Seconds $LimitSecondsToForceLogOffUser

                                if ($LimitSecondsToForceLogOffUser -ne 0) {
                                    #force users to log off
                                    Write-Log 1 "Force users to log off..." "Info"
                                    try {
                                        $hostPoolUserSessions = Get-RdsUserSession -TenantName $tenantName -HostPoolName $hostPoolName
                                    }
                                    catch {
                                        Write-Log 1 "Failed to retrieve list of user sessions in hostPool: $($hostPoolName) with error: $($_.exception.message)" "Error"
                                        exit 1
                                    }
                                    foreach ($session in $hostPoolUserSessions) {
                                        if ($session.SessionHostname -eq $SessionHost) {
                                            #log off user
                                            try {

                                                Invoke-RdsUserSessionLogoff -TenantName $tenantName -HostPoolName $hostPoolName -SessionHostName $session.SessionHostname -SessionId $session.sessionid -NoConfirm #:$false

                                                $existingSession = $existingSession - 1
                                            }
                                            catch {
                                                Write-Log 1 "Failed to log off user with error: $($_.exception.message)" "Error"
                                                exit 1
                                            }
                                        }
                                    }
                                }
                                #check the session count before shutting down the VM
                                if ($existingSession -eq 0) {

                                    #shutdown the Azure VM
                                    try {
                                        Write-Log 1 "Stopping Azure VM: $($roleInstance.Name) and waiting for it to complete ..." "Info"
                                        Stop-AzureRmVM -Name $roleInstance.Name -Id $roleInstance.Id -Force -ErrorAction SilentlyContinue

                                    }
                                    catch {
                                        Write-Log 1 "Failed to stop Azure VM: $($roleInstance.Name) with error: $($_.exception.message)" "Error"
                                        exit 1
                                    }
                                    #wait for the VM to stop
                                    $IsVMStopped = $false
                                    while (!$IsVMStopped) {

                                        $vm = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }

                                        if ($vm.PowerState -eq "VM deallocated") {
                                            $IsVMStopped = $true
                                            Write-Log 1 "Azure VM has been stopped: $($roleInstance.Name) ..." "Info"
                                        }
                                        else {
                                            Write-Log 3 "Waiting for Azure VM to stop $($roleInstance.Name) ..." "Info"
                                        }
                                    }
                                    #ensure the Azure VMs that are off have the AllowNewSession mode set to True
                                    try {
                                        Set-RdsSessionHost -TenantName $tenantName -HostPoolName $hostPoolName -Name $SessionHost -AllowNewSession $true -ErrorAction SilentlyContinue
                                    }
                                    catch {
                                        Write-Log 1 "Failed to set drain mode on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)" "Error"
                                        exit 1
                                    }
                                    $vm = Get-AzureRmVM -Status | Where-Object { $_.Name -eq $roleInstance.Name }
                                    $roleSize = Get-AzureRmVMSize -Location $roleInstance.Location | Where-Object { $_.Name -eq $roleInstance.HardwareProfile.VmSize }
                                    #decrement the number of running session host
                                    $numberOfRunningHost = $numberOfRunningHost - 1
                                    $totalRunningCores = $totalRunningCores - $roleSize.NumberOfCores
                                }
                            }
                        }
                    }
                }
            }

        }
        Write-Log 1 "HostpoolName:$hostpoolName, TotalRunningCores:$totalRunningCores NumberOfRunningHost:$numberOfRunningHost" "Info"
        #write to the usage log
        $depthBool = $false
        Write-UsageLog $hostPoolName $totalRunningCores $numberOfRunningHost $depthBool
    } #Scale hostPools
    Write-Log 3 "End WVD Tenant Scale Optimization." "Info"
}