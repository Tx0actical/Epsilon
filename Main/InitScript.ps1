        # ********************Zero Section********************

# This section will first check the registry value that is set when the computer is restarted in the middle of script execution.
# If the value is set, then the script will continue from where it left off (addtional logic will be required to do that).
# If the value is not set, then the script will start from the beginning.

# &&&&&&&&&& OR &&&&&&&&&&

# The restart can be handled in the end after the output dispatch center gives a green light after the result of all the functions are determined. In the meantime, restarts can be kept pending.

Write-Host "[+] Importing Modules" -ForegroundColor Blue

Start-Sleep -Seconds 1

try {
    Import-Module -Name Microsoft.PowerShell.Diagnostics
    Import-Module -Name Microsoft.PowerShell.Utility
    Import-Module -Name Microsoft.PowerShell.Management

    Import-Module .\LargeFunc.psm1
    
} catch {
    Write-Host "[-] Unable To Import Necessary Modules" -ForegroundColor Red
}

# Script records itself into the event log, for determination of last runtime.
try {
    New-EventLog    -LogName "PowerShellCore/Operational" -Source "PowerShellCore" -Message "EpsilonScript Instance"
} catch {
    Write-Host "[-] Unable To Create a Script Event" -ForegroundColor Red
}
try {
    Write-EventLog  -LogName "PowerShellCore/Operational" -Source "PowerShellCore" -EventID 4104 -Message "EpsilonScript Instance"  
}
catch {
    Write-Host "[-] Unable To Write To Script Event" -ForegroundColor Red
}
try {
    Get-WinEvent    -LogName "PowerShellCore/Operational" -MaxEvents 1
}
catch {
    Write-Host "[-] Unable To Read From Script Event" -ForegroundColor Red
}

# Function to set RunOnce registry value to 1. This will prevent the script from running again after the computer is restarted.
function Set_RunOnce_Registry_Key_Before_Restart_Handle_Function {
    # Set the RunOnce key
    Write-Host "[*] Setting the RunOnce Registry key" -ForegroundColor Yellow
    $Global:RegistryPath    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $Global:RegistryName    = "LastRestartCausedByScript"
    $Global:RegistryValue   = "Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -Verb RunAs -ArgumentList $PSCommandPath"
    New-Item            -Path $Global:RegistryPath -Name $Global:RegistryName
    New-ItemProperty    -Path $Global:RegistryPath -Name $Global:RegistryName -Value $Global:RegistryValue -PropertyType "String"
}
        # ********************END OF -> Zero Section********************
        
        # ********************Pre-Initialization Section********************

        
# Get OS version
$Global:HostOSVersion = Get-ComputerInfo | Select-Object WindowsProductName
$Global:HostPowershellVersion = $PSVersionTable.PSVersion 
$Global:IncompatibleOSVersion = @('Windows Server 2012', 'Windows Server 2008 R2', 'Windows 8.1')
$Global:MinimumRequiredPowershellVersion = [PSCustomObject]@{
    Major = 7
    Minor = 2 
}
$Global:CurrentDate = Get-Date -DisplayHint Date -Format "MM/dd/yyyy"
$Global:RegistryPath
$Global:RegistryName
$Global:RegistryValue  

$Global:CurrentDate                                         = $null
$Global:LastDiskOptimizeDate                                = $null
$Global:DaysSinceDiskLastOptimized                          = $null
$Global:VolumeNumber                                        = $null
$Global:LastSytemRebootDate                                 = $null
$Global:RestartStatusVariable                               = $null

# $Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS                = $null
# $Global:SFA_SFC_EXECUTION_FUNCTION_STATUS                   = $null
# $Global:SFA_DISM_EXECUTION_FUNCTION_STATUS                  = $null
# $Global:UA_SYS_UPDATE_FUNCTION_STATUS                       = $null
# $Global:UA_STORE_UPDATE_FUNCTION_STATUS                     = $null
# $Global:UA_DRIVER_UPDATE_FUNCTION_STATUS                    = $null
# $Global:NOP_DNS_UPDATE_FUNCTION_STATUS                      = $null
# $Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS                    = $null
# $Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS                  = $null
# $Global:NOP_LSO_DISABLE_FUNCTION_STATUS                     = $null
# $Global:NOP_ATUN_DISABLE_FUNCTION_STATUS                    = $null
# $Global:NOP_QOS_DISABLE_FUNCTION_STATUS                     = $null

# $Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS                  = $null
# $Global:MRO_TEMP_UPDATE_FUNCTION_STATUS                     = $null
# $Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS               = $null
# $Global:SA_DFNDR_DISABLE_EXECUTION_STATUS                   = $null
# $Global:SA_PR_HANDLE_FUNCTION_STATUS                        = $null

# $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED               = $null
# $Global:SET_SFA_SFC_NODE_RESULT_DETERMINED                  = $null
# $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED                 = $null
# $Global:SET_UA_SYS_UPDATE_NODE_RESULT_DETERMINED            = $null
# $Global:SET_UA_STORE_UPDATE_NODE_RESULT_DETERMINED          = $null
# $Global:SET_UA_DRIVER_UPDATE_NODE_RESULT_DETERMINED         = $null
# $Global:SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED           = $null
# $Global:SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED         = $null
# $Global:SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED       = $null
# $Global:SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED          = $null
# $Global:SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED         = $null
# $Global:SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED          = $null
# $Global:SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED          = $null
# $Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED                 = $null
# $Global:SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED          = $null
# $Global:SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED    = $null
# $Global:SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED         = $null
# $Global:SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED             = $null

# $Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS        = $null
# $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS       = $null

# Search for the PreviousStateFile in the current directory, that should be by the name of Resume.json
$Global:PreviousStateFile = Get-ChildItem -Path $PSScriptRoot -Recurse -ErrorAction SilentlyContinue -Force

function Resume_Script_Execution_With_Previous_State_Handle_Function {

    $DaysSinceScriptLastRun     = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Days
    $HoursSinceScriptLastRun    = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Hours
    $MinutesSinceScriptLastRun  = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Minutes
    $SecondsSinceScriptLastRun  = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Seconds

    # 300 seconds, a typical time to restart
    # TODO -> This logic is probably not sufficient, or even incorrect. A deeper look is required to make it more robust.
    if(($DaysSinceScriptLastRun -eq 0) -and ($HoursSinceScriptLastRun -eq 0) -and ($MinutesSinceScriptLastRun -eq 0) -and ($SecondsSinceScriptLastRun -ge 300)) {
        if($null -ne (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name "LastRestartCausedByScript")) {

            Write-Host "[*] Checking last boot cause"
            Start-Sleep -Seconds 1
            Write-Host "[+] Last restart was caused by a script instance"
            Start-Sleep -Seconds 1
            Write-Host "[*] Checking last boot cause"
            Start-Sleep -Seconds 1
            Write-Host "[+] RunOnce key successfully set before last restart"
            Start-Sleep -Seconds 1
            Write-Host "[*] Injecting previous instance state in current instance" -ForegroundColor Blue
            Start-Sleep -Seconds 1

            Reload_Previous_Script_Instance_State_Handle_Function
        }
    } else {
        Write-Host "[-] Last restart was not caused by the script"
    }
}

#Requires -Version 7.2.0

        # ********************END OF -> Pre-Initialization Section********************

        # ********************Initialization Section********************

if( -not ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[0]) -or ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[1]) -or ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[2])) {

    Write-Host "[*] Intializing Epsilon" -ForegroundColor Green
    Start-Sleep -Seconds 1
    Write-Host "[*] Do not interrupt execution. Keep the system plugged in. Follow Prompts as they appear." -ForegroundColor Yellow
    Start-Sleep -Seconds 1


        # ********************END OF -> Initialization Section********************


        # ********************Post-Initialization Section********************


    # TO DO: Think about more sources of information for behaviour of Windows Systems

    <#  Function to keep track of inputs after all node probability determination
        functions are true (values determined). Input_Dispatch_Function will supply inputs to handling functions,
        where inputs can be simply of bool type because the probabilities will determine the activation of functions that are described in the sub-sections.
        [Parameter(Mandatory = $True)] flag can be used to determine which function was not assigned a value by the sectional functions
        and that may provide necessary debug information and provide necessary checks during script execution. #>


    function __Input_Dispatch_Center_Control_Function__ {
        [CmdletBinding()] param(


            [Parameter(Position = 0,  Mandatory = $True)] [bool] $Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS   ,


            [Parameter(Position = 1,  Mandatory = $True)] [bool] $Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS           ,
            [Parameter(Position = 2,  Mandatory = $True)] [bool] $Global:SFA_SFC_EXECUTION_FUNCTION_STATUS              ,
            [Parameter(Position = 3,  Mandatory = $True)] [bool] $Global:SFA_DISM_EXECUTION_FUNCTION_STATUS             ,

            [Parameter(Position = 4,  Mandatory = $True)] [bool] $Global:UA_SYS_UPDATE_FUNCTION_STATUS                  ,
            [Parameter(Position = 5,  Mandatory = $True)] [bool] $Global:UA_STORE_UPDATE_FUNCTION_STATUS                ,
            [Parameter(Position = 6,  Mandatory = $True)] [bool] $Global:UA_DRIVER_UPDATE_FUNCTION_STATUS               ,

            [Parameter(Position = 7,  Mandatory = $True)] [bool] $Global:NOP_DNS_UPDATE_FUNCTION_STATUS                 ,
            [Parameter(Position = 8,  Mandatory = $True)] [bool] $Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS               ,
            [Parameter(Position = 9,  Mandatory = $True)] [bool] $Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS             ,
            [Parameter(Position = 10, Mandatory = $True)] [bool] $Global:NOP_LSO_DISABLE_FUNCTION_STATUS                ,
            [Parameter(Position = 11, Mandatory = $True)] [bool] $Global:NOP_ATUN_DISABLE_FUNCTION_STATUS               ,
            [Parameter(Position = 12, Mandatory = $True)] [bool] $Global:NOP_QOS_DISABLE_FUNCTION_STATUS                ,

            [Parameter(Position = 14, Mandatory = $True)] [bool] $Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS             ,
            [Parameter(Position = 15, Mandatory = $True)] [bool] $Global:MRO_TEMP_UPDATE_FUNCTION_STATUS                ,
            [Parameter(Position = 16, Mandatory = $True)] [bool] $Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS          ,

            [Parameter(Position = 17, Mandatory = $True)] [bool] $Global:SA_DFNDR_DISABLE_EXECUTION_STATUS              ,
            [Parameter(Position = 18, Mandatory = $True)] [bool] $Global:SA_PR_HANDLE_FUNCTION_STATUS
        )

        Write-Host "[*] Checking Probabilistic Activation Determination Sub-Section Intitialization" -ForegroundColor Blue

        if($Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS -eq $True) {

            Write-Host "[+] Sub-Section initialization completed" -ForegroundColor Green

        # ***************Base Information Sub-Section***************

            # function Get_System_Information_Handle_Function {
            #     # Get system information on the host
            #     
            # }

            function Parse_Windows_Event_Log_Handle_Function {

                <#  Parse specific events, count their number subsequent blocks will try to run specific lines of code. Each try block will have an associated boolean variable that will keep track
                    of successful or unsuccessful execution of that particular block. In the end of the function, all these variables will be together tested
                    for true status, in an 'AND' construct. If any single one of them is false a result of unsuccessful execution
                    then a boolean variable that finally determines the state of the current function will be set to true or false accordingly.

                    variables in this function should be global #>
                
                # Debugging outputs
                Write-Host "[+] Date today is $Global:CurrentDate" -ForegroundColor Blue

                # Get disk defragmentor logs. This is inside a try block because if the system drives were never optimized then that statement may throw an error or might
                # display nothing. The docs might tell that. So try block is used to be on the safer side.
                try {
                    $Global:LastDiskOptimizeDate = Get-WinEvent -FilterHashtable @{logname="Application"; id=258} | Select-Object TimeCreated | Select-Object -First 1
                }
                catch {
                    Write-Host "[-] Could not find Defrag Logs" -ForegroundColor Red
                }

                # Necessary formatting
                $Global:LastDiskOptimizeDate = $Global:LastDiskOptimizeDate -split " " -split "="
                $Global:LastDiskOptimizeDate = $Global:LastDiskOptimizeDate | Select-Object -Skip 1 | Select-Object -First 1

                # Days passed since the disk was optimized
                $Global:DaysSinceDiskLastOptimized = New-TimeSpan -Start $Global:LastDiskOptimizeDate -End $CurrentDate | Select-Object Days

                # Maybe unnecessary formatting (better method might be available, but I don't know that yet)
                $Global:DaysSinceDiskLastOptimized = $Global:DaysSinceDiskLastOptimized -split "{" -split "=" 
                $Global:DaysSinceDiskLastOptimized = $Global:DaysSinceDiskLastOptimized | Select-Object -Skip 2 | Select-Object -First 1
                $Global:DaysSinceDiskLastOptimized = $Global:DaysSinceDiskLastOptimized -split "}"
                $Global:DaysSinceDiskLastOptimized = $Global:DaysSinceDiskLastOptimized | Select-Object -First 1

                # Debug outputs
                Write-Host "[+] Disk was optimized $Global:DaysSinceDiskLastOptimized days ago" -ForegroundColor Yellow  

                # Optimise-Volume Cmdlet will help here
                # Add additional parameters!
            }

            try {
                Parse_Windows_Event_Log_Handle_Function
            } catch {
                Write-Host "[-] Could not parse Windows Event Logs" -ForegroundColor Red
            }

                # ***************END OF -> Base Information Sub-Section***************

            # ***************System Files Audit Sub-Section***************

            

            if($Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS -eq $True) {
                function Run_Chkdsk_Utility_Execution_Function {

                    Write-Host "[*] Running CheckDisk Utility" -ForegroundColor Yellow
    
                    # Determine volumes present in the system, and run chkdsk on all those volumes
                    $Volume = Get-Volume
                    $Global:VolumeNumber = $Volume.Count
                    $i = 0

                    foreach ($Letter in $Volume.DriveLetter) {
                        if($i -eq $Global:VolumeNumber) {
                            break
                        } else {
                            # run chkdsk on all volumes
                            Write-Host "[*] Currently checking drive: $($Volume.DriveLetter[$i])" -ForegroundColor Yellow
                            chkdsk "$($Volume.DriveLetter[$i]):" /r
                            if($LASTEXITCODE -eq 0) {

                                Write-Host "[+] No errors were found." -ForegroundColor Green
                            } elseif ($LASTEXITCODE -eq 1) {

                                Write-Host "[+] Errors were found and fixed." -ForegroundColor Green
                            } elseif ($LASTEXITCODE -eq 2) {

                                Write-Host "[+] Performed disk cleanup (such as garbage collection) or did not perform cleanup because /f was not specified." -ForegroundColor Green
                            } elseif ($LASTEXITCODE -eq 3) {

                                Write-Host "[-] Could not check the disk, errors could not be fixed, or errors were not fixed because /f was not specified." -ForegroundColor Red
                            }
                            $i++
                        }
                    }
    
                    $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED = $True
                }
                
                # Function call
                Run_Chkdsk_Utility_Execution_Function
            }
            
            if($Global:SFA_SFC_EXECUTION_FUNCTION_STATUS) {
                function Run_Sfc_Utility_Execution_Function {

                    Write-Host "[*] Running System File Check" -ForegroundColor Yellow
                    # run sfc
                    sfc /scannow
                    
                    # rough code start
                    if($LASTEXITCODE -eq 0) {
                        $ComputerName = Get-ComputerInfo | Select-Object CsCaption
                        $ComputerName = $ComputerName.CsCaption
                        Import-Module -Name Microsoft.PowerShell.Management
                        Restart-Computer -ComputerName $ComputerName -Wait -For "Powershell" -Timeout 200 # -wait parameter doesn't work on local system

                        # rough code end
                        $Global:SET_SFA_SFC_NODE_RESULT_DETERMINED = $True
                    }   
                }
                # Function call
                Run_Sfc_Utility_Execution_Function
            }

            if($Global:SFA_DISM_EXECUTION_FUNCTION_STATUS) {
                function Run_Dism_Utility_Execution_Function {

                    Write-Host "[*] Running DISM" -ForegroundColor Yellow
                    $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Run_Dism_Utility_Execution_Function
            }

            # ***************END OF -> System Files Audit Sub-Section***************

            # ***************Update Application Sub-Section***************

            if($Global:UA_SYS_UPDATE_FUNCTION_STATUS) {
                function Update_Windows_System_Handle_Function {

                    Write-Host "[+] Updating Windows" -ForegroundColor Blue
                    # Determine Windows updated or not (can use a boolean variable after calling Update_Windows_System_Handle_Function and determine its result)
                    Install-Module PSWindowsUpdate
                    $UpdateVariable = Get-WindowsUpdate
                    $UpdateVariable = $UpdateVariable | Select-Object ComputerName -First 1

                    # [!] This is working unexpectedly, opposite of expected behaviour [!]
                    if ($UpdateVariable -contains @{ComputerName = Get-ComputerInfo | Select-Object CsCaption}) {
                        # $UpdateVariable = $False
                        Write-Host "[-] No Updates were found" -ForegroundColor Blue
                    } else {
                        # $UpdateVariable = $True
                        Write-Host "[*] Updates found, installing" -ForegroundColor Yellow
                    }
                    $Global:SET_UA_SYS_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Update_Windows_System_Handle_Function
            }
            
            if($Global:UA_STORE_UPDATE_FUNCTION_STATUS) {
                function Update_Microsoft_Store_Application_Handle_Function {

                    Write-Host "[*] Updating Microsoft Store Applications" -ForegroundColor Blue
                    # update using winget
                    Write-Host "[*] Checking Microsoft Store Application updates" -ForegroundColor Yellow
                    $UpdateCheck = winget upgrade
                    if($null -eq $UpdateCheck) {
                        Write-Host "[-] No updates were found" -ForegroundColor Blue
                    } else {
                        Write-Host "[*] Updates found, installing" -ForegroundColor Green
                        winget upgrade --all
                    }
                    $Global:SET_UA_STORE_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Update_Microsoft_Store_Application_Handle_Function
            }
            
            if($Global:UA_DRIVER_UPDATE_FUNCTION_STATUS) {
                function Update_Windows_System_Drivers_Handle_Function {

                    Write-Host "[*] Checking Windows System Drivers Updates" -ForegroundColor Yellow
                    # If the PowerShell Modules Folder is non-existing, it will be created.
                    if ($false -eq (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules)) {
                        New-Item -ItemType Directory -Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules1 -Force
                    }
                    # Import the PowerShell Module
                    Install-Module -Name PSWindowsUpdate
                    # Specify the path usage of Windows Update registry keys
                    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
                    
                    # Updates and Driver download
                    
                    # If the necessary keys are non-existing, they will be created
                    if ($false -eq (Test-Path $Path\WindowsUpdate)) {
                        New-Item -Path $Path -Name WindowsUpdate
                        New-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -PropertyType DWord -Value '0'
                        New-ItemProperty $Path\WindowsUpdate -Name WUServer -PropertyType DWord -Value $null
                        New-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -PropertyType DWord -Value $null
                    } else {
                        # If the value of the keys are incorrect, they will be modified
                        try {
                            Set-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -value "0" -ErrorAction SilentlyContinue
                            Set-ItemProperty $Path\WindowsUpdate -Name WUServer -Value $null -ErrorAction SilentlyContinue
                            Set-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -Value $null -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Output '[*] Skipped modifying registry keys' -ForegroundColor Yellow
                        }
                    }
                    # Add ServiceID for Windows Update
                    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false

                    # Pause and give the service time to update
                    Start-Sleep 30

                    # Scan against Microsoft, accepting all drivers
                    Get-WUInstall -MicrosoftUpdate -AcceptAll

                    # Scaning against Microsoft for all Driver types, and accepting all
                    Get-WUInstall -MicrosoftUpdate Driver -AcceptAll

                    # Scanning against Microsoft for all Software Updates, and installing all, ignoring a reboot
                    Get-WUInstall -MicrosoftUpdate Software -AcceptAll -IgnoreReboot

                    $Global:SET_UA_SYS_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Update_Windows_System_Drivers_Handle_Function
            }

            # ***************END OF -> Update Application Sub-Section***************

            # ***************Network Optimization Sub-Section***************

            if($Global:NOP_DNS_UPDATE_FUNCTION_STATUS) {
                function Change_Dns_Server_Update_Function {

                    Write-Host "[+] Changing DNS to Google's public DNS" -ForegroundColor Blue
                    # First, determine the active interface that is connected to internet
                    Get-CimInstance Win32_NetworkAdapter -Filter "netconnectionstatus = 2" | Select-Object netconnectionid, name, InterfaceIndex, netconnectionstatus
                    # Note down InterfaceAlias name
                    Get-DnsClientServerAddress
                    # change IPv4 and IPv6 DNS servers
                    Set-DNSClientServerAddress "InterfaceAlias" –ServerAddresses ("8.8.8.8", "8.8.4.4")
                    # clear DNS cache
                    Clear-DnsClientCache

                    $Global:SET_NOP_DNS_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Change_Dns_Server_Update_Function
            }

            if($Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS) {
                function Change_Irp_Stack_Size_Update_Function {

                    Write-Host "[+] Increasing IRPStackSize value from default to 32" -ForegroundColor Blue
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize"
                    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Value 0x00000020
                    $Global:SET_NOP_IRPSS_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Change_Irp_Stack_Size_Update_Function
            }

            if($Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS) {
                function Configure_Background_Applications_Settings_Handle_Function {

                    Write-Host "[+] Disabling background apps" -ForegroundColor Blue
                    Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
                    $Global:SET_NOP_BAPP_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Configure_Background_Applications_Settings_Handle_Function
            }

            if($Global:NOP_LSO_DISABLE_FUNCTION_STATUS) {
                function Disable_Large_Send_Offload_Handle_Function {

                    Write-Host "[+] Disabling Large Send Offload" -ForegroundColor Blue
                    $Global:Adapter = Get-NetAdapter -physical | Where-Object status -eq 'up'
                    foreach ($Object in $Global:Adapter) {
                        Disable-NetAdapterLso -Name $Object -IPv6 -IPv4
                    }
                    $Global:SET_NOP_LSO_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Disable_Large_Send_Offload_Handle_Function
            }

            if($Global:NOP_ATUN_DISABLE_FUNCTION_STATUS) {
                function Disable_Windows_Auto_Tuning_Handle_Function {

                    Write-Host "[+] Disabling Windows Auto Tuning" -ForegroundColor Blue
                    netsh int tcp set global autotuninglevel=disabled
                    netsh int tcp set global autotuninglevel=normal
                    $Global:SET_NOP_ATUN_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Disable_Windows_Auto_Tuning_Handle_Function
            }

            if($Global:NOP_QOS_DISABLE_FUNCTION_STATUS) {
                function Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function {

                    Write-Host "[+] Disabling QoS Packet Scheduler" -ForegroundColor Blue
                    foreach ($Object in $Global:Adapter) {
                        Disable-NetAdapterQos -Name $Object
                    }
                    $Global:SET_NOP_QOS_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function
            }

            # ***************END OF -> Network Optimization Sub-Section***************

            # ***************Memory Resource Optimization Sub-Section***************

            if($Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS) {
                function Run_Disk_Defragmentor_Execution_Function {

                    Write-Host "[*] Runnig Disk Defragmentor" -ForegroundColor Yellow
                    # Determine volumes present in the system, and run chkdsk on all those volumes
                    $Volume = Get-Volume
                    foreach ($Letter in $Volume.DriveLetter) {
                        Get-PhysicalDisk | Where-Object {$_.MediaType -eq "SSD"}
                        Optimize-Volume -DriveLetter $Letter -Verbose
                    }
                    $Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Run_Disk_Defragmentor_Execution_Function
            }

            if($Global:MRO_TEMP_UPDATE_FUNCTION_STATUS) {
                function Remove_Temp_Files_Update_Function {

                    Write-Host "[+] Purging Windows TEMP files" -ForegroundColor Blue
                    Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse
                    $Global:SET_MRO_TEMP_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Remove_Temp_Files_Update_Function
            }

            if($Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS) {
                function Set_Increase_Pagefile_Size_Update_Function {

                    # TODO -> Get-WmiObject is not supported, in PowerShell 7, check other methods
                    # TODO -> Code needs improvement in this function

                    # Check if pagefiles are automatically managed
                    if($null -eq (Get-CimInstance Win32_Pagefile)) {
                        $sys = Get-WmiObject Win32_Computersystem –EnableAllPrivileges
                        $sys.AutomaticManagedPagefile = $false
                        $sys.put()

                        # Check pagefile size
                        Get-WmiObject WIN32_Pagefile | Select-Object Name, InitialSize, MaximumSize, FileSize
                        $Pagefile = Get-WmiObject Win32_PagefileSetting | Where-Object {$_.name -eq “C:\pagefile.sys”}
                        if($Pagefile -eq 40000) {
                            $Pagefile.InitialSize = 40000 # in MB
                            $Pagefile.MaximumSize = 80000
                            $Pagefile.put()
                        }
                    } else {
                        $Pagefile = Get-WmiObject Win32_PagefileSetting | Where-Object {$_.name -eq “C:\pagefile.sys”}
                        $Pagefile.InitialSize = 40000 # in MB
                        $Pagefile.MaximumSize = 80000
                        $Pagefile.put()
                    }
                    $Global:SET_MRO_INC_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Set_Increase_Pagefile_Size_Update_Function
            }

            # ***************END OF -> Memory Resource Optimization Sub-Section***************

            # ***************Security Audit Sub-Section***************

            if($Global:SA_DFNDR_DISABLE_EXECUTION_STATUS) {
                function Run_Windows_Defender_Scan_Execution_Function {

                    # Check defender status
                    if(((Get-MpComputerStatus).AntivirusEnabled) -eq "True") {
                        Write-Host "[+] Starting Windows Defender"  -ForegroundColor Green
                        Start-Sleep -Seconds 3
                        Write-Host "[*] Performing a Quick Scan"    -ForegroundColor Blue
                        Update-MpSignature
                        Start-MpScan -ScanType QuickScan
                        Remove-MpThreat
                    }
                    $Global:SET_SA_DFNDR_NODE_RESULT_DETERMINED = $True
                }

                # Function call
                Run_Windows_Defender_Scan_Execution_Function
            }

            if($Global:SA_PR_HANDLE_FUNCTION_STATUS) {
                function Analyze_Processes_Handle_Function {

                    Get-Process | Where-Object -FilterScript {$_.Responding -eq $false} | Stop-Process
                    $Global:SET_SA_PR_NODE_RESULT_DETERMINED = $True

                    # TODO -> Add more parameters to the definition of 'Suspicious Processes'
                }

                # Function call
                Analyze_Processes_Handle_Function
            }
            
            # more things can be included in this Sub-Section, as it relates to Security
            # PC can be checked if it is connected to a domain and all security scanning relating to domain can be then applied

            # ***************END OF -> Security Audit Sub-Section***************

            # ********************END OF -> Post-Initialization Section********************


    } else {
        Write-Host "[-] Probabilistic Activation Determination Sub-Section initialization failed" -ForegroundColor Red 
    }

    # if the value of $MASTER_INPUT_DISPATCH_CENTER_FUNCTION_STATUS is set to true then control-flow will continue
    # that will happen only when the Base Information Sub-Section is properly initialized. Hence, this variable acts as a checker.
}

    # ********************Probabilistic Activation Determination (PAD) Section********************


    <#  Functions within this section provides input to the section containing the __Input_Dispatch_Center_Control_Function__ function. Earlier, this Section was a Sub-section
        (until commit -> 27bb259), but it has been converted because it essentially computes values and pass it to __Input_Dispatch_Center_Control_Function__ function which ACTUALLY
        does the changes described in that. So, a Section giving input to itself isn't a great idea - it wouldn't affect the functioning of code per se, because these functions are divided
        into the so-called 'Sections and Sub-Sections' on the basis of comments just to keep track of complexity - as it might be a source of confusion. #>


        # ***************PAD Sub-Section-1***************

        <#  The reason why separate functions are required to pass the values to __Input_Dispatch_Center_Control_Function__ when it can be done right within the Perceptron functions is because all the issues require
        their own separate result and that is possible by having separate functions of handling each issue. #>

    function Forward_StopError_Remediation_Parameters_Fowarding_Function {
        <#  here parameters mean which functions are required to be called in case Part-1 of PAD has determined StopError events 
            as a regular happening that necessitates remedial actions defined in the functions to fix a particular type of error, in this case a StopError #>

        # This function will take input from the Perceptron that determines the activation of the functions
        
        Write-Host "[+] Problem Determined : Stop Errors" -ForegroundColor Green

        # This call to IDCCF is incomplete because
            # 1. The NN should plug the values in the function call statement.
            # 2. Function call parenthesis are missing.
        
        # TODO -> Complete the call statement in such a way that the Network.ps1 script can fill in the IDCCF parameters at runtime.
        
        __Input_Dispatch_Center_Control_Function__
    }

    function Forward_Memory_Optimizing_Parameters_Fowarding_Function {
        # Forwards the output of model to IDCCF, to determine function activations.

        Write-Host "[+] Problem Determined : Bad Memory" -ForegroundColor Green
        
        # This call to IDCCF is incomplete because
            # 1. The NN should plug the values in the function call statement.
            # 2. Function call parenthesis are missing.
        
        # TODO -> Complete the call statement in such a way that the Network.ps1 script can fill in the IDCCF parameters at runtime.
        
        __Input_Dispatch_Center_Control_Function__
    }

    function Forward_Security_Optimization_Parameters_Forwarding_Function {

        # Forwards the output of the model to IDCCF, to determine function activations.

        Write-Host "[+] Problem Determined : Poor Security Controls" -ForegroundColor Green

        # This call to IDCCF is incomplete because
            # 1. The NN should plug the values in the function call statement.
            # 2. Function call parenthesis are missing.
        
        # TODO -> Complete the call statement in such a way that the Network.ps1 script can fill in the IDCCF parameters at runtime.
        
        __Input_Dispatch_Center_Control_Function__

    }

    function Forward_Network_Optimization_Parameters_Forwarding_Function {
        # Forwards the output of the model to IDCCF, to determine function activations.

        Write-Host "[+] Problem Determined : Poor Network Configuration" -ForegroundColor Green

        # This call to IDCCF is incomplete because
            # 1. The NN should plug the values in the function call statement.
            # 2. Function call parenthesis are missing.
        
        # TODO -> Complete the call statement in such a way that the Network.ps1 script can fill in the IDCCF parameters at runtime.
        
        __Input_Dispatch_Center_Control_Function__
    }

    

        # ***************END OF -> PAD Sub-Section-1***************

        # ***************PAD Sub-Section-2***************

        # Individul Perceptrons to determine activation of functions depending upon the number of contributing factors
    function Invoke_Perceptron_For_Stop_Error_Parameters_Activation_Determination_Function {
        <#  This function determines activations of specific functions that might help resolve stop errors.
            The inputs will be the number of events that have been detected with respect to stop errors, which will be fetched from the Windows Event Logs.
            The weights will be the impact of a function in resolving the problem. Higher impact functions will have more weight.
            Bad driver configuration, Software updates, Hardware failures, Memory failures, Power failures, Disk Errors might be the cause #>

        Write-Host "[*] Checking if Stop Errors is a potential problem vector" -ForegroundColor Yellow
        Start-Sleep -Seconds 1

        Write-Host "[+] Injecting Log Data into Model" -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        # TODO -> Code [BELOW] to feed parsed event log data into the perceptron. To determine if stop errors is a problem.

        Write-Host "[*] Determining Appropriate Function Calls" -ForegroundColor Blue
        Start-Sleep -Seconds 1

        # Function call to forward function activation variables to IDCCF
        Forward_StopError_Remediation_Parameters_Fowarding_Function

    }

    Invoke_Perceptron_For_Stop_Error_Parameters_Activation_Determination_Function

    function Invoke_Perceptron_For_Memory_Opmitization_Parameters_Activation_Determination_Function {
        # This function determines activations of specific functions that might help troubleshoot and optimize memory.

        # Can check for memory failues, by using Windows Memory Diagnostics.
        Write-Host "[*] Checking if memory failures if a problem vector" -ForegroundColor Yellow
        Start-Sleep -Seconds 1

        Write-Host "[+] Injecting Log Data into Model" -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        # TODO -> Code [BELOW] to feed parsed event log data into the perceptron. To determine if memory is a problem.

        Write-Host "[*] Determining Appropriate Function Calls" -ForegroundColor Blue
        Start-Sleep -Seconds 1
        
        # Function call to forward function activation variables to IDCCF
        Forward_Memory_Optimizing_Parameters_Fowarding_Function
    }

    Invoke_Perceptron_For_Memory_Opmitization_Parameters_Activation_Determination_Function

    function Invoke_Perceptron_For_Security_Audit_Parameters_Activation_Determination_Function {
        <#  This function will check if relevant security controls are present like Windows Defender logs, or logs generated by third-party AV software, wether or not scanning is done.
            This might include system updates and other parameters related to security. And the most relevant functions that can solve the problem will be assigned higher weights. #>
        
        Write-Host "[*] Checking if poor security controls are a problem vector" -ForegroundColor Yellow
        Start-Sleep -Seconds 1

        Write-Host "[+] Injecting Log Data into Model" -ForegroundColor Cyan
        Start-Sleep -Seconds 1
        # TODO -> Code to feed parsed event log data into the perceptron. To determine if bad security controls are present. 

        Write-Host "[*] Determining Appropriate Function Calls" -ForegroundColor Blue
        Start-Sleep -Seconds 1

        # Function call to forward function activation variables to IDCCF
        Forward_Security_Optimization_Parameters_Forwarding_Function
    }

    Invoke_Perceptron_For_Security_Audit_Parameters_Activation_Determination_Function

    function Invoke_Perceptron_For_Network_Opmitization_Parameters_Activation_Determination_Function {
        <#  This function will evaluate the network connection and performance, and try to optimize them.
            Input parameters can be connection speed, or simply the presence of parameters that #>

        Write-Host "[*] Checking if Current Network configuration is a problem vector" -ForegroundColor Yellow
        Start-Sleep -Seconds 1

        Write-Host "[+] Injecting Log Data into Model" -ForegroundColor Cyan
        Start-Sleep -Seconds 1

        # TODO -> Code [BELOW] to feed parsed event log data into the perceptron. To determine if network configuration is not optimized. 

        Write-Host "[*] Determining Appropriate Function Calls" -ForegroundColor Blue
        Start-Sleep -Seconds 1

        # Function call to forward function activation variables to IDCCF
        Forward_Network_Optimization_Parameters_Forwarding_Function
    }

    Invoke_Perceptron_For_Network_Opmitization_Parameters_Activation_Determination_Function

        # ***************END OF -> PAD Sub-Section-2***************


        # ********************Output Handling Section********************


    <#  Output function will collect exit codes from all executed,
        functions and will give a green light when all are boolean true
        after that the system might proceed to restart for a final time #>

    function __Output_Dispatch_Center_Control_Function__ {
        <#  if all functions determine their outputs successfully, then this function will set the
            $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS to true, and if that is true then the system will be ready for final restart.
            This will set the $Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS which will be responsible for restarting the system. #>

        if($Global:SET_SFA_SFC_NODE_RESULT_DETERMINED -or $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED -or $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED) {
            Write-Host "[+] System Files Checking Section successfully determined all results" -ForegroundColor Green

            if($Global:SET_UA_SYS_NODE_RESULT_DETERMINED -or $Global:SET_UA_STORE_NODE_RESULT_DETERMINED -or $Global:SET_UA_DRIVER_NODE_RESULT_DETERMINED) {
                Write-Host "[+] Application Update Section successfully determined all results" -ForegroundColor Green

                if($Global:SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED) {
                    Write-Host "[+] Network Optimization Section successfully determined all results" -ForegroundColor Green

                    if($Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED -or $Global:SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED -or $Global:SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED) {
                        Write-Host "[+] Memory Resource Optimization Section successfully determined all results" -ForegroundColor Green

                        if($Global:SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED) {
                            Write-Host "[*] All Section results determined successfully, preparing final steps" -ForegroundColor Blue

                            # if all the above are true then the system will be ready for final restart and $Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS will be set to true
                            $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS = $True

                        } else {
                            Write-Host "[!] Security Audit Section Failed" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "[!] Memory Resource Optimization Section Failed" -ForegroundColor Red
                    }
                } else {
                    Write-Host "[!] Network Optimization Section Failed" -ForegroundColor Red
                }
            } else {
                Write-Host "[!] Update Application Section Failed" -ForegroundColor Red
            }
        } else {
            Write-Host "[!] System Files Section Failed" -ForegroundColor Red
        }
    }

    __Output_Dispatch_Center_Control_Function__ 

    <#  When everything is okay, system will restart for finally although this behaviour can be updated
        because of potiential restarts in between the script. For eg., when the system updates some 
        registry values, among other things. That might be a pain for the user.

        Another version to handle restart-needed-to-apply-changes, is to postpone the restart until all the operations are
        completed and then restarting the system, instead of restarting the system right away, in the middle of script execution. #>

    function Set_Ready_For_Final_Restart_Handle_Function {
        [CmdletBinding()] param(
            [Parameter(Mandatory=$true, Position=0)] [bool] $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS
        )
        
        if($Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS) {
            # set execution policy to default before final shutdown
            Set-ExecutionPolicy -ExecutionPolicy Default

            # restart the system
            shutdown -r -t 0
        }
    }

        # ********************END OF -> Output Handling Section********************

} else {
    Write-Host "[!] The script can't run on Windows Server 2012, Windows Server 2008 R2 and Windows 8.1" -ForegroundColor White -BackgroundColor Red
    Write-Host "[*] Exiting..." -ForegroundColor White -BackgroundColor Blue
}

