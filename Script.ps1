        # ********************Zero Section********************

        # This section will first check the registry value that is set when the computer is restarted in the middle of script execution.
        # If the value is set, then the script will continue from where it left off (addtional logic will be required to do that).
        # If the value is not set, then the script will start from the beginning.

        function Query_Registry_For_Mid_Execution_Restart_Handle_Function {
            # if it is determined that restart has occured, then control will directly jump to the function after the function which called the restart.
            # else run script from start.
        }

        # ********************END OF -> Zero Section********************
        
        # ********************Pre-Initialization Section********************


# Get OS version
$Global:HostOSVersion = Get-ComputerInfo | Select-Object WindowsProductName
$Global:HostPowershellVersion = $PSVersionTable.PSVersion 
$Global:IncompatibleOSVersion = @('Windows Server 2012',' Windows Server 2008 R2','Windows 8.1')
$Global:MinimumRequiredPowershellVersion = [PSCustomObject]@{
    Major = 7
    Minor = 2 
}

        # ********************END OF -> Pre-Initialization Section********************


        # ********************Initialization Section********************

$Global:CurrentDate = $null
$Global:LastDiskOptimizeDate = $null
$Global:DaysSinceDiskLastOptimized = $null
$Global:VolumeNumber = $null
$Global:LastAbruptSytemRebootDate = $null


# Aadditional requirements can be added into the if below as constraints pop up
if(($Global:HostPowershellVersion.Major -eq $Global:MinimumRequiredPowershellVersion.Major) -and ($Global:HostPowershellVersion.Minor -eq $Global:MinimumRequiredPowershellVersion.Minor)) {
    if( -not ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[0]) -or ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[1]) -or ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[2])) {
        Write-Host "[*] Intializing System-Wide Optimization (SWO) Script."
        Write-Host "[*] Do not interrupt the process once it has started. Irreversible Data Loss and Disk Corruption may occur."

        # # Import user module
        # Import-Module -Name Microsoft.PowerShell.LocalAccounts
        # # Import current user profile
        # $CurrentUser = whoami.exe
        # # Get members of administrators group
        # $IsAdmin = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name

        # # Check if user is Admin and act accordingly
        # if ($IsAdmin -Contains $CurrentUser) {
        #     # Spawn PowerShell with $CurrentUser privileges
        #     Start-Process -FilePath "powershell" -Verb RunAs
        #     # Modify ExecutionPolicy to run scripts
        #     Set-ExecutionPolicy -ExecutionPolicy Bypass
        # }
        # else {
        #     Write-Host "[!] Admin privileges required"  # can write Write-Error or something like that
        # }
        
        # if the user runs the code as administrator then the above code will not be required. But a self elevating script can be used.
        # That way, the user can elevate itself to admin, if not, if the user is admin then, the script will execute all the code below.

        # ********************END OF -> Initialization Section********************


        # ********************Post-Initialization Section********************


        # TO DO: Think about more sources of information for behaviour of Windows Systems


        # Function to keep track of inputs after all node probability determination
        # functions are true (values determined). Input_Dispatch_Function will supply inputs to handling functions,
        # where inputs can be simply of bool type because the probabilities will determine the activation of functions that are described in the sub-sections.
        # [Parameter(Mandatory = $True)] flag can be used to determine which function was not assigned a value by the sectional functions
        # and that may provide necessary debug information.

        # if the system needs to be restarted in between the function. A key must be added to registry indicating that the script must run again after the restart
        # there should be a mechanism to continue the script after the restart, from where the restart was triggered. Either the script can have a dedicated function
        # that will be responsible for the in-between restart. It can set the registry key to indicate that the script must run again after the restart (only one time).
        # a second registry key will save the state of the script before the restart (or a file can be used). Then, the function will resume the script from where it left
        # off, by reading the state either from the registry or from the file. The function will have to redirect execution to function next to the function that caused the 
        # restart.


        function __Input_Dispatch_Center_Control_Function__ { # meaning of cmdletbinding() ?
            [CmdletBinding()] param(
                [Parameter(Position = 0)] [Parameter(Mandatory = $True)] [bool] $Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS,
                [Parameter(Position = 1)] [Parameter(Mandatory = $True)] [bool] $Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 2)] [Parameter(Mandatory = $True)] [bool] $Global:SFA_SFC_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 3)] [Parameter(Mandatory = $True)] [bool] $Global:SFA_DISM_EXECUTION_FUNCTION_STATUS,

                [Parameter(Position = 4)] [Parameter(Mandatory = $True)] [bool] $Global:UA_SYS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 5)] [Parameter(Mandatory = $True)] [bool] $Global:UA_STORE_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 6)] [Parameter(Mandatory = $True)] [bool] $Global:UA_DRIVER_UPDATE_FUNCTION_STATUS,

                [Parameter(Position = 7)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_DNS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 8)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 8)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS,
                [Parameter(Position = 9)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_LSO_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 10)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_ATUN_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 11)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_QOS_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 12)] [Parameter(Mandatory = $True)] [bool] $Global:NOP_P2P_DISABLE_FUNCTION_STATUS,

                [Parameter(Position = 13)] [Parameter(Mandatory = $True)] [bool] $Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 14)] [Parameter(Mandatory = $True)] [bool] $Global:MRO_TEMP_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 15)] [Parameter(Mandatory = $True)] [bool] $Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS,

                [Parameter(Position = 16)] [Parameter(Mandatory = $True)] [bool] $Global:SA_DFNDR_DISABLE_EXECUTION_STATUS,
                [Parameter(Position = 17)] [Parameter(Mandatory = $True)] [bool] $Global:SA_PR_HANDLE_FUNCTION_STATUS
            )


            # ***************Base Information Sub-Section***************

        # function Get_System_Information_Handle_Function {
        #     # Get system information on the host
        #     $HostSystemInfo = Get-ComputerInfo
        #     $HostSystemInfo | Select-Object -ExpandProperty Name
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsProductName
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsBuildNumber
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsEdition
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsBuildType
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsProductId
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsSuseType
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsSuseVersion
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsSuseBuildNumber
        #     $HostSystemInfo | Select-Object -ExpandProperty WindowsSuseEdition
        # }

        # Copilot generated code for function Get_System_Information_Handle_Function

        function Parse_Windows_Event_Log_Handle_Function {
            # Parse specific events, count their number
            # subsequent blocks will try to run specific lines of code. Each try block will have an associated boolean variable that will keep track
            # of successful or unsuccessful execution of that particular block. In the end of the function, all these variables will be together tested
            # for true status, in an 'AND' construct. If any single one of them is false a result of unsuccessful execution
            # then a boolean variable that finally determines the state of the current function will be set to true or false accordingly.

            # variables in this functions should be global

            # Current Date
            $Global:CurrentDate = Get-Date -DisplayHint Date -Format "MM/dd/yyyy"
            # Debugging outputs
            Write-Host "[*] Date today is $Global:CurrentDate" -ForegroundColor White -BackgroundColor Blue

            # Get disk defragmentor logs. This is inside a try block because if the system drives were never optimized then that statement may throw an error or might
            # display nothing. The docs might tell that. So try block is used to be on the safer side.
            try {
                $Global:LastDiskOptimizeDate = Get-WinEvent -FilterHashtable @{logname="Application"; id=258} | Select-Object TimeCreated | Select-Object -First 1
            }
            catch {
                Write-Host "[-] Could not find Defrag Logs" -ForegroundColor White -BackgroundColor Red
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
            # Debugging outputs
            Write-Host "[*] Disk was optimized $Global:DaysSinceDiskLastOptimized days ago" -ForegroundColor White -BackgroundColor Blue

            # Optimise-Volume Cmdlet will help here
            # Add additional parameters!
        }


        # ***************END OF -> Base Information Sub-Section***************


        Write-Host "[*] Checking Probabilistic Activation Determination Sub-Section Intitialization" -ForegroundColor White -BackgroundColor Blue
        if($Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS -eq $True) {
            Write-Host "[*] Sub-Section initialization completed" -ForegroundColor White -BackgroundColor Green

            # ***************System Files Audit Sub-Section***************

            if($Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS) {
                function Run_CHKDSK_Utility_Execution_Function {
                    
                    # determine volumes present in the system
                    # run chkdsk on all those volumes
                    $Volume = Get-Volume
                    $Global:VolumeNumber = $Volume.Count
                    $i = 0
                    foreach ($Letter in $Volume.DriveLetter) {
                        if($i -eq $Global:VolumeNumber) {
                            break
                        } else {
                            # run chkdsk on all volumes
                            Write-Host "[*] Currently checking drive: $($Volume.DriveLetter[$i])"
                            chkdsk "$($Volume.DriveLetter[$i]):" /r
                            if($LASTEXITCODE -eq 0) {
                                Write-Host "[*] No errors were found."
                            } elseif ($LASTEXITCODE -eq 1) {
                                Write-Host "[*] Errors were found and fixed."
                            } elseif ($LASTEXITCODE -eq 2) {
                                Write-Host "[*] Performed disk cleanup (such as garbage collection) or did not perform cleanup because /f was not specified."
                            } elseif ($LASTEXITCODE -eq 3) {
                                Write-Host "[*] Could not check the disk, errors could not be fixed, or errors were not fixed because /f was not specified."
                            }
                            $i++
                        }
                    }
                }
            }
            
            if($Global:SFA_SFC_EXECUTION_FUNCTION_STATUS) {
                function Run_SFC_Utility_Execution_Function {
                    # run sfc
                    sfc /scannow
                    
                    # rough code start
                    # -wait parameter doesn't work on local system
                    # if($LASTEXITCODE -eq 0) {
                    #     $ComputerName = Get-ComputerInfo | Select-Object CsCaption
                    #     $ComputerName = $ComputerName.CsCaption
                    #     Import-Module -Name Microsoft.PowerShell.Management
                    #     Restart-Computer -ComputerName $ComputerName -Wait -For "Powershell" -Timeout 200
                    # rough code end
                    }
                }
            }
            
            if($Global:SFA_DISM_EXECUTION_FUNCTION_STATUS) {
                function Run_DISM_Utility_Execution_Function {

                }
            }

            # ***************END OF -> System Files Audit Sub-Section***************

            # ***************Update Application Sub-Section***************

            if($Global:UA_SYS_UPDATE_FUNCTION_STATUS) {
                function Update_Windows_System_Handle_Function {
                    # Determine Windows updated or not (can use a boolean variable after calling Update_Windows_System_Handle_Function and determine its result)
                    Install-Module PSWindowsUpdate
                    $UpdateVariable = Get-WindowsUpdate
                    $UpdateVariable = $UpdateVariable | Select-Object ComputerName -First 1

                    # [!] This is working unexpectedly, opposite of expected behaviour [!]
                    if ($UpdateVariable -contains @{ComputerName = Get-ComputerInfo | Select-Object CsCaption}) {
                        # $UpdateVariable = $False
                        Write-Host "[*] No Updates were found"
                    } else {
                        # $UpdateVariable = $True
                        Write-Host "[*] Updates found, installing them"
                    }
                }
            }
            
            if($Global:UA_STORE_UPDATE_FUNCTION_STATUS) {
                function Update_Microsoft_Store_Application_Handle_Function {
                    # update using winget
                    Write-Host "[*] Checking Microsoft Store Application updates"
                    $UpdateCheck = winget upgrade
                    if($null -eq $UpdateCheck) {
                        Write-Host "[*] No updates were found"
                    } else {
                        Write-Host "[*] Updates found, installing them"
                        winget upgrade --all
                    }
                }
            }
            
            if($Global:UA_DRIVER_UPDATE_FUNCTION_STATUS) {
                function Update_Windows_System_Drivers_Handle_Function {

                    # &&&&&&&&&& Method 1 &&&&&&&&&&

                    # $UpdateSvc = New-Object -ComObject Microsoft.Update.ServiceManager            
                    # $UpdateSvc.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") 

                    # (New-Object -ComObject Microsoft.Update.ServiceManager).Services

                    # $Session = New-Object -ComObject Microsoft.Update.Session           
                    # $Searcher = $Session.CreateUpdateSearcher() 

                    # $Searcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
                    # $Searcher.SearchScope =  1 # MachineOnly
                    # $Searcher.ServerSelection = 3 # Third Party
                            
                    # $Criteria = "IsInstalled=0 and Type='Driver'"
                    # Write-Host('Searching Driver-Updates...') -Fore Green     
                    # $SearchResult = $Searcher.Search($Criteria)          
                    # $Updates = $SearchResult.Updates
                        
                    # #Show available Drivers...
                    # $Updates | Select-Object Title, DriverModel, DriverVerDate, Driverclass, DriverManufacturer | Format-List

                    # $UpdatesToDownload = New-Object -Com Microsoft.Update.UpdateColl
                    # $updates | ForEach-Object { $UpdatesToDownload.Add($_) | out-null }
                    # Write-Host('Downloading Drivers...')  -Fore Green
                    # $UpdateSession = New-Object -Com Microsoft.Update.Session
                    # $Downloader = $UpdateSession.CreateUpdateDownloader()
                    # $Downloader.Updates = $UpdatesToDownload
                    # $Downloader.Download()

                    # $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl
                    # $updates | % { if($_.IsDownloaded) { $UpdatesToInstall.Add($_) | out-null } }

                    # Write-Host('Installing Drivers...')  -Fore Green
                    # $Installer = $UpdateSession.CreateUpdateInstaller()
                    # $Installer.Updates = $UpdatesToInstall
                    # $InstallationResult = $Installer.Install()
                    # if($InstallationResult.RebootRequired) { 
                    # Write-Host('Reboot required! please reboot now..') -Fore Red
                    # } else { Write-Host('Done..') -Fore Green }

                    # $updateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $false -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" } | ForEach-Object { $UpdateSvc.RemoveService($_.ServiceID) }

                    # &&&&&&&&&& Method 2 &&&&&&&&&&

                    # Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.devicename -eq 'Intel(R) Ethernet Connection (7) I219-LM'} | ForEach-Object {
                    #     if ([Version]$_.Driverversion -ge [Version]'12.17.8.9') {  
                    #         Write-Output "Version is Current"
                    #         # return from a function ?
                    #         # return 0
                    #         # exit script with exitcode?
                    #         # exit 0
                    #     } 
                    #     else {
                    #         Start-Process -FilePath "\\servername\share\share\Dell\Drivers\Dell 3630\Network Card\setup.exe" -ArgumentList '/s' -Wait -NoNewWindow
                    #     }
                    # }
                    
                    # &&&&&&&&&& Method 3 &&&&&&&&&&

                    # Beginning of the script
                    # If the PowerShell Modules Folder is non-existing, it will be created.
                    if ($false -eq (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules)) {
                        New-Item -ItemType Directory -Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules1 -Force
                    }
                    # Import the PowerShell Module
                    $ScriptPath = Get-Location
                    Import-Module $ScriptPath\PSWindowsUpdate -Force
                    # Specify the path usage of Windows Update registry keys
                    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
                    
                    # Updates and Driver download
                    
                    # If the necessary keys are non-existing, they will be created
                    if ($false -eq (Test-Path $Path\WindowsUpdate)) {
                        New-Item -Path $Path -Name WindowsUpdate
                        New-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -PropertyType DWord -Value '0'
                        New-ItemProperty $Path\WindowsUpdate -Name WUServer -PropertyType DWord -Value $null
                        New-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -PropertyType DWord -Value $null
                    }
                    else {
                        # If the value of the keys are incorrect, they will be modified
                        try {
                            Set-ItemProperty $Path\WindowsUpdate -Name DisableDualScan -value "0" -ErrorAction SilentlyContinue
                            Set-ItemProperty $Path\WindowsUpdate -Name WUServer -Value $null -ErrorAction SilentlyContinue
                            Set-ItemProperty $Path\WindowsUpdate -Name WUStatusServer -Value $null -ErrorAction SilentlyContinue
                        }
                        catch {
                            Write-Output 'Skipped modifying registry keys'
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
                }
            }

            # ***************END OF -> Update Application Sub-Section***************

            # ***************Network Optimization Sub-Section***************

            if($Global:NOP_DNS_UPDATE_FUNCTION_STATUS) {
                function Change_DNS_Server_Update_Function {
                    # First, determine the active interface that is connected to internet
                    # Get-WmiObject Win32_NetworkAdapter -Filter "netconnectionstatus = 2" | Select-Object netconnectionid, name, InterfaceIndex, netconnectionstatus

                    # Note down InterfaceAlias name
                    Get-DnsClientServerAddress

                    # change IPv4 and IPv6 DNS servers
                    Set-DNSClientServerAddress "InterfaceAlias" –ServerAddresses ("8.8.8.8", "8.8.4.4")

                    # clear DNS cache
                    Clear-DnsClientCache
                }
            }
            if($Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS) {
                function Change_IRP_Stack_Size_Update_Function {
                    
                }
            }
            if($Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS) {
                function Configure_Background_Applications_Settings_Handle_Function {
                
                }
            }
            if($Global:NOP_LSO_DISABLE_FUNCTION_STATUS) {
                function Disable_Large_Send_Offload_Handle_Function {

                }
            }
            if($Global:NOP_ATUN_DISABLE_FUNCTION_STATUS) {
                function Disable_Windows_Auto_Tuning_Handle_Function {
                
                }
            }
            if($Global:NOP_QOS_DISABLE_FUNCTION_STATUS) {
                function Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function {

                }
            }
            if($Global:NOP_P2P_DISABLE_FUNCTION_STATUS) {
                function Disable_P2P_Update_Process_Handle_Function {
                
                }
            }

            # ***************END OF -> Network Optimization Sub-Section***************

            # ***************Memory Resource Optimization Sub-Section***************

            if($Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS) {
                function Run_Disk_Defragmentor_Execution_Function {

                    
                }
            }
            if($Global:MRO_TEMP_UPDATE_FUNCTION_STATUS) {
                function Remove_TEMP_Files_Update_Function {
                
                }
            }
            if($Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS) {
                function Set_Increase_Pagefile_Size_Update_Function {
                
                }
            }

            # ***************END OF -> Memory Resource Optimization Sub-Section***************

            # ***************Security Audit Sub-Section***************
            if($Global:SA_DFNDR_DISABLE_EXECUTION_STATUS) {
                function Run_Windows_Defender_Scan_Execution_Function {

                }
            }
            if($Global:SA_PR_HANDLE_FUNCTION_STATUS) {
                function Analyze_Processes_Handle_Function {

                }
            }
            
            # more things can be included in this Sub-Section, as it relates to Security
            # PC can be checked if it is connected to a domain and all security scanning relating to domain can be then applied

            # ***************END OF -> Security Audit Sub-Section***************

            # ***************Recommendations Sub-Section***************
            
            function Generate_Recommendations_Display_Function {
                # check if the system is connected to an AD Domain, if true then prompt user to check all configurations and security policies
                # if and only if the user is a part of the Administrators group or is a Domain Controller (DC)
            }

            # ***************END OF -> Recommendations Sub-Section***************


        # ********************END OF -> Post-Initialization Section********************


        } else {
            Write-Host "[!] Probabilistic Activation Determination Sub-Section initialization failed" -ForegroundColor White -BackgroundColor Red 
        }
        # if the value of $MASTER_INPUT_DISPATCH_CENTER_FUNCTION_STATUS is set to true then control-flow will continue
        # that will happen only when the Base Information Sub-Section is properly initialized. Hence, this variable acts as a checker.


        

        # ********************Probabilistic Activation Determination (PAD) Section********************


        # Functions within this section provides input to the section containing the __Input_Dispatch_Center_Control_Function__ function. Earlier, this Section was a Sub-section
        # (until commit -> 27bb259), but it has been converted because it essentially computes values and pass it to __Input_Dispatch_Center_Control_Function__ function which ACTUALLY
        # does the changes described in that. So, a Section giving input to itself isn't a great idea - it wouldn't affect the functioning of code per se, because these functions are divided
        # into the so-called 'Sections and Sub-Sections' on the basis of comments just to keep track of complexity - as it might be a source of confusion. 


            # ***************PAD Sub-Section-1***************

        # Determining probabilities
        function Compute_BSOD_Probability_Handle_Function {
            # This calculates probability of BSOD events
            # It does so by calculating the number of kernel-power failures leading to abrupt reboots
            try {
                $Global:LastAbruptSytemRebootDate = Get-WinEvent -FilterHashtable @{logname="System"; id=41} | Select-Object TimeCreated
                
                # Logic is pending!
                if($Global:LastAbruptSytemRebootDate.Count) {

                }
            }
            catch {
                Write-Host "[!] Could not find Defrag Logs" -ForegroundColor White -BackgroundColor Red
            }
        }
        function Compute_Memory_Failure_Probability_Handle_Function {
            # This calculates probility of memory failures happening
        }
        function Compute_Security_Related_Stuff_Handle_Function {

        }
        function Compute_BSOD_Probability_Handle_Function {
            # This calculates probability of BSOD events
            # It does so by calculating the number of kernel-power failures leading to abrupt reboots
            # Event log is the source of information
        }

            # ***************END OF -> PAD Sub-Section-1***************

            # ***************PAD Sub-Section-2***************

        function Determine_BSOD_Fixing_Parameters_Activation_Handle_Function {
            # here parameters mean which functions are required to be called in case Part-1 of PAD has determined BSOD events 
            # as a regular happening that necessitates calling of measures and methods in the functions that were defined to
            # fix a particular type of error, in this case a BSOD

            # call to IDCC Function
            __Input_Dispatch_Center_Control_Function__
        }
        function Determine_Memory_Fixing_Parameters_Activation_Handle_Function {
            # this function determines

            # call to IDCC Function
            __Input_Dispatch_Center_Control_Function__
        }

            # ***************END OF -> PAD Sub-Section-2***************


        # ********************Output Handling Section********************


        # Output function will collect exit codes from all executed,
        # functions and will give a green light when all are boolean true
        # after that the system might proceed to restart for a final time

        function __Output_Dispatch_Center_Update_Function__ {
            # if all functions determine their outputs successfully, then this function will set the
            # $Global:Output_DISPATCH_CENTER_FUNCTION_MASTER_STATUS to true, and if that is true then the system will be ready for final restart.
            # This will set the $Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS which will be responsible for restarting the system.
        }

        # When everything is okay, system will restart for finally although this behaviour can be updated
        # because of potiential restarts in between the script. For eg., when the system updates some 
        # registry values, among other things. That might be a pain for the user.

        function Set_Ready_For_Final_Restart_Handle_Function {
            [CmdletBinding()] param(
                [Parameter(Mandatory=$true, Position=0)] [bool] $Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS
            )
            
            if($Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS) {
                # restart the system

            }
        }


        # ********************END OF -> Output Handling Section********************


    } else {
        Write-Host "[!] The script can't run on Windows Server 2012, Windows Server 2008 R2 and Windows 8.1"
        Write-Host "[*] Exiting..."
    }

} else {
    Write-Host "[!] You need atleast PowerShell 7.2 to run this script"
    Write-Host "[*] Exiting..."
}
