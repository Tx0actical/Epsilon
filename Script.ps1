        # ********************Zero Section********************

        # This section will first check the registry value that is set when the computer is restarted in the middle of script execution.
        # If the value is set, then the script will continue from where it left off (addtional logic will be required to do that).
        # If the value is not set, then the script will start from the beginning.

        # &&&&&&&&&& OR &&&&&&&&&&

        # The restart can be handled in the end after the output dispatch center gives a green light after the result of all the functions are determined. In the meantime, restarts can be kept pending.
        # That would save a lot of extra code. But if certain operation requires immediate restart to complete, then this section might have a relevance, till then this is commeted.

        # function Query_Registry_For_Mid_Execution_Restart_Handle_Function {
        #     # if it is determined that restart has occured, then control will directly jump to the function after the function which called the restart.
        #     # else run script from start.
        # }

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

        # ********************END OF -> Pre-Initialization Section********************


        # ********************Initialization Section********************

$Global:CurrentDate                                     = $null
$Global:LastDiskOptimizeDate                            = $null
$Global:DaysSinceDiskLastOptimized                      = $null
$Global:VolumeNumber                                    = $null
$Global:LastAbruptSytemRebootDate                       = $null


$Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS    = $null

$Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS            = $null
$Global:SFA_SFC_EXECUTION_FUNCTION_STATUS               = $null
$Global:SFA_DISM_EXECUTION_FUNCTION_STATUS              = $null
$Global:UA_SYS_UPDATE_FUNCTION_STATUS                   = $null
$Global:UA_STORE_UPDATE_FUNCTION_STATUS                 = $null
$Global:UA_DRIVER_UPDATE_FUNCTION_STATUS                = $null
$Global:NOP_DNS_UPDATE_FUNCTION_STATUS                  = $null
$Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS                = $null
$Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS              = $null
$Global:NOP_LSO_DISABLE_FUNCTION_STATUS                 = $null
$Global:NOP_ATUN_DISABLE_FUNCTION_STATUS                = $null
$Global:NOP_QOS_DISABLE_FUNCTION_STATUS                 = $null
$Global:NOP_P2P_DISABLE_FUNCTION_STATUS                 = $null
$Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS              = $null
$Global:MRO_TEMP_UPDATE_FUNCTION_STATUS                 = $null
$Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS           = $null
$Global:SA_DFNDR_DISABLE_EXECUTION_STATUS               = $null
$Global:SA_PR_HANDLE_FUNCTION_STATUS                    = $null


$Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS   = $null

$Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED           = $null
$Global:SET_SFA_SFC_NODE_RESULT_DETERMINED              = $null
$Global:SET_SFA_DISM_NODE_RESULT_DETERMINED             = $null
$Global:SET_UA_SYS_UPDATE_NODE_RESULT_DETERMINED        = $null
$Global:SET_UA_STORE_UPDATE_NODE_RESULT_DETERMINED      = $null
$Global:SET_UA_DRIVER_UPDATE_NODE_RESULT_DETERMINED     = $null
$Global:SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED       = $null
$Global:SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED     = $null
$Global:SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED   = $null
$Global:SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED      = $null
$Global:SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED     = $null
$Global:SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED      = $null
$Global:SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED      = $null
$Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED             = $null
$Global:SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED      = $null
$Global:SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED= $null
$Global:SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED     = $null
$Global:SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED         = $null


# Aadditional requirements can be added into the if below as constraints pop up
if(($Global:HostPowershellVersion.Major -eq $Global:MinimumRequiredPowershellVersion.Major) -and ($Global:HostPowershellVersion.Minor -eq $Global:MinimumRequiredPowershellVersion.Minor)) {
    if( -not ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[0]) -or ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[1]) -or ($Global:HostOSVersion.WindowsProductName -contains $Global:IncompatibleOSVersion[2])) {
        Write-Host "[*] Intializing System-Wide Optimization (SWO) Script." -ForegroundColor White -BackgroundColor Blue
        Write-Host "[*] Do not interrupt the process once it has started. Irreversible Data Loss and Disk Corruption may occur." -ForegroundColor White -BackgroundColor Blue

        # Import user module
        Import-Module -Name Microsoft.PowerShell.LocalAccounts
        # Import current user profile
        $CurrentUser = whoami.exe
        # Get members of administrators group
        $IsAdmin = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name

        # Check if user is Admin and act accordingly
        if ($IsAdmin -Contains $CurrentUser) {
            # Spawn PowerShell with $CurrentUser privileges
            Start-Process -FilePath "powershell" -Verb RunAs
            # Modify ExecutionPolicy to run scripts
            Set-ExecutionPolicy -ExecutionPolicy Bypass
        }
        else {
            Write-Host "[!] Admin privileges required"  # can write Write-Error or something like that
        }
        
        # if the user runs the code as administrator then the above code will not be required. But a self elevating script can be used.
        # That way, the user can elevate itself to admin, utilizing a credential prompt (Get-Credential), if not, if the user is admin then, the script will execute all the code below.
        
        # If the required version of powershell is not present in the host system, then the user can be prompted to install it. A choice can be given to the user.
        # If the user chooses to install it, then the script will install it otherwise, the script can return the incompatibility message and exit.


        # ********************END OF -> Initialization Section********************


        # ********************Post-Initialization Section********************


        # TO DO: Think about more sources of information for behaviour of Windows Systems


        # Function to keep track of inputs after all node probability determination
        # functions are true (values determined). Input_Dispatch_Function will supply inputs to handling functions,
        # where inputs can be simply of bool type because the probabilities will determine the activation of functions that are described in the sub-sections.
        # [Parameter(Mandatory = $True)] flag can be used to determine which function was not assigned a value by the sectional functions
        # and that may provide necessary debug information and provide necessary checks during script execution.


        function __Input_Dispatch_Center_Control_Function__ { # meaning of cmdletbinding() ?
            [CmdletBinding()] param(
                [Parameter(Position = 0, Mandatory = $True)] [bool] $Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS,
                [Parameter(Position = 1, Mandatory = $True)] [bool] $Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 2, Mandatory = $True)] [bool] $Global:SFA_SFC_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 3, Mandatory = $True)] [bool] $Global:SFA_DISM_EXECUTION_FUNCTION_STATUS,

                [Parameter(Position = 4, Mandatory = $True)] [bool] $Global:UA_SYS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 5, Mandatory = $True)] [bool] $Global:UA_STORE_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 6, Mandatory = $True)] [bool] $Global:UA_DRIVER_UPDATE_FUNCTION_STATUS,

                [Parameter(Position = 7, Mandatory = $True)] [bool] $Global:NOP_DNS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 8, Mandatory = $True)] [bool] $Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 9, Mandatory = $True)] [bool] $Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS,
                [Parameter(Position = 10, Mandatory = $True)] [bool] $Global:NOP_LSO_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 11, Mandatory = $True)] [bool] $Global:NOP_ATUN_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 12, Mandatory = $True)] [bool] $Global:NOP_QOS_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 13, Mandatory = $True)] [bool] $Global:NOP_P2P_DISABLE_FUNCTION_STATUS,

                [Parameter(Position = 14, Mandatory = $True)] [bool] $Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 15, Mandatory = $True)] [bool] $Global:MRO_TEMP_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 16, Mandatory = $True)] [bool] $Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS,

                [Parameter(Position = 17, Mandatory = $True)] [bool] $Global:SA_DFNDR_DISABLE_EXECUTION_STATUS,
                [Parameter(Position = 18, Mandatory = $True)] [bool] $Global:SA_PR_HANDLE_FUNCTION_STATUS
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
                    $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED = $True
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
                    $Global:SET_SFA_SFC_NODE_RESULT_DETERMINED = $True
                }
            }
            
            if($Global:SFA_DISM_EXECUTION_FUNCTION_STATUS) {
                function Run_DISM_Utility_Execution_Function {
                    $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED = $True
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
                    $Global:SET_UA_SYS_NODE_RESULT_DETERMINED = $True
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
                    $Global:SET_UA_STORE_NODE_RESULT_DETERMINED = $True
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
                            Write-Output '[*] Skipped modifying registry keys' -ForegroundColor White -BackgroundColor Blue
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

                    $Global:SET_NOP_DNS_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS) {
                function Change_IRP_Stack_Size_Update_Function {
                    $Global:SET_NOP_IRPSS_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS) {
                function Configure_Background_Applications_Settings_Handle_Function {
                    $Global:SET_NOP_BAPP_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:NOP_LSO_DISABLE_FUNCTION_STATUS) {
                function Disable_Large_Send_Offload_Handle_Function {
                    $Global:SET_NOP_LSO_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:NOP_ATUN_DISABLE_FUNCTION_STATUS) {
                function Disable_Windows_Auto_Tuning_Handle_Function {
                    $Global:SET_NOP_ATUN_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:NOP_QOS_DISABLE_FUNCTION_STATUS) {
                function Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function {
                    $Global:SET_NOP_QOS_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:NOP_P2P_DISABLE_FUNCTION_STATUS) {
                function Disable_P2P_Update_Process_Handle_Function {
                    $Global:SET_NOP_P2P_NODE_RESULT_DETERMINED = $True
                }
            }

            # ***************END OF -> Network Optimization Sub-Section***************

            # ***************Memory Resource Optimization Sub-Section***************

            if($Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS) {
                function Run_Disk_Defragmentor_Execution_Function {
                    $Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:MRO_TEMP_UPDATE_FUNCTION_STATUS) {
                function Remove_TEMP_Files_Update_Function {
                    $Global:SET_MRO_TEMP_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS) {
                function Set_Increase_Pagefile_Size_Update_Function {
                    $Global:SET_MRO_INC_NODE_RESULT_DETERMINED = $True
                }
            }

            # ***************END OF -> Memory Resource Optimization Sub-Section***************

            # ***************Security Audit Sub-Section***************
            if($Global:SA_DFNDR_DISABLE_EXECUTION_STATUS) {
                function Run_Windows_Defender_Scan_Execution_Function {
                    $Global:SET_SA_DFNDR_NODE_RESULT_DETERMINED = $True
                }
            }
            if($Global:SA_PR_HANDLE_FUNCTION_STATUS) {
                function Analyze_Processes_Handle_Function {
                    $Global:SET_SA_PR_NODE_RESULT_DETERMINED = $True
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

        # Individul Perceptrons to determine activation of functions depending upon the number of contributing factors
        function Invoke_Perceptron_For_Stop_Error_Parameters_Activation_Determination_Function {
            # This function determines activations of specific functions that might help resolve stop errors.
            # The inputs will be the number of events that have been detected with respect to stop errors, which will be fetched from the Windows Event Logs.
            # The weights will be the impact of a function in resolving the problem. Higher impact functions will have more weight.

            # Bad driver configuration, Software updates, Hardware failures, Memory failures, Power failures, Disk Errors might be the cause.

            Write-Host "[*] Checking if StopError is a potiential problem vector" -ForegroundColor White -BackgroundColor Blue

            
        }

        function Invoke_Perceptron_For_Memory_Opmitization_Parameters_Activation_Determination_Function {
            # This function determines activations of specific functions that might help troubleshoot and optimize memory.

            # Can close unused appications that are left open for a long time, unused. Or this section can be binned if no controls were found to achieve the desired results.
            Write-Host "[*] Checking if memory optimization is needed" -ForegroundColor White -BackgroundColor Blue

            # Can check for memory failues, by using Windows Memory Diagnostics.
            Write-Host "[*] Checking if memory failures if a problem vector" -ForegroundColor White -BackgroundColor Blue
        }

        function Invoke_Perceptron_For_Security_Audit_Parameters_Activation_Determination_Function {
            # This function will check if relevant security controls are present like Windows Defender logs, or logs generated by third-party AV software, wether or not scanning is done.
            # This might include system updates and other parameters related to security. And the most relevant functions that can solve the problem will be assigned higher weights.
            Write-Host "[*] Checking if system wide security controls are present" -ForegroundColor White -BackgroundColor Blue

        }

        function Invoke_Perceptron_For_Network_Opmitization_Parameters_Activation_Determination_Function {
            # This function will evaluate the network connection and performance, and try to optimize them.
            # Input parameters can be connection speed, or simply the presence of parameters that 
        }

        # **************Function Call Sub-Section***************

        
        
        # **************END OF -> Function Call Sub-Section***************
        

        # ^^^^^^^^^^^^^^^IMPORTANT NOTE^^^^^^^^^^^^^^^^

        # Determining exact cause of StopError is not procedural, there might be a faulty kernel-mode driver, there might be hardware failure, possibilities are very large.
        # A rigorous analysis of a stop error or StopError is beyond the scope of this script as it requires advanced troubleshooting techniques by investigating crash dump files using the kernel debugger (kd).
        # This script only analyses system behaviour and tries to determine the cause of the crash.

        # ^^^^^^^^^^^^^^^END OF -> IMPORTANT NOTE^^^^^^^^^^^^^^^^


            # ***************END OF -> PAD Sub-Section-1***************

            # ***************PAD Sub-Section-2***************

        # The reason why separate functions are required to pass the values to __Input_Dispatch_Center_Control_Function__ when it can be done right within the Perceptron functions is because all the issues require
        # their own separate result and that is possible by having separate functions of handling each issue.

        function Forward_StopError_Fixing_Parameters_Fowarding_Function {
            # here parameters mean which functions are required to be called in case Part-1 of PAD has determined StopError events 
            # as a regular happening that necessitates calling of measures and methods in the functions that were defined to
            # fix a particular type of error, in this case a StopError

            # This function will take input from the Perceptron that determines the activation of the functions
            
            Write-Host "[*] One of the problems were found out to be Stop Errors resulting in system crashes" -ForegroundColor White -BackgroundColor Blue

            # call to IDCC Function
            __Input_Dispatch_Center_Control_Function__
        }
        function Forward_Memory_Fixing_Parameters_Fowarding_Function {
            # this function determines

            Write-Host "[*] One of the problems were found out to be Bad memory" -ForegroundColor White -BackgroundColor Blue
            # call to IDCC Function
            __Input_Dispatch_Center_Control_Function__
        }

            # ***************END OF -> PAD Sub-Section-2***************


        # ********************Output Handling Section********************


        # Output function will collect exit codes from all executed,
        # functions and will give a green light when all are boolean true
        # after that the system might proceed to restart for a final time

        function __Output_Dispatch_Center_Control_Function__ {
            # if all functions determine their outputs successfully, then this function will set the
            # $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS to true, and if that is true then the system will be ready for final restart.
            # This will set the $Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS which will be responsible for restarting the system.

            if($Global:SET_SFA_SFC_NODE_RESULT_DETERMINED -or $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED -or $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED) {

                if($Global:SET_UA_SYS_NODE_RESULT_DETERMINED -or $Global:SET_UA_STORE_NODE_RESULT_DETERMINED -or $Global:SET_UA_DRIVER_NODE_RESULT_DETERMINED) {

                    if($Global:SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED) {

                        if($Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED -or $Global:SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED -or $Global:SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED) {

                            if($Global:SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED -or $Global:SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED) {

                                # if all the above are true then the system will be ready for final restart and $Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS will be set to true
                                $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS = $True
                            } else {
                                Write-Host "[!] Security Audit Section Failed" -ForegroundColor White -BackgroundColor Red
                            }
                        } else {
                            Write-Host "[!] Memory Resource Optimization Section Failed" -ForegroundColor White -BackgroundColor Red
                        }
                    } else {
                        Write-Host "[!] Network Optimization Section Failed" -ForegroundColor White -BackgroundColor Red
                    }
                } else {
                    Write-Host "[!] Update Application Section Failed" -ForegroundColor White -BackgroundColor Red
                }
            } else {
                Write-Host "[!] System Files Section Failed" -ForegroundColor White -BackgroundColor Red
            }
        }

        # **************Function Call Sub-Section***************

        __Output_Dispatch_Center_Control_Function__ 

        # **************END OF -> Function Call Sub-Section***************

        # When everything is okay, system will restart for finally although this behaviour can be updated
        # because of potiential restarts in between the script. For eg., when the system updates some 
        # registry values, among other things. That might be a pain for the user.

        # Another version to handle restart-needed-to-apply-changes, is to postpone the restart until all the operations are
        # completed and then restarting the system, instead of restarting the system right away, in the middle of script execution.

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

        # **************Function Call Sub-Section***************

        Set_Ready_For_Final_Restart_Handle_Function

        # **************END OF -> Function Call Sub-Section***************


        # ********************END OF -> Output Handling Section********************

    
    }
    
    } else {
        Write-Host "[!] The script can't run on Windows Server 2012, Windows Server 2008 R2 and Windows 8.1" -ForegroundColor White -BackgroundColor Red
        Write-Host "[*] Exiting..." -ForegroundColor White -BackgroundColor Blue
    }

} else {
    Write-Host "[!] You need atleast PowerShell 7.2 to run this script" -ForegroundColor White -BackgroundColor Red
    Write-Host "[*] Exiting..." -ForegroundColor White -BackgroundColor Blue
}
