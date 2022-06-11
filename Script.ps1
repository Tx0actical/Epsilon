# ********************Pre-Initialization Section********************


# Get OS version
$HostOSVersion = Get-ComputerInfo | Select-Object WindowsProductName
$HostPowershellVersion = $PSVersionTable.PSVersion 
$IncompatibleOSVersion = @('Windows Server 2012',' Windows Server 2008 R2','Windows 8.1')
$MinimumRequiredPowershellVersion = [PSCustomObject]@{
    Major = 7
    Minor = 2 
}

# Aadditional requirements can be added into the if below as constraints pop up
if(($HostPowershellVersion.Major -eq $MinimumRequiredPowershellVersion.Major) -and ($HostPowershellVersion.Minor -eq $MinimumRequiredPowershellVersion.Minor)) {
    if( -not ($HostOSVersion.WindowsProductName -contains $IncompatibleOSVersion[0]) -or ($HostOSVersion.WindowsProductName -contains $IncompatibleOSVersion[1]) -or ($HostOSVersion.WindowsProductName -contains $IncompatibleOSVersion[2])) {
        Write-Host '[*] Intializing System-Wide Optimization (SWO) Script' -ForegroundColor White -BackgroundColor Green

        # Import user module
        Import-Module -Name Microsoft.PowerShell.LocalAccounts
        # Import current user profile
        $CurrentUser = whoami.exe
        # Get members of administrators group
        $IsAdmin = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name

        # Check if user is Admin and act accordingly
        if ($IsAdmin -Contains $CurrentUser) {
            # Spawn PowerShell with $CurrentUser privileges
            runas.exe /user:$CurrentUser PowerShell.exe
            # Modify ExecutionPolicy to run scripts
            Set-ExecutionPolicy -ExecutionPolicy Bypass
        }
        else {
            Write-Host '[!] Admin privileges required' -ForegroundColor White -BackgroundColor Red  # can write Write-Error or something like that
        }


        # ********************END OF -> Pre-Initialization Section********************


        # ********************Initialization Section********************

        # ***************Base Information Sub-Section***************

        function Get_System_Information_Handle_Function {
            
        }

        function Parse_Windows_Event_Log_Handle_Function {
            # Parse specific events, count their number
            # subsequent blocks will try to run specific lines of code. Each try block will have an associated boolean variable that will keep track
            # of successful or unsuccessful execution of that particular block. In the end of the function, all these variables will be together tested
            # for true status, in an 'AND' construct. If any single one of them is false a result of unsuccessful execution
            # then a boolean variable that finally determines the state of the current function will be set to true or false accordingly.

            # Current Date
            $CurrentDate = Get-Date -DisplayHint Date -Format "MM/dd/yyyy"
            # Debugging outputs
            Write-Host "Date today is $CurrentDate" -ForegroundColor White -BackgroundColor Blue

            # Get disk defragmentor logs. This is inside a try block because if the system drives were never optimized then that statement may throw an error or might
            # display nothing. The docs might tell that. So try block is used to be on the safer side.
            try {
                $LastDiskOptimizeDate = Get-WinEvent -FilterHashtable @{logname='Application'; id=258} | Select-Object TimeCreated | Select-Object -First 1
            }
            catch {
                Write-Host '[*] Could not find Defrag Logs' -ForegroundColor White -BackgroundColor Red
            }

            # Necessary formatting
            $LastDiskOptimizeDate = $LastDiskOptimizeDate -split " " -split "="
            $LastDiskOptimizeDate = $LastDiskOptimizeDate | Select-Object -Skip 1 | Select-Object -First 1

            # Days passed since the disk was optimized
            $DaysSinceDiskLastOptimized = New-TimeSpan -Start $LastDiskOptimizeDate -End $CurrentDate | Select-Object Days

            # Maybe unnecessary formatting (better method might be available, but I don't know that yet)
            $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized -split "{" -split "=" 
            $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized | Select-Object -Skip 2 | Select-Object -First 1
            $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized -split "}"
            $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized | Select-Object -First 1
            # Debugging outputs
            Write-Host "Disk was optimized $DaysSinceDiskLastOptimized days ago" -ForegroundColor White -BackgroundColor Blue


        }



        # TO DO: Think about more sources of information for behaviour of Windows Systems


        # ***************Probabilistic activation determination (PAD) Sub-Section***************


        # *****Part-1 of PAD Sub-Section*****

        # Determining probabilities
        function Compute_BSOD_Probability_Handle_Function {
            # This calculates probability of BSOD events
            # It does so by calculating the number of kernel-power failures leading to abrupt reboots
            try {
                $LastAbruptSytemRebootDate = Get-WinEvent -FilterHashtable @{logname='System'; id=41} | Select-Object TimeCreated
                
                # Logic is pending!
                if($LastAbruptSytemRebootDate.Count) {

                }
            }
            catch {
                Write-Host '[*] Could not find Defrag Logs' -ForegroundColor White -BackgroundColor Red
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

        # *****END OF -> Part-1 of PAD Sub-Section*****

        # *****Part-2 of PAD Sub-Section*****
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

        # *****END OF -> Part-2 of PAD Sub-Section*****

        # Function to keep track of inputs after all node probability determination
        # functions are true (values determined). Input_Dispatch_Function will supply inputs to handling functions,
        # where inputs can be simply of bool type because the probabilities will determine the activation of functions that are described in the sub-sections.
        function __Input_Dispatch_Center_Control_Function__ { # meaning of cmdletbinding() ?
            [CmdletBinding()] param(
                [Parameter(Position = 0)] [bool] $MASTER_INPUT_DISPATCH_CENTER_FUNCTION_STATUS,
                [Parameter(Position = 1)] [bool] $SFA_CHKDSK_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 2)] [bool] $SFA_SFC_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 3)] [bool] $SFA_DISM_EXECUTION_FUNCTION_STATUS,

                [Parameter(Position = 4)] [bool] $UA_SYS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 5)] [bool] $UA_STORE_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 6)] [bool] $UA_DRIVER_UPDATE_FUNCTION_STATUS,

                [Parameter(Position = 7)] [bool] $NOP_DNS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 8)] [bool] $NOP_IRPSS_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 8)] [bool] $NOP_BAPP_CONFIGURE_FUNCTION_STATUS,
                [Parameter(Position = 9)] [bool] $NOP_LSO_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 10)] [bool] $NOP_ATUN_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 11)] [bool] $NOP_QOS_DISABLE_FUNCTION_STATUS,
                [Parameter(Position = 12)] [bool] $NOP_P2P_DISABLE_FUNCTION_STATUS,

                [Parameter(Position = 13)] [bool] $MRO_DFRG_EXECUTION_FUNCTION_STATUS,
                [Parameter(Position = 14)] [bool] $MRO_TEMP_UPDATE_FUNCTION_STATUS,
                [Parameter(Position = 15)] [bool] $MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS,

                [Parameter(Position = 16)] [bool] $SA_DFNDR_DISABLE_EXECUTION_STATUS,
                [Parameter(Position = 17)] [bool] $SA_PR_HANDLE_FUNCTION_STATUS
            )

            Write-Host "[*] Checking Probabilistic Activation Determination Sub-Section Intitialization"
            if($MasterInputDispatchCenterFunctionStatus -eq $True) {
                Write-Host "[*] Sub-Section initialization completed" -ForegroundColor White -BackgroundColor Green

                # ***************System Files Audit Sub-Section***************

                if($SFA_CHKDSK_EXECUTION_FUNCTION_STATUS) {
                    function Run_CHKDSK_Utility_Execution_Function {
                    
                    }
                }
                
                if($SFA_SFC_EXECUTION_FUNCTION_STATUS) {
                    function Run_SFC_Utility_Execution_Function {
                    
                    }
                }
                
                if($SFA_DISM_EXECUTION_FUNCTION_STATUS) {
                    function Run_DISM_Utility_Execution_Function {

                    }
                }

                # ***************END OF -> System Files Audit Sub-Section***************
                

                # ***************Update Application Sub-Section***************

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
                        Write-Host "[*] Updates found!"
                        Write-Host "[*] Installing Updates"
                        
                    }
                }

                function Update_Microsoft_Store_Application_Handle_Function {

                }

                function Update_Windows_System_Drivers_Handle_Function {

                }

                # ***************END OF -> Update Application Sub-Section***************

                # ***************Network Optimization Sub-Section***************

                function Change_DNS_Server_Update_Function {

                }
                function Change_IRP_Stack_Size_Update_Function {
                    
                }
                function Configure_Background_Applications_Settings_Handle_Function {
                    
                }
                function Disable_Large_Send_Offload_Handle_Function {

                }
                function Disable_Windows_Auto_Tuning_Handle_Function {
                    
                }
                function Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function {

                }
                function Disable_P2P_Update_Process_Handle_Function {
                    
                }
                # ***************END OF -> Network Optimization Sub-Section***************

                # ***************Memory Resource Optimization Sub-Section***************

                function Run_Disk_Defragmentor_Execution_Function {
                    # Optimise-Volume Cmdlet will help here
                }
                function Remove_TEMP_Files_Update_Function {
                    
                }
                function Set_Increase_Pagefile_Size_Update_Function {
                    
                }

                # ***************END OF -> Memory Resource Optimization Sub-Section***************

                # ***************Security Audit Sub-Section***************

                function Run_Windows_Defender_Scan_Execution_Function {

                }
                function Analyze_Processes_Handle_Function {

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

            } else {
                Write-Host "[*] Sub-Section initialization failed" -ForegroundColor White -BackgroundColor Red 
            }
            # if the value of $MASTER_INPUT_DISPATCH_CENTER_FUNCTION_STATUS is set to true then control-flow will continue
            # that will happen only when the Base Information Sub-Section is properly initialized. Hence, this variable acts as a checker.
        }


        # Output function will collect exit codes from all executed,
        # functions and will give a green light when all are boolean true
        # after that the system might proceed to restart for a final time

        function __Output_Dispatch_Center_Update_Function__ {

        }

        # When everything is okay, system will restart for finally although this behaviour can be updated
        # because of potiential restarts in between the script. For eg., when the system updates some 
        # registry values, among other things. That might be a pain for the user.

        function Set_Ready_For_Final_Restart_Handle_Function {

        }
    }


    # ********************END OF -> Initialization Section********************


} else {
    Write-Host "[*] You need atleast PowerShell 7.2 to run this script" -ForegroundColor White -BackgroundColor Blue
    Write-Host "[*] Exiting" -ForegroundColor White -BackgroundColor Blue
}