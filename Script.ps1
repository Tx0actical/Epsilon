# ********************Initialization Section********************

Write-Host "[*] You need atleast PowerShell 7.2 to run this script"
Write-Host '[*] Intializing System-Wide Optimization (SWO) Script'

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
    Write-Host '[!] Admin privileges required' # may require Write-Error or something like that
}

# ********************Post-Initialization Section********************

# ***************Base Information Sub-Section***************

function Get_System_Information_Handle_Function {
    # Get OS version
    $OSVersion = Get-ComputerInfo | Select-Object WindowsProductName

    # Get disk defragmentor logs. This 
    $LastDiskOptimizeDate = Get-WinEvent -FilterHashtable @{logname='Application'; id=258} | Select-Object TimeCreated | Select-Object -First 1

    # Necessary formatting
    $LastDiskOptimizeDate = $LastDiskOptimizeDate -split " " -split "="
    $LastDiskOptimizeDate = $LastDiskOptimizeDate | Select-Object -Skip 1 | Select-Object -First 1

    # Current Date
    $CurrentDate = Get-Date -DisplayHint Date -Format "MM/dd/yyyy"

    # Debugging outputs
    Write-Host "Date today is $CurrentDate"

    # Days passed since the disk was optimized
    $DaysSinceDiskLastOptimized = New-TimeSpan -Start $LastDiskOptimizeDate -End $CurrentDate | Select-Object Days

    # Necessary formatting
    $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized -split "{" -split "=" 
    $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized | Select-Object -Skip 2 | Select-Object -First 1
    $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized -split "}"
    $DaysSinceDiskLastOptimized = $DaysSinceDiskLastOptimized | Select-Object -First 1
    
    # Debugging outputs
    Write-Host "Disk was optimized $DaysSinceDiskLastOptimized days ago"

    

}

function Parse_Windows_Event_Log_Handle_Function {
    # Parse specific events, count their number
}



# TO DO: Think about more sources of information for behaviour of Windows Systems

# ***************Probabilistic activation determination (PAD) Sub-Section***************

# *****Part-1 of PAD Sub-Section*****

# Determining probabilities
function Compute_BSOD_Probability_Handle_Function {
    # This calculates probability of BSOD events
    # It does so by calculating the number of kernel-power failures leading to  
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

# *****Part-2 of PAD Sub-Section*****
function Determine_BSOD_Fixing_Parameters_Activation_Handle_Function {
    # here parameters mean which functions are required to be called in case Part-1 of PAD has determined BSOD events 
    # as a regular happening that necessitates calling of measures and methods in the functions that were defined to
    # fix a particular type of error, in this case a BSOD
}
function Determine_Memory_Fixing_Parameters_Activation_Handle_Function {
    # this function determines
}

# Function to keep track of inputs after all node probability determination
# functions are true (values determined). Input_Dispatch_Function will supply inputs to handling functions,
# where inputs can be simply of bool type because the probabilities will determine the activation of functions that are described in the sub-sections.
function __Input_Dispatch_Center_Update_Function__ {
    [CmdletBinding()] param([Parameter()] [bool] $InputDispatchCenterFunction)

    Write-Host "[*] Checking Base Information Sub-Section Intitialization"

    # if the value of $InputDispatchCenterFunction is set to true then control-flow will continue
    # that will happen only when the Base Information Sub-Section is properly initialized

}



# ***************System Files Audit Sub-Section***************

function Run_CHKDSK_Utility_Execution_Function {
    
}

function Run_SFC_Utility_Execution_Function {
    
}

function Run_DISM_Utility_Execution_Function {

}

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

# ***************Network Optimization Sub-Section***************

function Change_DNS_Server_Update_Function {

}
function Change_IRP_Stack_Size_Update_Function {
    
}
function Configure_Background_Applications_Settings_Handle_Function {
    
}
function Update_DNS_Server_Update_Function {
    
}
function Disable_Large_Send_Offload_Handle_Function {

}
function Disable_Windows_Auto_Tuning_Handle_Function {
    
}
function Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function {

}
function Disable_P2P_Update_Process_Handle_Function {
    
}

# ***************Memory Resource Optimization Sub-Section***************

function Run_Disk_Defragmentor_Execution_Function {
    # Optimise-Volume Cmdlet will help here
}
function Remove_TEMP_Files_Update_Function {
    
}
function Set_Increase_Pagefile_Size_Update_Function {
    
}

# ***************Security Audit Sub-Section***************

function Run_Windows_Defender_Scan_Execution_Function {

}
function Analyze_Processes_Handle_Function {

}

# more things can be included in this Sub-Section, as it relates to Security
# PC can be checked if it is connected to a domain and all security scanning relating to domain can be then applied

# ***************Recommendations Sub-Section***************

function Generate_Recommendations_Display_Function {

}

# Output function will collect exit es from all executed,
# functions and will give a green light when all are boolean true

function __Output_Dispatch_Center_Update_Function__ {

}

# When everything is okay, system will restart for finally although this behaviour can be updated
# because of potiential restarts in between the script. For eg., when the system updates some 
# registry values, among other things. That might be a pain for the user.

function Set_Ready_For_Final_Restart_Handle_Function {

}
