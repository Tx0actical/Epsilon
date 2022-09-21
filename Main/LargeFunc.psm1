# Function to save and reload script state from a statefile
function Record_Previous_Script_Instance_State_Handle_Function {
    
    # function to record current state including variables and other state information used when resuming the script after restart.
    # create a statefile

    $Global:ScriptVariableState = @{
        'CurrentDate'                                       = $Global:CurrentDate                                       ;
        'HostOSVersion'                                     = $Global:HostOSVersion                                     ;
        'HostPowershellVersion'                             = $Global:HostPowershellVersion                             ;
        'IncompatibleOSVersion'                             = $Global:IncompatibleOSVersion                             ;
        'MinimumRequiredPowershellVersion'                  = $Global:MinimumRequiredPowershellVersion                  ;
        'RegistryPath'                                      = $Global:RegistryPath                                      ;
        'RegistryName'                                      = $Global:RegistryName                                      ;
        'RegistryValue'                                     = $Global:RegistryValue                                     ;                                         
        'LastDiskOptimizeDate'                              = $Global:LastDiskOptimizeDate                              ;                              
        'DaysSinceDiskLastOptimized'                        = $Global:DaysSinceDiskLastOptimized                        ;
        'VolumeNumber'                                      = $Global:VolumeNumber                                      ;  
        'LastSytemRebootDate'                               = $Global:LastSytemRebootDate                               ; 
        'RestartStatusVariable'                             = $Global:RestartStatusVariable                             ;  

        'INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS'      = $Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS      ;  
        'OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS'     = $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS     ;  

        'SFA_CHKDSK_EXECUTION_FUNCTION_STATUS'              = $Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS              ; 
        'SFA_SFC_EXECUTION_FUNCTION_STATUS'                 = $Global:SFA_SFC_EXECUTION_FUNCTION_STATUS                 ;  
        'SFA_DISM_EXECUTION_FUNCTION_STATUS'                = $Global:SFA_DISM_EXECUTION_FUNCTION_STATUS                ;  
        'UA_SYS_UPDATE_FUNCTION_STATUS'                     = $Global:UA_SYS_UPDATE_FUNCTION_STATUS                     ;  
        'UA_STORE_UPDATE_FUNCTION_STATUS'                   = $Global:UA_STORE_UPDATE_FUNCTION_STATUS                   ;  
        'UA_DRIVER_UPDATE_FUNCTION_STATUS'                  = $Global:UA_DRIVER_UPDATE_FUNCTION_STATUS                  ;  
        'NOP_DNS_UPDATE_FUNCTION_STATUS'                    = $Global:NOP_DNS_UPDATE_FUNCTION_STATUS                    ;  
        'NOP_IRPSS_UPDATE_FUNCTION_STATUS'                  = $Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS                  ;  
        'NOP_BAPP_CONFIGURE_FUNCTION_STATUS'                = $Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS                ; 
        'NOP_LSO_DISABLE_FUNCTION_STATUS'                   = $Global:NOP_LSO_DISABLE_FUNCTION_STATUS                   ;  
        'NOP_ATUN_DISABLE_FUNCTION_STATUS'                  = $Global:NOP_ATUN_DISABLE_FUNCTION_STATUS                  ;  
        'NOP_QOS_DISABLE_FUNCTION_STATUS'                   = $Global:NOP_QOS_DISABLE_FUNCTION_STATUS                   ;  
            
        'MRO_DFRG_EXECUTION_FUNCTION_STATUS'                = $Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS                ;  
        'MRO_TEMP_UPDATE_FUNCTION_STATUS'                   = $Global:MRO_TEMP_UPDATE_FUNCTION_STATUS                   ;  
        'MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS'             = $Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS             ;  
        'SA_DFNDR_DISABLE_EXECUTION_STATUS'                 = $Global:SA_DFNDR_DISABLE_EXECUTION_STATUS                 ;  
        'SA_PR_HANDLE_FUNCTION_STATUS'                      = $Global:SA_PR_HANDLE_FUNCTION_STATUS                      ;  

        'SET_SFA_CHKDSK_NODE_RESULT_DETERMINED'             = $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED             ;  
        'SET_SFA_SFC_NODE_RESULT_DETERMINED'                = $Global:SET_SFA_SFC_NODE_RESULT_DETERMINED                ; 
        'SET_SFA_DISM_NODE_RESULT_DETERMINED'               = $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED               ;  
        'SET_UA_SYS_UPDATE_NODE_RESULT_DETERMINED'          = $Global:SET_UA_SYS_UPDATE_NODE_RESULT_DETERMINED          ;  
        'SET_UA_STORE_UPDATE_NODE_RESULT_DETERMINED'        = $Global:SET_UA_STORE_UPDATE_NODE_RESULT_DETERMINED        ;  
        'SET_UA_DRIVER_UPDATE_NODE_RESULT_DETERMINED'       = $Global:SET_UA_DRIVER_UPDATE_NODE_RESULT_DETERMINED       ;  
        'SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED'         = $Global:SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED         ;  
        'SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED'       = $Global:SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED       ;  
        'SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED'     = $Global:SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED     ; 
        'SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED'        = $Global:SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED        ; 
        'SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED'       = $Global:SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED       ;  
        'SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED'        = $Global:SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED        ;  
        'SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED'        = $Global:SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED        ;  
        'SET_MRO_DFRG_NODE_RESULT_DETERMINED'               = $Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED               ;  
        'SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED'        = $Global:SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED        ;  
        'SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED'  = $Global:SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED  ;  
        'SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED'       = $Global:SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED       ;  
        'SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED'           = $Global:SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED           ;  
    };
    $Global:ScriptVariableState | ConvertTo-Json | Set-Content -Path ResumeScript.json
}

function Reload_Previous_Script_Instance_State_Handle_Function {
    [CmdletBinding()] param (
        [Parameter()] [String] $Global:PreviousStateFile
    )
    Write-Host "[+] Importing previous instance variable state" -BackgroundColor Yellow
    Start-Sleep -Seconds 3

    # Restore script state by loading variable state information from the statefile
    $Global:State = Get-Content -Path $Global:ScriptVariableState | ConvertFrom-Json

    $Global:CurrentDate                                         = $Global:State.CurrentDate
    $Global:LastDiskOptimizeDate                                = $Global:State.LastDiskOptimizeDate
    $Global:DaysSinceDiskLastOptimized                          = $Global:State.DaysSinceDiskLastOptimized
    $Global:VolumeNumber                                        = $Global:State.VolumeNumber
    $Global:LastSytemRebootDate                                 = $Global:State.LastSytemRebootDate
    $Global:RestartStatusVariable                               = $Global:State.RestartStatusVariable

    $Global:INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS        = $Global:State.INPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS
    $Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS       = $Global:State.OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS

    $Global:SFA_CHKDSK_EXECUTION_FUNCTION_STATUS                = $Global:State.SFA_CHKDSK_EXECUTION_FUNCTION_STATUS
    $Global:SFA_SFC_EXECUTION_FUNCTION_STATUS                   = $Global:State.SFA_SFC_EXECUTION_FUNCTION_STATUS
    $Global:SFA_DISM_EXECUTION_FUNCTION_STATUS                  = $Global:State.SFA_DISM_EXECUTION_FUNCTION_STATUS
    $Global:UA_SYS_UPDATE_FUNCTION_STATUS                       = $Global:State.UA_SYS_UPDATE_FUNCTION_STATUS
    $Global:UA_STORE_UPDATE_FUNCTION_STATUS                     = $Global:State.UA_STORE_UPDATE_FUNCTION_STATUS
    $Global:UA_DRIVER_UPDATE_FUNCTION_STATUS                    = $Global:State.UA_DRIVER_UPDATE_FUNCTION_STATUS
    $Global:NOP_DNS_UPDATE_FUNCTION_STATUS                      = $Global:State.NOP_DNS_UPDATE_FUNCTION_STATUS
    $Global:NOP_IRPSS_UPDATE_FUNCTION_STATUS                    = $Global:State.NOP_IRPSS_UPDATE_FUNCTION_STATUS
    $Global:NOP_BAPP_CONFIGURE_FUNCTION_STATUS                  = $Global:State.NOP_BAPP_CONFIGURE_FUNCTION_STATUS
    $Global:NOP_LSO_DISABLE_FUNCTION_STATUS                     = $Global:State.NOP_LSO_DISABLE_FUNCTION_STATUS
    $Global:NOP_ATUN_DISABLE_FUNCTION_STATUS                    = $Global:State.NOP_ATUN_DISABLE_FUNCTION_STATUS
    $Global:NOP_QOS_DISABLE_FUNCTION_STATUS                     = $Global:State.NOP_QOS_DISABLE_FUNCTION_STATUS

    $Global:MRO_DFRG_EXECUTION_FUNCTION_STATUS                  = $Global:State.MRO_DFRG_EXECUTION_FUNCTION_STATUS
    $Global:MRO_TEMP_UPDATE_FUNCTION_STATUS                     = $Global:State.MRO_TEMP_UPDATE_FUNCTION_STATUS
    $Global:MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS               = $Global:State.MRO_INC_PFSIZE_UPDATE_FUNCTION_STATUS
    $Global:SA_DFNDR_DISABLE_EXECUTION_STATUS                   = $Global:State.SA_DFNDR_DISABLE_EXECUTION_STATUS
    $Global:SA_PR_HANDLE_FUNCTION_STATUS                        = $Global:State.SA_PR_HANDLE_FUNCTION_STATUS

    $Global:SET_SFA_CHKDSK_NODE_RESULT_DETERMINED               = $Global:State.SET_SFA_CHKDSK_NODE_RESULT_DETERMINED
    $Global:SET_SFA_SFC_NODE_RESULT_DETERMINED                  = $Global:State.SET_SFA_SFC_NODE_RESULT_DETERMINED
    $Global:SET_SFA_DISM_NODE_RESULT_DETERMINED                 = $Global:State.SET_SFA_DISM_NODE_RESULT_DETERMINED
    $Global:SET_UA_SYS_UPDATE_NODE_RESULT_DETERMINED            = $Global:State.SET_UA_SYS_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_UA_STORE_UPDATE_NODE_RESULT_DETERMINED          = $Global:State.SET_UA_STORE_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_UA_DRIVER_UPDATE_NODE_RESULT_DETERMINED         = $Global:State.SET_UA_DRIVER_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED           = $Global:State.SET_NOP_DNS_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED         = $Global:State.SET_NOP_IRPSS_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED       = $Global:State.SET_NOP_BAPP_CONFIGURE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED          = $Global:State.SET_NOP_LSO_DISABLE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED         = $Global:State.SET_NOP_ATUN_DISABLE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED          = $Global:State.SET_NOP_QOS_DISABLE_NODE_RESULT_DETERMINED
    $Global:SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED          = $Global:State.SET_NOP_P2P_DISABLE_NODE_RESULT_DETERMINED
    $Global:SET_MRO_DFRG_NODE_RESULT_DETERMINED                 = $Global:State.SET_MRO_DFRG_NODE_RESULT_DETERMINED
    $Global:SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED          = $Global:State.SET_MRO_TEMP_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED    = $Global:State.SET_MRO_INC_PFSIZE_UPDATE_NODE_RESULT_DETERMINED
    $Global:SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED         = $Global:State.SET_SA_DFNDR_DISABLE_NODE_RESULT_DETERMINED
    $Global:SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED             = $Global:State.SET_SA_PR_HANDLE_NODE_RESULT_DETERMINED
    
}