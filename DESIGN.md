## Zero Section

This section will first check the registry value that is set when the computer is restarted in the middle of script execution.
If the value is set, then the script will continue from where it left off (addtional logic will be required to do that).
If the value is not set, then the script will start from the beginning.

-- OR --

The restart can be handled in the end after the output dispatch center gives a green light after the result of all the functions are determined. In the meantime, restarts can be kept pending.

## Security Audit Sub-Section

More things can be included in this Sub-Section, as it relates to Security. PC can be checked if it is connected to a domain and all security scanning relating to domain can be then applied.

## Probabilistic Activation Determination Section

Functions within this section provides input to the section containing the __Input_Dispatch_Center_Control_Function__ function. Earlier, this Section was a Sub-section (until commit -> 27bb259), but it has been converted because it essentially computes values and pass it to `__Input_Dispatch_Center_Control_Function__` function which ACTUALLY does the changes described in that. So, a Section giving input to itself isn't a great idea - it wouldn't affect the functioning of code per se because these functions are divided into the so-called 'Sections and Sub-Sections' on the basis of comments just to keep track of complexity - as it might be a source of confusion.

The reason why separate functions are required to pass the values to `__Input_Dispatch_Center_Control_Function__` when it can be done right within the Perceptron functions is because all the issues require their own separate result and that is possible by having separate functions of handling each issue.

## Output Handling Section

Output function will collect exit codes from all executed, functions and will give a green light when all are boolean `true` after that the system might proceed to restart for a final time.

# Functions

1. `Set_RunOnce_Registry_Key_Before_Restart_Handle_Function` -> Function to set RunOnce registry value to 1. This will prevent the script from running again after the computer is restarted.

2. `__Input_Dispatch_Center_Control_Function__` -> Function to keep track of inputs after all node probability determination functions are true (values determined). This function will supply inputs to handling functions, where inputs can be simply of bool type because the probabilities will determine the activation of functions that are described in the sub-sections. `[Parameter(Mandatory = $True)]` flag can be used to determine which function was not assigned a value by the sectional functions and that may provide necessary debug information and provide necessary checks during script execution. If the value of `$MASTER_INPUT_DISPATCH_CENTER_FUNCTION_STATUS` is set to true then control-flow will continue that will happen only when the Base Information Sub-Section is properly initialized. Hence, this variable acts as a checker.

3. `Parse_Windows_Event_Log_Handle_Function` -> Parse specific events, count their number subsequent blocks will try to run specific lines of code. Each try block will have an associated boolean variable that will keep track of successful or unsuccessful execution of that particular block. In the end of the function, all these variables will be together tested for true status, in an 'AND' construct. If any single one of them is false a result of unsuccessful execution then a boolean variable that finally determines the state of the current function will be set to true or false accordingly. Variables in this function should be global.

4. Invoke_Perceptron_For_Stop_Error_Parameters_Activation_Determination_Function -> This function determines activations of specific functions that might help resolve stop errors. The inputs will be the number of events that have been detected with respect to stop errors, which will be fetched from the Windows Event Logs. The weights will be the impact of a function in resolving the problem. Higher impact functions will have more weight. Bad driver configuration, Software updates, Hardware failures, Memory failures, Power failures, Disk Errors might be the cause.

5. `__Output_Dispatch_Center_Control_Function__` -> if all functions determine their outputs successfully, then this function will set the `$Global:OUTPUT_DISPATCH_CENTER_FUNCTION_MASTER_STATUS` to true, and if that is true then the system will be ready for final restart. This will set the `$Global:FINAL_RESTART_HANDLE_FUNCTION_STATUS` which will be responsible for restarting the system.

6. `Set_Ready_For_Final_Restart_Handle_Function` -> When everything is okay, system will restart for finally although this behaviour can be updated because of potiential restarts in between the script. For eg., when the system updates some registry values, among other things. That might be a pain for the user.

Another version to handle restart-needed-to-apply-changes, is to postpone the restart until all the operations are
completed and then restarting the system, instead of restarting the system right away, in the middle of script execution.
