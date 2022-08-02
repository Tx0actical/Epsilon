![Weights and Biases](https://img.shields.io/badge/Weights_&_Biases-FFBE00?style=for-the-badge&logo=WeightsAndBiases&logoColor=white)
![VS Code](https://img.shields.io/badge/VSCode-0078D4?style=for-the-badge&logo=visual%20studio%20code&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/powershell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

# Stochastic Optimization of System Wide Performance Characteristics in WindowsOS using PowerShell.

## Overview

In a lot of other optimization software/scripts, user interaction is required to interface with the tool, so that a better determination of the problem can be made. This involves passing parameters, calling specific functions, using dedicated troubleshooters, to get the desired results. This might not be the most user friendly.

This is where Stochastic Optimization (SO) comes in. In classical sense, SO means that a Neural Network is non-deterministic in nature, outcomes cannot be determined and results vary each time a stochastic algorithm is run. In the context of this project (matching the classical idea), SO is used to describe the process of determination of causes of performance issues in Windows OS by looking at logs and related system behaviour, then determining the cause of the issue, and try to fix that as a last step.

Problems like BSODs (Blue Screen of Death) can have multiple causes like Bad driver configuration, recent Software updates, Hardware problems, Memory failures, Power failures, Disk Errors. The initial state of the system is unoptimized. The final state can be assumed to be optimized, for the sake of argument. But as seen in the BSOD example, there might not be a single cause and any automatic optimization may fail to rectify the issue, as complex system misbehaviours most often require manual analysis like manual debugging. Hence, realistically, automatic optimization approches like this one, may or may not be able to fix all issues, that's why the nature of AI environment is stochastic in nature. 

The heart of this script is a MultiLayer Perceptron (MLP) that is trained to recognise patterns of mis-configuration and/or inefficient settings (such as Background Apps that might waste system resources). After determinig the problem, the MLP is used activate different sections of the main script, `Script.ps1`, to try and fix the issues.

In a nutshell the script aims to:

> Provide the least possible element of user interaction in which the user doesn’t even need to specify what type of error he/she is facing, the script will auto-’magically’ pull data from logs, determine the type of error and try to fix that.

## Features

The script has the following features:

- System File Auditing &rarr; The script uses CheckDisk (CHKDSK), System File Checker (SFC), and Deployment Image Servicing and Management (DISM) tools, to automate system-files integrity checking. These functions are handled by `Run_CHKDSK_Utility_Execution_Function`, `Run_SFC_Utility_Execution_Function`, and `Run_DISM_Utility_Execution_Function` respectively. 

- Updating Capabilities &rarr; The script uses WinGet, modules such as `PSWindowsUpdate` to perform System, Microsoft Store, and Driver updates, if available. These are handled by `Update_Windows_System_Handle_Function`, `Update_Microsoft_Store_Application_Handle_Function`, and `Update_Windows_System_Drivers_Handle_Function`.

- Network Optimization &rarr; The script aims to change DNS server to Google, changes IRP stack size, configures background apps to utilise less resources, disables Large Send Offload (LSO), Disables Windows Auto Tuning, Disable QoS Packet Scheduler, Disables P2P Update Process, with an aim to improve network performance. These are achieved by `Change_DNS_Server_Update_Function`, `Change_IRP_Stack_Size_Update_Function`, `Configure_Background_Applications_Settings_Handle_Function`,`Disable_Large_Send_Offload_Handle_Function, Disable_Windows_Auto_Tuning_Handle_Function`, `Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function`, and `Disable_P2P_Update_Process_Handle_Function`.

- Memory Resource Optimization &rarr; The script is capable of optimizing non-volatile memory in the system, by using the buit-in Disk Deframentor Utility which is handled by `Run_Disk_Defragmentor_Execution_Function`, and a couple of registry tweaks which is the duty of `Remove_TEMP_Files_Update_Function` and `Set_Increase_Pagefile_Size_Update_Function`, as they seek to flush temporary files and increase pagefile size, respectively.

- Security Checks &rarr; The script uses
## Installation

Clone the repository, `cd` into the repository directory and run:

`.\Script.ps1`

> Running the script as `Administrator` is recommended, but not necessary as it will self-elevate.

## Results

## Tasks

- [x] Complete overall structure of `Script.ps1`, `Network.ps1`, and `Neural_Engine.ps1`
- [ ] Add Multi-Threading Support to the `.\Script.ps1` script.
- [ ] Integrate the main script with `Neural_Engine.ps1`.
- [ ] Develop a Windows Log Parser, language independent, to collect and parse logs into a suitable format like `json`, `xml`, `csv`, etc.
- [ ] Function defintions for the remaining functions in `.\Script.ps1`.
- [ ] Research other Neural Networks, study feasibility of integrating/replacing with the current one.
- [ ] Giving users choice to opt out of certain optimization methods (e.g. Disabling some features in the Network Optimization Section).

## References

- [Guide to optimize PowerShell scripts](https://www.itprotoday.com/powershell/tips-optimizing-powershell-scripts)

- An excellent YouTube stream for building a Neural Network &rarr; [Neural Networks in PowerShell](https://github.com/CarolineChiari/PowerShell)

- [Official PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)

- [Multi-Threading in PowerShell](https://adamtheautomator.com/powershell-multithreading/)

## <Rough Section>

- To automate system file integrity checking, SFC and DISM can be used.
    - Additional rules can be applied, for eg. using task scheduler to trigger the script when a critical warning has lead to a sudden reboot. This can be looked by event viewer.
    - Another thing, after running SFC, if problems were found and fixed, them system needs to restart, but upon restart, either the script should continue to run or TS should run another     script based on the restart event.
        - This should be the first in script even before SFC and DISM, that would optimize later processes.

- To automate storage optimization across all drives, disk defragmenter can be used.

- `ExecutionPolicy` should be set to unrestricted for the instance in which the script will run. `ExecutionPolicy` will be set to default before exiting.

- The script might check when passwords were last changed, checks if Windows Updates are pending, checks if the user has a local or cloud backup. Thus, they can come under security recommendations.

- Script can record itself into the event log. If it was run in the past 14 days (or a custom/any other time period), then it can inform the user about this, put up a choice, if they want to run it or not.

- Script can perform security functions by recognizing suspicious processes and kill them.

- Most importantly, the script will collect logs, there will be functions for determining problems that the system might be facing. Those functions should calculate probabilities to determine (with best possible confidence) possible problem(s), and based on that probability, it should trigger specific remediation methods (specific to the determined problem). Specifically, critical or warning logs can be looked into, for better determination.

- **Windows Updates**: Even windows updates can be based on the EventLog. The logs can be searched for the last time the system was updated and based upon that (for eg., if the last time the system was updated was more than 40 days ago, chances are, that the system is not updated. Also the script may attempt to turn on automatic updates after updating. Moreover, even before checking for updates manually the script can straightaway check if automatic updates are enabled, if they are, then it can skip to checking for updates), the function should decide whether to check for updates or not.

- **Network Optimization**: Script can renew DHCP lease, configure DNS to CloudFlare (More rules can be added!)

- **Disk Optimization**: Script can check when the disk was last optimized

- Each of the mentioned Sub-Sections can later be converted into structures containing functions. But this is a speculation.

- This being a custom script. The usual naming conventions were not strictly followed because of the following reasons:
    - To make more functions more descriptive, their type is mentioned after the function that it performs. And that function not being normal, is written in a way to be descriptive.
    - To avoid conflict with existing functions and cmdlets within PowerShell.
    - Some functions names are esoteric, meaning, they are unique to this script.
    - Moreover, these functions are defined inside script, they are not called directly in a command-line.

- There should be extensive focus on reducing restarts.

- Various functional tests are implemented, in-line with the best practices of unit testing. Best example being the `$MasterInputDispatchCenterFunctionStatus` **variable without which being set to true the script cannot perform maintenance tasks and all the sub-sections will not run.

- An important thing to keep in mind while determining the cause of a particular problem, is to analyse what was going on when the problem happened or in other words, what was the state?

- Maybe the script should put more focus on security.

- A realistic and useful aim would be solve a problem for which there is no troubleshooter available.

## </Rough Section>

