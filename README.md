[![Project Status: Concept – Minimal or no implementation has been done yet, or the repository is only intended to be a limited example, demo, or proof-of-concept.](https://www.repostatus.org/badges/latest/concept.svg)](https://www.repostatus.org/#concept)
<a href="https://www.repostatus.org/#wip"><img src="https://www.repostatus.org/badges/latest/wip.svg" alt="Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public." /></a>

![Weights and Biases](https://img.shields.io/badge/Weights_&_Biases-FFBE00?style=for-the-badge&logo=WeightsAndBiases&logoColor=white)
![VS Code](https://img.shields.io/badge/VSCode-0078D4?style=for-the-badge&logo=visual%20studio%20code&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/powershell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

> :warning: **The project is in a Concept/Initial Development stage, also indicated by badges above. Please consider side-effects before running the script and do so at your own volition. Do not run this except for testing environments** :warning:

# Stochastic Optimization of System Wide Performance Characteristics in WindowsOS using PowerShell.

## Overview

In a lot of other optimization software/scripts, user interaction is required to interface with the tool, so that a better determination of the problem can be made. This involves passing parameters, calling specific functions, using dedicated troubleshooters, to get the desired results. This might not be the most user friendly.

This is where Stochastic Optimization (SO) comes in. In classical sense, SO means that a Neural Network is non-deterministic in nature, outcomes cannot be determined and results vary each time a stochastic algorithm is run. In the context of this project (matching the classical idea), SO is used to describe the process of determination of causes of performance issues in Windows OS by employing a Machine Learning (ML) Model looking at logs and related system behaviour, then determining the cause of the issue, and try to fix that as a last step.

Problems like BSODs (Blue Screen of Death) can have multiple causes like Bad driver configuration, recent Software updates, Hardware problems like Memory failures, Power failures, Disk Errors. The initial state of the system is unoptimized. The final state can be assumed to be optimized, for the sake of argument. But as seen in the BSOD example, there might not be a single cause and any automatic optimization may fail to rectify the issue, as complex system misbehaviours most often require manual analysis like manual debugging. Hence, realistically, automatic optimization approches like this one, may or may not be able to fix all issues, that's why the nature of AI environment is stochastic in nature. 

The heart of this script is a MultiLayer Perceptron (MLP) that is trained to recognise patterns of mis-configuration and/or inefficient settings (such as Background Apps that might waste system resources). After determinig the problem, the MLP is used activate different sections of the main script, `Script.ps1`, to try and fix the issues.

In a nutshell the script aims to:

> Provide the least possible element of user interaction in which the user doesn’t even need to specify what type of error he/she is facing, the script will auto-’magically’ pull data from logs, determine the type of error and try to fix that.

## Features

The script has the following features:

- System File Auditing &rarr; The script uses CheckDisk (CHKDSK), System File Checker (SFC), and Deployment Image Servicing and Management (DISM) tools, to automate system-files integrity checking. These functions are handled by `Run_CHKDSK_Utility_Execution_Function`, `Run_SFC_Utility_Execution_Function`, and `Run_DISM_Utility_Execution_Function` respectively. 
- Updating Capabilities &rarr; The script uses WinGet, modules such as `PSWindowsUpdate` to perform System, Microsoft Store, and Driver updates, if available. These are handled by `Update_Windows_System_Handle_Function`, `Update_Microsoft_Store_Application_Handle_Function`, and `Update_Windows_System_Drivers_Handle_Function`.
- Network Optimization &rarr; The script aims to change DNS server to Google, changes IRP stack size, configures background apps to utilise less resources, disables Large Send Offload (LSO), Disables Windows Auto Tuning, Disable QoS Packet Scheduler, Disables P2P Update Process, with an aim to improve network performance. These are achieved by 
```
Change_DNS_Server_Update_Function
Change_IRP_Stack_Size_Update_Function
Configure_Background_Applications_Settings_Handle_Function
Disable_Large_Send_Offload_Handle_Function
Disable_Windows_Auto_Tuning_Handle_Function
Disable_Quality_Of_Service_Packet_Scheduler_Handle_Function
Disable_P2P_Update_Process_Handle_Function
```
- Memory Resource Optimization &rarr; The script is capable of optimizing non-volatile memory in the system, by using the buit-in Disk Deframentor Utility which is handled by `Run_Disk_Defragmentor_Execution_Function`, and a couple of registry tweaks which is the duty of `Remove_TEMP_Files_Update_Function` and `Set_Increase_Pagefile_Size_Update_Function`, as they seek to flush temporary files and increase pagefile size, respectively.
- Security Checks &rarr; The script can start Windows Defender to perform a quick/complete scan depending upon last scan and recognise, and kill suspicious/not responding processes. There are achieved through
```
Run_Windows_Defender_Scan_Execution_Function
Analyze_Processes_Handle_Function
```

## Useage

> Running the script as `Administrator` is recommended, but not necessary as it will self-elevate.

### If Git is installed
- Clone the repository by opening a PowerShell terminal and type:
- ```git clone https://github.com/Tx0actical/EpsilonScript```
- `cd` into the repository directory
- ```cd [Drive]://[Path]/[to]/[Script]```
- ```.\Script.ps1```

### If Git is not installed
- Navigate to `https://github.com/Tx0actical/EpsilonScript` and click the `code` button. From the drop-down menu select `Download ZIP`.
- Once downloaded, unzip and run `Script.ps1`

## Results

- [ ] How the result is displayed, formatted and presented to the user, is still a work in progress.

## Tasks

- [x] Complete overall structure of `Script.ps1`, `Network.ps1`, and `Neural_Engine.ps1`
- [x] Function definitions for the remaining functions in `.\Script.ps1`.
- [ ] Integrate the main script with `Neural_Engine.ps1`.
- [ ] Develop a Windows Log Parser, language independent, to collect and parse logs into a suitable format like `json`, `xml`, `csv`, etc.
- [ ] Add Multi-Threading Support to the `.\Script.ps1` script.
- [ ] Research other Neural Networks, study feasibility of integrating/replacing with the current one.
- [ ] Feature &rarr; Giving users choice to opt out of certain optimization methods (e.g. Disabling some features in the Network Optimization Section).

## References

- A big shout-out to [@CarolineChiari](https://github.com/CarolineChiari), the creator of the excellent YouTube stream for building a Neural Network [Coding a Neural Network in PowerShell](https://github.com/CarolineChiari/PowerShell). Really appreciate her work!
- A guide to Optimizing PowerShell Scripts can be found [here](https://www.itprotoday.com/powershell/tips-optimizing-powershell-scripts)
- The Official PowerShell Documentation by Mircosoft, [link](https://docs.microsoft.com/en-us/powershell/)
- An awesome blog on PowerShell Multithreading &rarr; [link](https://adamtheautomator.com/powershell-multithreading/)
- [Tips](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory) for hardening Active Directory networks 
