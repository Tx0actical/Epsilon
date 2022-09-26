[![Project Status: Concept – Minimal or no implementation has been done yet, or the repository is only intended to be a limited example, demo, or proof-of-concept.](https://www.repostatus.org/badges/latest/concept.svg)](https://www.repostatus.org/#concept)
<a href="https://www.repostatus.org/#wip"><img src="https://www.repostatus.org/badges/latest/wip.svg" alt="Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public." /></a>

![Weights and Biases](https://img.shields.io/badge/Weights_&_Biases-FFBE00?style=for-the-badge&logo=WeightsAndBiases&logoColor=white)
![VS Code](https://img.shields.io/badge/VSCode-0078D4?style=for-the-badge&logo=visual%20studio%20code&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/powershell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

:warning: The project is in **Initial Development**, also indicated by the badges above. Please consider side-effects before running the script in production environments, do so at your own volition. **Do not run this script, except for, testing environments**.

# Stochastic Optimization of System Wide Performance Characteristics in WindowsOS using PowerShell.

## Aim

Provide the least possible element of user interaction in which the user doesn’t even need to specify what problem affects the system, the script will auto-’magically’ pull data from logs, determine the problem and apply the fix.

## Overview

In a lot of other optimization software/scripts, user interaction is required to interface with the tool, so that a better determination of the problem can be made. This involves passing parameters, calling specific functions, using dedicated troubleshooters to get the desired results. This might not be the most user friendly.

This is where Stochastic Optimization (SO) comes in. In classical sense, SO means that a Neural Network is non-deterministic in nature, outcomes cannot be determined and results vary each time a stochastic algorithm is run. In the context of this project (matching the classical idea), SO is used to describe the process of determination of causes of performance issues in Windows OS by employing a Machine Learning (ML) Model looking at logs and related system behaviour, then determining the cause of the issue, and try to fix that as a last step.

Problems like BSODs (Blue Screen of Death) can have multiple causes like Bad driver configuration, recent Software updates, Hardware problems like Memory failures, Power failures, Disk Errors. The initial state of the system is unoptimized. The final state can be assumed to be optimized, for the sake of argument. But as seen in the BSOD example, there might not be a single cause and any automatic optimization may fail to rectify the issue, as complex system misbehaviours most often require manual analysis like manual debugging. Hence, realistically, automatic optimization approches like this one, may or may not be able to fix all issues, that's why the nature of AI environment is stochastic in nature. 

The heart of this script is a MultiLayer Perceptron (MLP) that is trained to recognise patterns of mis-configuration and/or inefficient settings (such as Background Apps that might waste system resources). After determinig the problem, the MLP is used activate different sections of the main script, `Script.ps1`, to try and fix the issues.

## Features

The script has the following features:

- System File Auditing &rarr; The script uses CheckDisk (CHKDSK), System File Checker (SFC), and Deployment Image Servicing and Management (DISM) tools, to automate system-files integrity checking. 
- Updating Capabilities &rarr; The script uses WinGet and other modules to perform System, Microsoft Store, and Driver updates, if available.
- Network Optimization &rarr; The script aims to change DNS server to Google, changes IRP stack size, configures background apps to utilise less resources, disables Large Send Offload (LSO), Disables Windows Auto Tuning, Disable QoS Packet Scheduler, Disables P2P Update Process, with an aim to improve network performance.
- Memory Resource Optimization &rarr; The script is capable of optimizing non-volatile memory in the system, by using the buit-in Disk Deframentor Utility, et al.
- Security Checks &rarr; The script can start Windows Defender to perform a quick/complete scan depending upon last scan and recognise, and kill suspicious/not responding processes.

## Useage

> Running `.\PreInitScript` without `Administrator` is equivalent to running `.\InitScript` as `Administrator`.

- Clone the repository:
```
git clone https://github.com/Tx0actical/EpsilonScript
```
- `cd` into the repository directory
- `cd [Drive]://[Path]/[to]/[PreInitScript]`
- `.\PreInitScript.ps1`

## Results

- [ ] How the result is displayed, formatted and presented to the user, is still a work in progress.

## Tasks

- [x] Complete overall structure of `Script.ps1`, `Network.ps1`, and `Neural_Engine.ps1`
- [x] Function definitions for the remaining functions in `.\Script.ps1`.
- [x] Individual components have reached a semi-working state.
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
