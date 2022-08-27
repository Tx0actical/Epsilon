# Parameter help description
Write-Host "[+] Provide the path to InitScript.ps1" -ForegroundColor Blue

param([string] $PreInitScriptPath = "${$PSScriptRoot}\InitScript.ps1") 

Write-Host "[*] Intializing PreInitScript" -ForegroundColor Green
Write-Host "[*] Importing Modules" -ForegroundColor Yellow

# Import user module
Import-Module -Name Microsoft.PowerShell.LocalAccounts

Import-Module -Name Microsoft.PowerShell.Core

# Import current user profile
$CurrentUser = whoami.exe

# Get members of administrators group
$IsAdmin = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name

function Start_InitScript_Execution_Function {

    [CmdletBinding()]
    param (
        
    )
    # Check if user is Admin and act accordingly
    if ($IsAdmin -Contains $CurrentUser) {


        # Spawn PowerShell with admin privileges
        Start-Process -FilePath "powershell.exe -file ${PreInitScriptPath}" -Verb RunAs -RedirectStandardError ./debugfile.txt -WindowStyle Maximized

        
        # Modify ExecutionPolicy to run scripts
        try {
            $ExecutionPolicy = Get-ExecutionPolicy
            if ($ExecutionPolicy -ne 'Bypass') {
                Set-ExecutionPolicy Bypass -Force
            }
        } catch {
            Write-Host "[-] Unable to get required Execution Policy permissions" -ForegroundColor Red    
        } finally {
            Write-Host "Have a nice day :)" -BackgroundColor Green
        }
    }
    else {
        Write-Host "[-] Current user not admin" -ForegroundColor Red
        Write-Host "[*] Please provide admin credentials" -ForegroundColor Blue
        try {
            Start-Process -FilePath "powershell.exe -file InitScript.ps1 - " (Get-Credential) -RedirectStandardError ./debugfile.txt -WindowStyle Maximized
        } catch {
            Write-Host "[-] Credentials Insufficient or Incorrect. Please try again later" -ForegroundColor Red
            Exit-PSSession
        } finally {
            Write-Host "Have a nice day :)" -BackgroundColor Green
        }
    }   
}

Start_InitScript_Execution_Function
