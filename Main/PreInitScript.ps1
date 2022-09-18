param([string] $PreInitScriptPath) 

$PreInitScriptPath = "${$PSScriptRoot}InitScript.ps1"

Write-Host "[*] Intializing PreInitScript" -ForegroundColor Green
Start-Sleep -Seconds 1
Write-Host "[*] Importing Modules" -ForegroundColor Yellow

# Import user module
Import-Module -Name Microsoft.PowerShell.LocalAccounts

# Import current user profile
$CurrentUser = whoami.exe

# Get members of administrators group
$IsAdmin = Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name

function Start_InitScript_Execution_Function {
    [CmdletBinding()] param (
        [string] $PreInitScriptPath
    )

    # Check if user is Admin and act accordingly
    if ($IsAdmin -Contains $CurrentUser) {
        try {
            Start-Process -FilePath "pwsh.exe ${PreInitScriptPath}" -ArgumentList "-ExecutionPolicy Bypass -NoExit -RedirectStandardError ./debugfile.txt -WindowStyle Maximized" -Verb RunAs
        } catch {
            Write-Host "[-] Unable start Main script" -ForegroundColor Red
        }

    } else {

        Write-Host "[-] Current user not admin" -ForegroundColor Red
        Start-Sleep -Seconds 2
        Write-Host "[*] Please provide admin credentials" -ForegroundColor Blue
        Start-Sleep -Seconds 2

        try {
            Start-Process -FilePath "pwsh.exe ${PreInitScriptPath}" -ArgumentList " (Get-Credential) -ExecutionPolicy Bypass -NoExit -RedirectStandardError ./debugfile.txt -WindowStyle Maximized" -Verb RunAs
        } catch {
            Write-Host "[-] Credentials Insufficient or Incorrect. Please try again later" -ForegroundColor Red
            Start-Sleep -Seconds 2
            Exit-PSSession
        }
    }   
}

Start_InitScript_Execution_Function
