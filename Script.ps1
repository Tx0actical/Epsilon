# **********Initialization Section**********

$Intro = '[*] Intializing System-Wide Optimization Script'
Get-Variable -Name $Intro

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
    $Fail = '[!] Admin privileges required'
    Get-Variable -Name $Fail
}

# **********Post-Initialization Section**********

# Function to keep track of inputs
# after all node probability determination functions are true (values determined)
# Input_Dispatch_Function will supply inputs to handling functions
function Input_Dispatch_Function {
    param (
        OptionalParameters
    )
}

# Event

