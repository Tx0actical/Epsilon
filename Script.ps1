# **********Start of the main script**********
$Intro = '[*] Welcome! To the GOD of PowerShell scripts! A healthy system is just a script away!'
Get-Variable -Name $Intro

# Check current ExecutionPolicy, 
# set it to Bypass if configured to any other
# Spawn a new powershell with ExecutionPolicy set to 'bypass'
Set-ExecutionPolicy -ExecutionPolicy Bypass
