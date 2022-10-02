# # Write-Host hi

# # $LogCommandLifeCycleEvent

# # time elapsed since the script was last run
# $DaysSinceScriptLastRun     = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Days
# $HoursSinceScriptLastRun    = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Hours
# $MinutesSinceScriptLastRun  = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Minutes
# $SecondsSinceScriptLastRun  = (((Get-Date) - (Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime).lastbootuptime)).Seconds

# # 300 seconds, a typical time to restart
# if(( ($DaysSinceScriptLastRun -eq 0) -and ($HoursSinceScriptLastRun -eq 0) -and ($MinutesSinceScriptLastRun -eq 0) -and $SecondsSinceScriptLastRun -ge 300)) {
#     Write-Host "Last restart was caused by a script instance"

#     # because last restart was caused by the script, some additional logic is required to continue where the control left off
# } else {
#     Write-Host "last restart was a normal one"
# }
$Global:ScriptVariableState = @{
        'foo' = $foo;
        'bar' = $bar;
        'baz' = $baz;
    };
    
    $Global:ScriptVariableState | ConvertTo-Json | Set-Content -Path ResumeScript.json
