workflow test-restart {

    Get-WmiObject -Class Win32_ComputerSystem | Out-File -FilePath C:Reportscomp.txt
   
    Get-ChildItem -Path C:Reports | Out-File -FilePath C:dir.txt
   
    Restart-Computer -Wait
   
    Get-WmiObject -Class Win32_OperatingSystem | Out-File -FilePath C:Reportsos.txt
   
}