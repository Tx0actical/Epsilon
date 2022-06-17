#!/bin/bash
cd C:\Users\abc\source\repos\Project_Automation\
echo "[*] Checking repository status"
git status &&
echo "[*] Adding untracked files"
git add . && 
echo "[*] Committing changes to local"
git commit -am "Changed status variables' scope to global, improved definitions of final restart functions, and added thought comments for restart mechanism. Need to recheck and refine Update_Windows_System_Drivers_Handle_Function and Change_DNS_Server_Update_Function" &&
echo "[*] Pushing changes to remote"
git push origin main && 
echo "[*] Updating local from remote"
git pull origin main