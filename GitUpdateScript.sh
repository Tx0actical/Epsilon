#!/bin/bash
cd C:\Users\abc\source\repos\Project_Automation\
echo "[*] Checking repository status"
git status &&
echo "[*] Adding untracked files"
git add . && 
echo "[*] Committing changes to local"
git commit -am "Regular changes" &&
echo "[*] Pushing changes to remote"
git push origin main && 
echo "[*] Updating local from remote"
git pull origin main