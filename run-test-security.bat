@echo off
cd /d "%~dp0"
if exist test-security-log.txt del test-security-log.txt
if exist test-security-done.txt del test-security-done.txt
echo === pip install -r requirements.txt === > test-security-log.txt
"venv\Scripts\python.exe" -m pip install -r requirements.txt >> test-security-log.txt 2>&1
echo. >> test-security-log.txt
echo === running test_security.py === >> test-security-log.txt
"venv\Scripts\python.exe" test_security.py >> test-security-log.txt 2>&1
echo DONE > test-security-done.txt
