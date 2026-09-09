@echo off
cd /d "%~dp0"
if exist test-monitor-log.txt del test-monitor-log.txt
if exist test-monitor-done.txt del test-monitor-done.txt
echo === pip install -r requirements.txt === > test-monitor-log.txt
"venv\Scripts\python.exe" -m pip install -r requirements.txt >> test-monitor-log.txt 2>&1
echo. >> test-monitor-log.txt
echo === running test_monitor.py === >> test-monitor-log.txt
"venv\Scripts\python.exe" test_monitor.py >> test-monitor-log.txt 2>&1
echo DONE > test-monitor-done.txt
