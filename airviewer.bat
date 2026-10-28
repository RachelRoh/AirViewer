@echo off
rem Drag an Ellisys CSV export onto this file (or: airviewer.bat capture.csv [options]).
rem Makes capture_airviewer.html next to the CSV and opens it.
where py >nul 2>nul
if %errorlevel%==0 (py -3 "%~dp0airviewer.py" %*) else (python "%~dp0airviewer.py" %*)
if errorlevel 1 pause
