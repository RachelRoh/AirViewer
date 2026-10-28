@echo off
rem Drag an Ellisys trace (.btt) onto this file (or: airviewer.bat capture.btt [options]).
rem Makes capture.html next to the trace and opens it. The Ellisys analyzer must be running
rem with Remote Control enabled; see README.
where py >nul 2>nul
if %errorlevel%==0 (py -3 "%~dp0airviewer.py" %*) else (python "%~dp0airviewer.py" %*)
if errorlevel 1 pause
