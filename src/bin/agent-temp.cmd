@echo off
rem agent-temp global launcher (Agent Temp Manager).
rem  * Absolute Windows PowerShell 5.1 path (no PATH lookup) and -NoProfile (no user profile code).
rem  * PSModulePath pinned to the system module directory for the child process only: modules come from an
rem    administrator-owned location, and a PowerShell 7 parent cannot leak its incompatible module path.
rem  * PROCESS-SCOPED execution policy for this single administrator-owned, ACL-protected script.
rem    Machine/user execution policies are not modified; Group Policy (MachinePolicy/UserPolicy) still wins.
setlocal
for %%I in ("%~dp0..") do set "ATM_ROOT=%%~fI"
set "PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ATM_ROOT%\agent-temp.ps1" %*
exit /b %ERRORLEVEL%
