@echo off

nssm install ConsentMonitor .\ConsentMonitor.exe

nssm set ConsentMonitor DisplayName ConsentMonitor

nssm set ConsentMonitor Description Monitor Consent UI Processes

nssm set ConsentMonitor Start SERVICE_AUTO_START

nssm set ConsentMonitor ObjectName LocalSystem

nssm start ConsentMonitor