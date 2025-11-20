# ConsentMonitor Summary

ConsentMonitor is a utility designed to monitor consent.exe and capture the memory block passed to it during a User Account Control (UAC) prompt. When UAC is triggered, the **AppInfo** service (running under *svchost.exe*) calls consent.exe and provides three key pieces of information: the process ID, the size of the memory block, and the memory block’s address. For example:

`consent.exe 1072 468 000002050F426B30`

If the UAC prompt is approved, consent.exe exits and the elevated process is launched with explorer.exe as its parent. However, it’s not always obvious which process was attempting elevation-particularly when UAC fails.

ConsentMonitor captures the passed memory block to provide visibility into **what process was attempting to elevate**, making it easier to analyze UAC activity.

# Usage
ConsentMonitor must be run from an elevated command prompt. When executed without arguments, it writes its logs to a custom event log provider. If the `-c` option is specified, output is sent to the console instead.

![](.\Images\event5.png)
![](.\Images\event1.png)
![](.\Images\cmd.png)

ConsentMonitor can also be ran as a service. This can be acheived by doing the following:
1. Download [NSSM](https://nssm.cc/download). In the same folder as NSSM, copy ConsentMonitor_Service.bat and change the path to ConsentMonitor:
    ```
    @echo off

    nssm install ConsentMonitor <PATH_TO_CONSENTMONITOR>\ConsentMonitor.exe

    nssm set ConsentMonitor DisplayName ConsentMonitor

    nssm set ConsentMonitor Description Monitor Consent UI Processes

    nssm set ConsentMonitor Start SERVICE_AUTO_START

    nssm set ConsentMonitor ObjectName LocalSystem

    nssm start ConsentMonitor
    ```

2. From a command prompt, run auto_ingest_service.bat. If everything was successful, you should see the following output:  
    >C:\nssm-2.24\nssm-2.24\win64>auto_ingest_service.bat

    Service "ConsentMonitor" installed successfully!  
    Set parameter "DisplayName" for service "ConsentMonitor".  
    Set parameter "Description" for service "ConsentMonitor".  
    Set parameter "Start" for service "ConsentMonitor".  
    Reset parameter "ObjectName" for service "ConsentMonitor" to its default.  
    ConsentMonitor: START: The operation completed successfully.