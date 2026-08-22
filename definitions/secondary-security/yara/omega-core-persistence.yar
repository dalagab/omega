/* Omega Core YARA: persistence compound indicators. */

rule Omega_RunKey_Persistence_Executable
{
    strings:
        $runkey_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runkey_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $registry_1 = "RegSetValue" ascii wide
        $registry_2 = "RegistryKey.SetValue" ascii wide
        $drop_1 = "WriteAllBytes" ascii wide
        $drop_2 = "FileStream" ascii wide
        $exec_1 = "Process.Start" ascii wide
        $exec_2 = "CreateProcess" ascii wide
    condition:
        1 of ($runkey_*) and 1 of ($registry_*) and 1 of ($drop_*) and 1 of ($exec_*)
}

rule Omega_ScheduledTask_Persistence
{
    strings:
        $schtasks = "schtasks.exe" ascii wide nocase
        $create = "/create" ascii wide nocase
        $taskname = "/tn" ascii wide nocase
        $taskrun = "/tr" ascii wide nocase
        $exec_1 = "Process.Start" ascii wide
        $exec_2 = "ShellExecute" ascii wide
    condition:
        $schtasks and $create and $taskname and $taskrun and 1 of ($exec_*)
}

rule Omega_Service_Persistence_Native
{
    strings:
        $scm = "OpenSCManager" ascii wide
        $create = "CreateService" ascii wide
        $start = "StartService" ascii wide
    condition:
        all of them
}
