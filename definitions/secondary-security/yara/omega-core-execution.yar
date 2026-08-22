/* Omega Core YARA: high-signal execution/injection compound indicators. */

rule Omega_Process_Injection_Classic
{
    strings:
        $open = "OpenProcess" ascii wide
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread = "CreateRemoteThread" ascii wide
    condition:
        all of them
}

rule Omega_Process_Injection_NtThread
{
    strings:
        $open = "OpenProcess" ascii wide
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread = "NtCreateThreadEx" ascii wide
    condition:
        all of them
}

rule Omega_PowerShell_Encoded_Download_Execute
{
    strings:
        $shell_1 = "powershell.exe" ascii wide nocase
        $shell_2 = "pwsh.exe" ascii wide nocase
        $encoded_1 = "-EncodedCommand" ascii wide nocase
        $encoded_2 = " -enc " ascii wide nocase
        $download_1 = "Invoke-WebRequest" ascii wide nocase
        $download_2 = "DownloadString" ascii wide
        $download_3 = "DownloadFile" ascii wide
        $execute_1 = "Process.Start" ascii wide
        $execute_2 = "ShellExecute" ascii wide
    condition:
        1 of ($shell_*) and 1 of ($encoded_*) and 1 of ($download_*) and 1 of ($execute_*)
}

rule Omega_Defender_Exclusion_Tamper
{
    strings:
        $command_1 = "Add-MpPreference" ascii wide nocase
        $command_2 = "Set-MpPreference" ascii wide nocase
        $setting_1 = "-ExclusionPath" ascii wide nocase
        $setting_2 = "DisableRealtimeMonitoring" ascii wide nocase
        $setting_3 = "DisableBehaviorMonitoring" ascii wide nocase
    condition:
        1 of ($command_*) and 1 of ($setting_*)
}

rule Omega_Base64_PE_Dynamic_Load
{
    strings:
        $mz_base64 = "TVqQAAMAAAAEAAAA" ascii wide
        $decode = "FromBase64String" ascii wide
        $load_1 = "Assembly.Load" ascii wide
        $load_2 = "Assembly.LoadFrom" ascii wide
        $write = "WriteAllBytes" ascii wide
        $execute = "Process.Start" ascii wide
    condition:
        $mz_base64 and $decode and (1 of ($load_*) or ($write and $execute))
}

rule Omega_AMSI_Memory_Patch_Compound
{
    strings:
        $amsi_1 = "AmsiScanBuffer" ascii wide
        $amsi_2 = "amsi.dll" ascii wide nocase
        $memory_1 = "VirtualProtect" ascii wide
        $memory_2 = "GetProcAddress" ascii wide
    condition:
        all of them
}
