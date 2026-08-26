/* Omega Core YARA: contextual anti-analysis indicators.
 * These matches are intentionally treated as anomaly evidence, not malware verdicts.
 */

rule Omega_AntiDebug_API_Cluster
{
    strings:
        $debug_1 = "IsDebuggerPresent" ascii wide
        $debug_2 = "CheckRemoteDebuggerPresent" ascii wide
        $debug_3 = "NtQueryInformationProcess" ascii wide
        $debug_4 = "OutputDebugString" ascii wide
    condition:
        3 of them
}

rule Omega_AntiVM_Environment_Cluster
{
    strings:
        $vm_1 = "VBoxGuest" ascii wide nocase
        $vm_2 = "VBoxService" ascii wide nocase
        $vm_3 = "VMware Tools" ascii wide nocase
        $vm_4 = "vmtoolsd" ascii wide nocase
        $vm_5 = "QEMU" ascii wide nocase
        $vm_6 = "VIRTUALBOX" ascii wide nocase
    condition:
        3 of them
}
