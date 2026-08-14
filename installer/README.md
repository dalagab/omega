# Omega repository installer

The installer is intentionally small and auditable. It **does not install Omega itself**. It only registers the Omega PluginMaster URL in Dalamud's custom repository list so Dalamud can perform the normal install/update/uninstall lifecycle.

## File changed

Default Windows path:

```text
%APPDATA%\XIVLauncher\dalamudConfig.json
```

The script changes one logical value in that JSON document: an entry in `ThirdRepoList` with the Omega repository URL and `IsEnabled: true`.

It does **not** copy DLLs, write to the FFXIV installation, modify executables, inject into a process, create a Windows service, create a scheduled task, change the registry, change PATH, add firewall rules, or install an external updater.

Before any write, the installer creates a timestamped backup beside the original configuration file.

## Functions in `Install-OmegaRepository.ps1`

| Function | Purpose | Reads | Writes |
|---|---|---|---|
| `Find-DalamudConfiguration` | Resolves the active config path or `-ConfigPath` override. | Environment / argument | Nothing |
| `Assert-OmegaRepositoryUrl` | Requires an absolute HTTPS repository URL. | Repository URL | Nothing |
| `Assert-DalamudIsNotRunning` | Avoids racing XIVLauncher/Dalamud while they may save config. | Process list | Nothing |
| `Read-DalamudConfiguration` | Reads and parses the existing JSON. | `dalamudConfig.json` | Nothing |
| `Ensure-ThirdRepoList` | Ensures the expected custom-repository collection exists in memory. | In-memory JSON | In-memory only |
| `Add-OrEnableOmegaRepository` | Adds the exact Omega URL or enables the existing entry. | In-memory `ThirdRepoList` | In-memory only |
| `Backup-DalamudConfiguration` | Creates the rollback copy. | Original config | Timestamped backup |
| `Write-DalamudConfigurationAtomically` | Writes validated JSON to a same-directory temporary file and replaces the original. | In-memory config | Temp file, then config |
| `Test-OmegaRepositoryRegistration` | Re-reads the saved file and verifies the exact enabled URL. | Saved config | Nothing |
| `Invoke-OmegaRepositoryInstallation` | Orchestrates the steps above. | All of the above | Only through the explicit write step |

## Preview without changing anything

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Install-OmegaRepository.ps1 -WhatIfOnly
```

## Register the source

Close FINAL FANTASY XIV and XIVLauncher, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\installer\Install-OmegaRepository.ps1
```

After that, start XIVLauncher/FFXIV, open `/xlplugins`, search for **Omega**, and install it normally through Dalamud.

## Removal

`Remove-OmegaRepository.ps1` removes only the exact Omega custom-repository entry and creates a backup first. It does not uninstall the Omega plugin; do that through Dalamud.
