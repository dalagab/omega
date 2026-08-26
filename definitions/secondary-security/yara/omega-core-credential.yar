/* Omega Core YARA: credential/token theft compound indicators.
 * Supplemental evidence only. These rules intentionally require multiple related
 * indicators so ordinary plugin network/filesystem use does not match by itself.
 */

rule Omega_Credential_Browser_DPAPI_Exfil
{
    strings:
        $browser_login = "Login Data" ascii wide nocase
        $browser_state = "Local State" ascii wide nocase
        $browser_cookie = "Cookies" ascii wide nocase
        $dpapi_1 = "CryptUnprotectData" ascii wide
        $dpapi_2 = "ProtectedData.Unprotect" ascii wide
        $sink_webhook = "discord.com/api/webhooks/" ascii wide nocase
        $sink_post = "PostAsync" ascii wide
        $sink_upload = "UploadData" ascii wide
    condition:
        2 of ($browser_*) and 1 of ($dpapi_*) and 1 of ($sink_*)
}

rule Omega_Discord_LevelDB_Token_Exfil
{
    strings:
        $leveldb = "Local Storage\\leveldb" ascii wide nocase
        $discord = "discord" ascii wide nocase
        $dpapi_1 = "CryptUnprotectData" ascii wide
        $dpapi_2 = "ProtectedData.Unprotect" ascii wide
        $webhook = "discord.com/api/webhooks/" ascii wide nocase
        $http_post = "PostAsync" ascii wide
    condition:
        $leveldb and $discord and 1 of ($dpapi_*) and 1 of ($webhook, $http_post)
}

rule Omega_Windows_Credential_API_Exfil
{
    strings:
        $credential_1 = "CredRead" ascii wide
        $credential_2 = "PasswordVault" ascii wide
        $credential_3 = "Windows.Security.Credentials" ascii wide
        $sink_1 = "discord.com/api/webhooks/" ascii wide nocase
        $sink_2 = "PostAsync" ascii wide
        $sink_3 = "UploadString" ascii wide
    condition:
        1 of ($credential_*) and 1 of ($sink_*)
}
