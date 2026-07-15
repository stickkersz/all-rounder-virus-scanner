/*
 * Starter YARA rules for common USB-borne threat patterns.
 * Extend with your own / import community rulesets (e.g. YARA-Rules, Neo23x0).
 * Requires the optional `yara-python` package; ignored if not installed.
 */

rule USB_Autorun_Launcher
{
    meta:
        description = "autorun.inf that auto-launches an executable from removable media"
        severity    = "high"
    strings:
        $a = "[autorun]" nocase
        $o = "open=" nocase
        $s = "shellexecute=" nocase
    condition:
        $a and ($o or $s)
}

rule Suspicious_VBS_Dropper
{
    meta:
        description = "VBScript that writes/executes a payload — common USB worm behavior"
        severity    = "medium"
    strings:
        $fso  = "Scripting.FileSystemObject" nocase
        $shell = "WScript.Shell" nocase
        $run  = ".Run" nocase
        $copy = ".CopyFile" nocase
    condition:
        $fso and $shell and ($run or $copy)
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell one-liner that downloads and runs a remote payload"
        severity    = "high"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $iex = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
        $enc = "-enc" nocase
        $hidden = "-w hidden" nocase
    condition:
        (any of ($dl1, $dl2)) and (any of ($iex, $iex2, $enc, $hidden))
}
