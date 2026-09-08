rule Generic_PHP_Webshell
{
    meta:
        description = "Common PHP webshell primitives (eval/system on request input)"
        mitre_technique = "T1505.003"
        severity = "high"
        author = "SOC Lab"

    strings:
        $eval1 = "eval($_POST" nocase
        $eval2 = "eval($_GET" nocase
        $eval3 = "eval($_REQUEST" nocase
        $sys1  = "system($_GET" nocase
        $sys2  = "system($_POST" nocase
        $b64   = "base64_decode($_" nocase
        $assert = "assert($_" nocase

    condition:
        any of them
}

rule Generic_ASPX_Webshell
{
    meta:
        description = "Common ASPX/ASP webshell primitives (Process.Start on request params)"
        mitre_technique = "T1505.003"
        severity = "high"
        author = "SOC Lab"

    strings:
        $s1 = "Request.Item[" nocase
        $s2 = "Process.Start" nocase
        $s3 = "cmd.exe /c" nocase
        $s4 = "Server.CreateObject(\"WScript.Shell\")" nocase

    condition:
        2 of them
}
