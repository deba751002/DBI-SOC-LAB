rule Suspicious_Mimikatz_Strings
{
    meta:
        description = "Generic strings commonly found in Mimikatz and forks"
        mitre_technique = "T1003.001"
        severity = "critical"
        author = "SOC Lab"

    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "sekurlsa::pth" nocase
        $s3 = "mimikatz" nocase wide ascii
        $s4 = "gentilkiwi" nocase
        $s5 = { 4B 00 49 00 57 00 49 00 } // "KIWI" wide-encoded marker used in several builds

    condition:
        any of them
}

rule LSASS_Dump_File_Marker
{
    meta:
        description = "MDMP header combined with lsass-related strings, typical of a saved LSASS memory dump"
        mitre_technique = "T1003.001"
        severity = "critical"
        author = "SOC Lab"

    strings:
        $mdmp_header = { 4D 44 4D 50 93 A7 }  // "MDMP" minidump signature
        $lsass       = "lsass" nocase

    condition:
        $mdmp_header at 0 and $lsass
}
