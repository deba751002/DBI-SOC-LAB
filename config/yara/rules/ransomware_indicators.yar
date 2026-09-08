rule Ransomware_Note_Generic
{
    meta:
        description = "Common phrasing found in ransomware ransom-note text files"
        mitre_technique = "T1486"
        severity = "critical"
        author = "SOC Lab"

    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "to decrypt your files" nocase
        $s3 = "bitcoin wallet" nocase
        $s4 = "do not rename" nocase
        $s5 = "all your files are encrypted" nocase

    condition:
        2 of them
}

rule Suspicious_Shadow_Copy_Deletion
{
    meta:
        description = "Command-line strings for deleting Volume Shadow Copies / disabling recovery, typical ransomware pre-encryption step"
        mitre_technique = "T1490"
        severity = "critical"
        author = "SOC Lab"

    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wbadmin delete catalog" nocase
        $s3 = "bcdedit /set {default} recoveryenabled no" nocase

    condition:
        any of them
}
