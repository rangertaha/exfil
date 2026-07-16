/*
 * Example YARA rules for exfill. Run with:
 *   exfill scan <path> --yara datasets/example.yar
 *
 * Rule metadata (severity, cwe, cve) flows into exfill findings.
 */

rule EICAR_Test_File : malware {
    meta:
        description = "EICAR antivirus test string"
        severity    = "critical"
        cwe         = "CWE-506"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule PE_Executable : binary {
    meta:
        description = "DOS/PE executable header (MZ)"
        severity    = "info"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Suspicious_Shell : script {
    meta:
        description = "Reverse-shell style one-liner"
        severity    = "high"
        cwe         = "CWE-78"
    strings:
        $bash = "bash -i"
        $devtcp = "/dev/tcp/"
    condition:
        all of them
}
