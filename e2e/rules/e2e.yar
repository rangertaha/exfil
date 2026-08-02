rule Detect_Evil_Marker {
    meta:
        description = "Matches the e2e binary fixtures' marker string"
    strings:
        $a = "EVILMARKER"
    condition:
        $a
}
