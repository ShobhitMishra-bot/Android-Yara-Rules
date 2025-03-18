rule Detect_XREFto_In_APK
{
    meta:
        author = "Shobhit"
        description = "Detects the string 'XREFto' in direct APK files"
        date = "2025-01-22"
        version = "1.0"

    strings:
        $xref_to_string = "XREFto"

    condition:
        $xref_to_string
}
