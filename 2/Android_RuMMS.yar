rule Android_RuMMS
{
    meta:
        author = "reverseShell - https://twitter.com/JReyCastro"
        date = "2016/04/02"
        description = "Detects Android.Banking.RuMMS malware based on package names and permissions."
        sample = "13569bc8343e2355048a4bccbe92a362dde3f534c89acff306c800003d1d10c6"
        source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

    strings:
        $package_name_1 = "org.starsizew"
        $package_name_2 = "com.tvone.untoenynh"
        $package_name_3 = "org.zxformat"

    condition:
        any of ($package_name_*)
}

