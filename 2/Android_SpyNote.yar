rule spynote_variants
{
    meta:
        author = "5h1vang"
        description = "Yara rule for detection of different Spynote Variants"
        source = "http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
        rule_source = "https://analyst.koodous.com/rulesets/1710"

    strings:
        $str_1 = "SERVER_IP" nocase
        $str_2 = "SERVER_NAME" nocase
        $str_3 = "content://sms/inbox"
        $str_4 = "screamHacker"
        $str_5 = "screamon"
        $package_name = "dell.scream.application"
        $cert_sha1 = "219D542F901D8DB85C729B0F7AE32410096077CB"

    condition:
        all of ($str_*) or 
        $package_name or 
        $cert_sha1
}
