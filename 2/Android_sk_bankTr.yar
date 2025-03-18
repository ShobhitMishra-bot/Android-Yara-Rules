rule andr_sk_bank
{
    meta:
        description = "Yara rule for Banking trojan targeting South Korean banks"
        sample = "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad"
        source = "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users"
        author = "https://twitter.com/5h1vang"

    strings:
        $str_1 = "NPKI"
        $str_2 = "portraitCallBack("
        $str_3 = "android.app.extra.DEVICE_ADMIN"
        $str_4 = "SMSReceiver&imsi="
        $str_5 = "com.ahnlab.v3mobileplus"
        $package_name = "com.qbjkyd.rhsxa"
        $certificate_sha1 = "543382EDDAFC05B435F13BBE97037BB335C2948B"

    condition:
        all of ($str_*) or
        $package_name or
        $certificate_sha1
}
