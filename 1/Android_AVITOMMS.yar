rule Android_Malware_Detector
{
    meta:
        author = "Jacob Soo Lead Re"
        date = "28-May-2016"
        description = "Detects multiple Android malware variants based on hardcoded strings"
        source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"

    strings:
        // Suspicious Services
        $service_1 = "IMService"
        $service_2 = "SpyService"

        // Hardcoded URLs
        $url_1 = "s.cloudsota.com"
        $url_2 = "lexsmilefux.link"
        $url_3 = "niktoegoneyznaet0kol.pw"
        $url_4 = "104.238.176.9"
        $url_5 = "golioni.tk"
        $url_6 = "poloclubs.tk"
        $url_7 = "thejcb.ru"
        $url_8 = "playmarketcheck.com"
        $url_9 = "pornigy.biz"
        $url_10 = "https://bank-phishing-url.com"

    condition:
        // Match any suspicious receivers or services
        all of ($service_*) or

        // Match any hardcoded URLs
        any of ($url_*)
}
