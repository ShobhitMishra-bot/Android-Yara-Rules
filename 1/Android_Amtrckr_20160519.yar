rule coudw_amtrckr
{
    meta:
        family = "coudw"
        description = "Detects hardcoded malicious URLs related to coudw malware"

    strings:
        $url_1 = "s.cloudsota.com"

    condition:
        $url_1
}

rule z3core_amtrckr
{
    meta:
        family = "z3core"
        description = "Detects hardcoded malicious URLs related to z3core malware"

    strings:
        $url_1 = "lexsmilefux.link"

    condition:
        $url_1
}

rule gtalocker_amtrckr
{
    meta:
        family = "gtalocker"
        description = "Detects hardcoded malicious URLs related to gtalocker malware"

    strings:
        $url_1 = "niktoegoneyznaet0kol.pw"

    condition:
        $url_1
}

rule marcher_amtrckr
{
    meta:
        family = "marcher"
        description = "Detects hardcoded malicious URLs related to marcher malware"

    strings:
        $url_1 = "104.238.176.9"
        $url_2 = "golioni.tk"
        $url_3 = "poloclubs.tk"
        $url_4 = "thejcb.ru"
        $url_5 = "shgt.tk"
        $url_6 = "pologt.tk"
        $url_7 = "vipcoon.com"
        $url_8 = "firenzonne.com"

    condition:
        any of ($url_*)
}

rule lenovo_reaper_amtrckr
{
    meta:
        family = "lenovo_reaper"
        description = "Detects hardcoded malicious URLs related to lenovo_reaper malware"

    strings:
        $url_1 = "uefsr.lenovomm.com"

    condition:
        $url_1
}

rule unknown_1_amtrckr
{
    meta:
        family = "unknown"
        description = "Detects hardcoded malicious URLs related to unknown malware family"

    strings:
        $url_1 = "222.76.213.20"
        $url_2 = "103.38.42.236"
        $url_3 = "103.243.181.41"
        $url_4 = "123.1.157.4"

    condition:
        any of ($url_*)
}

rule jagonca_amtrckr
{
    meta:
        family = "jagonca"
        description = "Detects hardcoded malicious URLs related to jagonca malware"

    strings:
        $url_1 = "abra-k0dabra.com"
        $url_2 = "heibe-titten.com"

    condition:
        any of ($url_*)
}

rule thoughtcrime_amtrckr
{
    meta:
        family = "thoughtcrime"
        description = "Detects hardcoded malicious URLs related to thoughtcrime malware"

    strings:
        $url_1 = "losbalonazos.com"
        $url_2 = "www.oguhtell.ch"
        $url_3 = "szaivert-numis.at"
        $url_4 = "edda-mally.at"
        $url_5 = "clubk-ginza.net"

    condition:
        any of ($url_*)
}

rule slocker_amtrckr
{
    meta:
        family = "slocker"
        description = "Detects hardcoded malicious URLs related to slocker malware"

    strings:
        $url_1 = "aerofigg.org"

    condition:
        $url_1
}

rule infostealer_amtrckr
{
    meta:
        family = "infostealer"
        description = "Detects hardcoded malicious URLs related to infostealer malware"

    strings:
        $url_1 = "koko02.ru"

    condition:
        $url_1
}

rule pornlocker_amtrckr
{
    meta:
        family = "pornlocker"
        description = "Detects hardcoded malicious URLs related to pornlocker malware"

    strings:
        $url_1 = "playmarketcheck.com"
        $url_2 = "pornigy.biz"

    condition:
        any of ($url_*)
}

rule droidian_amtrckr
{
    meta:
        family = "droidian"
        description = "Detects hardcoded malicious URLs related to droidian malware"

    strings:
        $url_1 = "z0.tkurd.net"

    condition:
        $url_1
}

rule androrat_amtrckr
{
    meta:
        family = "androrat"
        description = "Detects hardcoded malicious URLs related to androrat malware"

    strings:
        $url_1 = "toyman6699.no-ip.info"
        $url_2 = "aerror.no-ip.biz"
        $url_3 = "androrat.servegame.com"
        $url_4 = "197.35.22.37"
        $url_5 = "recycled.no-ip.org"
        $url_6 = "androjan.ddns.net"

    condition:
        any of ($url_*)
}

rule sandrorat_amtrckr
{
    meta:
        family = "sandrorat"
        description = "Detects hardcoded malicious URLs related to sandrorat malware"

    strings:
        $url_1 = "tak.no-ip.info"
        $url_2 = "maskaralama.ddns.net"
        $url_3 = "toyman6699.no-ip.info"
        $url_4 = "dantehack.zapto.org"
        $url_5 = "droidjack1.sytes.net"

    condition:
        any of ($url_*)
}

rule ibanking_amtrckr
{
    meta:
        family = "ibanking"
        description = "Detects hardcoded malicious URLs related to ibanking malware"

    strings:
        $url_1 = "www.irmihan.ir"
        $url_2 = "emberaer.com"

    condition:
        any of ($url_*)
}
