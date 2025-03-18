rule Banker_Acecard
{
    meta:
        author = "https://twitter.com/SadFud75"
        more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
        samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252"

    strings:
        $str_1 = "Cardholder name"
        $str_2 = "instagram.php"
        $pkg_1 = "starter.fl"
        $pkg_2 = "cosmetiq.fl"
        $svc_1 = "CosmetiqFlServicesCallHeadlessSmsSendService"

    condition:
        any of ($str_*) or ($pkg_1 or $pkg_2 or $svc_1)
}
