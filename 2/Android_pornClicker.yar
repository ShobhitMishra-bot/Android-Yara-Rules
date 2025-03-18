rule Trojan_PornClicker
{
    meta:
        description = "Detects Android PornClicker Trojan connecting to remote hosts and fetching JavaScript and URLs leading to pornographic content."
        sample = "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca"
        reference = "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/"
        author = "Koodous Project"

    strings:
        $a = "SELEN3333"
        $b = "SELEN33"
        $c = "SELEN333"
        $api = "http://mayis24.4tubetv.xyz/dmr/ya" ascii wide
        $url = "mayis24.4tubetv.xyz" ascii wide

    condition:
        ($a and $b and $c and $api) or $url
}
