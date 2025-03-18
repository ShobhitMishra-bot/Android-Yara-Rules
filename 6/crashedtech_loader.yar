rule crashedtech_loader {
    meta:
        author = "@luc4m"
        date = "2023-03-26"
        hash_md5 = "53f9c2f2f1a755fc04130fd5e9fcaff4"
        link = "https://medium.com/@lcam/updates-from-the-maas-new-threats-delivered-through-nullmixer-d45defc260d1"
        tlp = "WHITE"

	yarahub_uuid = "6bcec71c-e550-4ff6-b877-3953ef892179"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        yarahub_reference_md5="53f9c2f2f1a755fc04130fd5e9fcaff4" 

    strings:
        $trait_0 = {02 14 7d ?? ?? ?? ?? 02 28 ?? ?? ?? ?? ?? ?? 02 28 ?? ?? ?? ?? ?? 2a}
        $trait_1 = {?? 02 7b ?? ?? ?? ?? 6f ?? ?? ?? ?? ?? ?? 02 03 28 ?? ?? ?? ?? ?? 2a}
        $trait_2 = {?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 0a 2b ??}
        $trait_4 = {?? 73 ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 2b ??}
        $trait_5 = {06 6f ?? ?? ?? ?? ?? dc ?? de ?? 26 ?? ?? de ?? 2a}
        $trait_6 = {11 ?? 6f ?? ?? ?? ?? ?? dc 09 6f ?? ?? ?? ?? 16 fe 01 13 ?? 11 ?? 2c ??}
        $trait_7 = {06 6f ?? ?? ?? ?? ?? dc ?? de ?? 26 ?? ?? de ?? 2a}
        $trait_8 = {?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 0b 2b ??}

        $str_0 = "username" wide
        $str_1 = "windows" wide
        $str_2 = "client" wide
        $str_3 = "ip" wide
        $str_4 = "api.ipify.org" wide 
        $str_5 = "(.*)<>(.*)" wide

    condition:
        5 of ($str_* ) and 3 of ($trait_*)
}

