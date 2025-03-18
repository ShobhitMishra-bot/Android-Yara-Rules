rule HackingTeam_Android : Android_Implant
{
    meta:
        description = "Detects HackingTeam Android implant, known to target versions v4 - v7"
        author = "Tim 'diff' Strazzere <strazz@gmail.com>"
        reference = "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
        date = "2016-11-14"
        version = "1.0"

    strings:
        // Detects the decryption routine used by HackingTeam implants
        $decryptor = { 
            12 01                     // const/4 v1, 0x0
            D8 00 ?? ??               // add-int/lit8 ??, ??, ??
            6E 10 ?? ?? ?? 00         // invoke-virtual {??} -> String.toCharArray()
            0C 04                     // move-result-object v4
            21 45                     // array-length v5, v4
            01 02                     // move v2, v0
            01 10                     // move v0, v1
            32 50 11 00               // if-eq v0, v5, 0xb
            49 03 04 00               // aget-char v3, v4, v0
            DD 06 02 5F               // and-int/lit8 v6, v2, 0x5f
            B7 36                     // xor-int/2addr v6, v3
            D8 03 02 ??               // and-int/lit8 v3, v2, ??
            D8 02 00 01               // and-int/lit8 v2, v0, 0x1
            8E 66                     // int-to-char v6, v6
            50 06 04 00               // aput-char v6, v4, v0
            01 20                     // move v0, v2
            01 32                     // move v2, v3
            28 F0                     // goto 0xa
            71 30 ?? ?? 14 05         // invoke-static {v4, v1, v5}, ?? -> String.valueOf()
            0C 00                     // move-result-object v0
            6E 10 ?? ?? 00 00         // invoke-virtual {v0} ?? -> String.intern()
            0C 00                     // move-result-object v0
            11 00                     // return-object v0
        }

        // Encoded reference to Android global settings
        $settings = {
            00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E
            64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74
            74 69 6E 67 73 3B 00
        }

        // Encoded reference to `getSmsInputNumbers`
        $getSmsInputNumbers = {
            00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D
            62 65 72 73 00
        }

    condition:
        $decryptor and ($settings and $getSmsInputNumbers)
}
