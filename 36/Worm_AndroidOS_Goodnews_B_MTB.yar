
rule Worm_AndroidOS_Goodnews_B_MTB{
	meta:
		description = "Worm:AndroidOS/Goodnews.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 63 68 6f 64 75 6b 61 6b 61 2f 69 73 70 6f 72 62 61 6e } //1 Lcom/chodukaka/isporban
		$a_00_1 = {53 74 61 72 74 41 70 70 41 64 } //1 StartAppAd
		$a_00_2 = {67 65 74 53 75 62 49 64 } //1 getSubId
		$a_00_3 = {59 6f 75 20 6e 65 65 64 20 74 6f 20 63 6c 69 63 6b 20 6f 6e 20 41 64 20 74 6f 20 43 6f 6e 74 69 6e 75 65 2e } //1 You need to click on Ad to Continue.
		$a_00_4 = {54 6f 20 73 74 61 72 74 20 54 69 6b 74 6f 6b 2c 20 66 6f 6c 6c 6f 77 20 6e 65 78 74 20 73 74 65 70 73 } //1 To start Tiktok, follow next steps
		$a_00_5 = {43 6c 69 63 6b 20 6f 6e 20 4e 65 78 74 20 42 75 74 74 6f 6e 20 74 6f 20 63 6f 6e 74 69 6e 75 65 } //1 Click on Next Button to continue
		$a_00_6 = {68 74 74 70 3a 2f 2f 74 69 6e 79 2e 63 63 2f 54 69 6b 74 6f 6b 2d 50 72 6f } //1 http://tiny.cc/Tiktok-Pro
		$a_00_7 = {53 68 61 72 65 20 74 68 69 73 20 41 50 50 20 6f 6e 20 57 68 61 74 73 61 70 70 20 67 72 6f 75 70 73 20 31 30 20 54 69 6d 65 73 2e 5c 6e 74 6f 20 53 74 61 72 74 20 54 69 6b 74 6f 6b 2e } //1 Share this APP on Whatsapp groups 10 Times.\nto Start Tiktok.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}