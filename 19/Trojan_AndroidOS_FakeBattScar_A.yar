
rule Trojan_AndroidOS_FakeBattScar_A{
	meta:
		description = "Trojan:AndroidOS/FakeBattScar.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 61 74 74 65 72 79 20 44 6f 63 74 6f 72 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 6f 20 64 69 73 61 62 6c 65 20 79 6f 75 72 20 57 69 46 69 2c 20 42 6c 75 65 74 6f 6f 74 68 2c 20 61 6e 64 20 44 69 6d 20 79 6f 75 72 20 73 63 72 65 65 6e 2e } //1 Battery Doctor would like to disable your WiFi, Bluetooth, and Dim your screen.
		$a_01_1 = {50 75 73 68 41 64 73 2e 6a 61 76 61 } //1 PushAds.java
		$a_01_2 = {50 75 73 68 69 6e 67 20 43 43 20 41 64 73 2e 2e 2e 2e 2e } //1 Pushing CC Ads.....
		$a_01_3 = {53 44 4b 20 69 73 20 64 69 73 61 62 6c 65 64 2c 20 70 6c 65 61 73 65 20 65 6e 61 62 6c 65 20 74 6f 20 72 65 63 65 69 76 65 20 41 64 73 20 21 } //1 SDK is disabled, please enable to receive Ads !
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}