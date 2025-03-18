
rule Trojan_AndroidOS_Hiddad_A{
	meta:
		description = "Trojan:AndroidOS/Hiddad.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 52 65 73 74 61 72 74 56 69 65 77 41 64 73 53 65 72 76 69 63 65 52 65 63 65 69 76 65 72 3b } //1 /RestartViewAdsServiceReceiver;
		$a_00_1 = {2f 47 65 74 41 64 6d 53 65 72 76 69 63 65 3b } //1 /GetAdmService;
		$a_00_2 = {56 69 65 77 41 64 73 41 63 74 69 76 69 74 79 } //1 ViewAdsActivity
		$a_00_3 = {53 74 6f 70 56 69 65 77 41 64 73 53 65 72 76 69 63 65 } //1 StopViewAdsService
		$a_00_4 = {4c 33 42 79 5a 57 4e 6c 63 48 51 76 50 32 6b 39 } //1 L3ByZWNlcHQvP2k9
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}