
rule Trojan_AndroidOS_Falcon_A{
	meta:
		description = "Trojan:AndroidOS/Falcon.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 41 63 74 69 76 69 74 79 47 65 74 53 4d 53 46 61 41 70 70 3b } //1 /ActivityGetSMSFaApp;
		$a_01_1 = {2f 41 63 74 69 76 69 74 79 53 70 61 6d 53 6d 73 46 61 41 70 70 3b } //1 /ActivitySpamSmsFaApp;
		$a_01_2 = {2f 41 63 74 69 76 69 74 79 53 74 61 72 74 55 53 53 44 46 61 41 70 70 3b } //1 /ActivityStartUSSDFaApp;
		$a_01_3 = {2f 41 63 74 69 76 69 74 79 46 61 6b 65 41 70 70 53 74 61 72 74 46 61 41 70 70 3b } //1 /ActivityFakeAppStartFaApp;
		$a_01_4 = {2f 53 65 72 76 69 63 65 41 63 63 65 73 73 69 62 69 6c 69 74 79 46 61 41 70 70 3b } //1 /ServiceAccessibilityFaApp;
		$a_01_5 = {2f 41 63 74 69 76 69 74 79 53 74 61 72 74 49 6e 6a 65 63 74 69 6f 6e 46 61 41 70 70 3b } //1 /ActivityStartInjectionFaApp;
		$a_01_6 = {2f 53 65 72 76 69 63 65 49 6e 74 65 72 61 63 74 69 6f 6e 53 65 72 76 65 72 46 61 41 70 70 3b } //1 /ServiceInteractionServerFaApp;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}