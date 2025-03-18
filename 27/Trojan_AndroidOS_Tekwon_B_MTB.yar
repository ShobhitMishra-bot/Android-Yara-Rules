
rule Trojan_AndroidOS_Tekwon_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Tekwon.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 79 73 42 72 6f 77 73 65 72 4f 62 73 65 72 76 65 72 } //1 SysBrowserObserver
		$a_00_1 = {41 70 70 46 61 6b 65 41 63 74 69 76 69 74 79 } //1 AppFakeActivity
		$a_00_2 = {64 6f 55 70 64 61 74 65 56 69 73 69 74 65 64 48 69 73 74 6f 72 79 } //1 doUpdateVisitedHistory
		$a_00_3 = {4d 6f 6e 69 74 6f 72 50 68 6f 6e 65 43 61 6c 6c } //1 MonitorPhoneCall
		$a_00_4 = {44 65 6c 65 74 65 43 61 6c 6c 43 6f 6e 74 65 6e 74 } //1 DeleteCallContent
		$a_00_5 = {53 4d 53 53 61 70 6d 4f 62 73 65 72 76 65 72 } //1 SMSSapmObserver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}