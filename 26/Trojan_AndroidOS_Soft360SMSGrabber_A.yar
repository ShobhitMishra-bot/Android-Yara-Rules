
rule Trojan_AndroidOS_Soft360SMSGrabber_A{
	meta:
		description = "Trojan:AndroidOS/Soft360SMSGrabber.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 42 61 6e 6b 44 42 5f 32 33 2e 64 62 00 } //3 䉩湡䑫彂㌲搮b
		$a_00_1 = {4c 63 6f 6d 2f 73 6f 66 74 33 36 30 2f 69 53 65 72 76 69 63 65 00 } //1 捌浯猯景㍴〶椯敓癲捩e
		$a_00_2 = {2f 41 6e 64 72 6f 69 64 2f 6f 62 62 2f 00 } //1 䄯摮潲摩漯扢/
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}