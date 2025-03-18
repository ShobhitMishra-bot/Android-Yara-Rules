
rule Trojan_AndroidOS_Zitmo_B{
	meta:
		description = "Trojan:AndroidOS/Zitmo.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 66 72 6f 6d 3d 25 73 26 74 65 78 74 3d 25 73 } //1 &from=%s&text=%s
		$a_01_1 = {3f 74 6f 3d 25 73 26 69 3d 25 73 26 6d 3d 25 73 } //1 ?to=%s&i=%s&m=%s
		$a_01_2 = {26 66 3d 31 } //1 &f=1
		$a_01_3 = {46 69 72 73 74 52 75 6e } //1 FirstRun
		$a_01_4 = {46 69 72 65 47 65 74 52 65 71 75 65 73 74 } //1 FireGetRequest
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_AndroidOS_Zitmo_B_2{
	meta:
		description = "Trojan:AndroidOS/Zitmo.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 3d 25 73 26 69 3d 25 73 26 6d 3d 25 73 26 61 69 64 3d 25 73 26 68 3d 25 73 26 76 3d 25 73 } //1 to=%s&i=%s&m=%s&aid=%s&h=%s&v=%s
		$a_01_1 = {6b 61 76 64 61 74 61 2e 64 62 } //1 kavdata.db
		$a_01_2 = {68 3d 2d 71 2d 2d 3d 2d 2d 2d 2d 74 71 2d 2d 74 2d 71 3d 70 2d 71 3d 3a 2d 3d 3d 71 2f 71 2f 71 72 71 6f 71 75 2d 3d 74 2d 69 3d 71 6e 71 2d 67 71 3d 2d 73 71 6d 3d 2d 73 71 2e 2d 3d 63 2d 3d 71 6f 2d 6d 71 2f 3d 2d 71 7a 71 2e 2d 71 3d 70 3d 71 68 2d 70 3d } //1 h=-q--=----tq--t-q=p-q=:-==q/q/qrqoqu-=t-i=qnq-gq=-sqm=-sq.-=c-=qo-mq/=-qzq.-q=p=qh-p=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}