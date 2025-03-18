
rule Trojan_AndroidOS_Kmin_B{
	meta:
		description = "Trojan:AndroidOS/Kmin.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 2e 61 73 70 78 3f 61 63 3d 67 65 74 72 65 63 65 69 76 65 72 } //1 Service.aspx?ac=getreceiver
		$a_01_1 = {25 73 65 72 76 69 63 65 2e 61 73 70 78 3f 61 63 3d 67 65 74 73 6d 73 61 6e 73 77 65 72 26 63 6f 6e 74 65 6e 74 3d } //1 %service.aspx?ac=getsmsanswer&content=
		$a_03_2 = {73 75 2e 35 6b 33 67 2e 63 6f 6d 2f 70 6f 72 74 61 6c 2f 6d 2f 63 35 2f ?? 2e 61 73 68 78 } //1
		$a_01_3 = {63 6f 6d 2e 6a 78 2e 61 64 2e 41 44 53 65 72 76 69 63 65 2e 52 75 6e } //1 com.jx.ad.ADService.Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}