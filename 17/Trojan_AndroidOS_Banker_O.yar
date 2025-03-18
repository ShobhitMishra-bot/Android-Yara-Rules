
rule Trojan_AndroidOS_Banker_O{
	meta:
		description = "Trojan:AndroidOS/Banker.O,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6b 65 41 31 31 79 53 65 72 76 69 63 65 49 6e 66 6f } //2 makeA11yServiceInfo
		$a_01_1 = {64 6f 52 65 63 76 55 73 65 72 } //2 doRecvUser
		$a_01_2 = {64 6f 53 75 63 6b 42 61 6c 6c 73 54 68 72 65 61 64 } //2 doSuckBallsThread
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}