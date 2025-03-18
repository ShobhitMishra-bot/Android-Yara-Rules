
rule TrojanSpy_AndroidOS_Zanubis_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Zanubis.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 75 74 61 73 5f 74 61 72 67 65 74 73 } //1 rutas_targets
		$a_00_1 = {43 6f 6e 53 65 72 76 65 72 43 6f 6e 65 78 69 6f 6e 65 73 } //1 ConServerConexiones
		$a_00_2 = {44 65 6c 53 6d 73 } //1 DelSms
		$a_00_3 = {6f 6e 53 65 72 76 69 63 65 43 6f 6e 6e 65 63 74 65 64 } //1 onServiceConnected
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}