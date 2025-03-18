
rule TrojanSpy_AndroidOS_GossRat_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GossRat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {67 6f 73 73 69 70 65 72 2e 70 68 70 } //5 gossiper.php
		$a_00_1 = {2f 72 61 74 2f } //1 /rat/
		$a_00_2 = {69 72 2f 61 70 70 2f } //1 ir/app/
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}