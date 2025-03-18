
rule TrojanDropper_AndroidOS_FakeApp_QA_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/FakeApp.QA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {44 8b 97 04 01 00 00 45 8d 4a 01 41 8d 82 00 01 00 00 45 85 c9 41 0f 49 c1 25 00 ff ff ff f7 d8 44 01 d0 83 c0 01 44 8b 8f 08 01 00 00 89 87 04 01 00 00 4c 63 d0 46 0f b6 1c 17 43 8d 04 19 05 ff 00 00 00 44 89 c9 44 01 d9 0f 49 c1 25 00 ff ff ff 29 c1 89 8f 08 01 00 00 48 63 c1 46 0f b6 0c 17 0f b6 0c 07 42 88 0c 17 44 88 0c 07 48 63 87 04 01 00 00 0f b6 04 07 48 63 8f 08 01 00 00 0f b6 0c 0f 01 c1 0f b6 c1 0f b6 0c 1e 32 0c 07 88 0c 1a 48 83 c3 01 49 39 d8 0f 85 60 ff ff ff } //10
	condition:
		((#a_00_0  & 1)*10) >=10
 
}