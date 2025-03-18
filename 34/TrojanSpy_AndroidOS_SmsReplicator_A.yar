
rule TrojanSpy_AndroidOS_SmsReplicator_A{
	meta:
		description = "TrojanSpy:AndroidOS/SmsReplicator.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 53 4d 53 52 65 70 6c 69 63 61 74 6f 72 53 65 63 72 65 74 3b } //1 /SMSReplicatorSecret;
		$a_01_1 = {72 65 64 34 6c 69 66 65 } //1 red4life
		$a_01_2 = {44 42 66 6f 72 77 61 72 64 69 6e 67 4e 6f } //1 DBforwardingNo
		$a_01_3 = {73 68 61 64 79 2e 64 62 } //1 shady.db
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}