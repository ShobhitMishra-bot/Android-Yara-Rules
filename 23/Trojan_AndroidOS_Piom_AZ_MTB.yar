
rule Trojan_AndroidOS_Piom_AZ_MTB{
	meta:
		description = "Trojan:AndroidOS/Piom.AZ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {69 6e 73 74 61 6e 74 2d 65 2d 61 70 70 6c 79 2d 63 61 6d 70 61 69 67 6e 2d 70 61 67 65 2d 69 64 66 2d 63 61 6d 70 61 69 67 6e 2d 66 69 78 2e 78 79 7a 2f 61 70 69 2f 6d 61 70 4e 65 74 42 61 6e 6b } //1 instant-e-apply-campaign-page-idf-campaign-fix.xyz/api/mapNetBank
		$a_00_1 = {63 61 6d 70 61 69 67 6e 2d 66 69 78 2e 78 79 7a 2f 61 70 69 2f 6d 61 70 4d 73 67 } //1 campaign-fix.xyz/api/mapMsg
		$a_00_2 = {63 61 6d 70 61 69 67 6e 2d 66 69 78 2e 78 79 7a 2f 61 70 69 2f 6d 61 70 43 75 72 72 4c 69 6d 69 74 } //1 campaign-fix.xyz/api/mapCurrLimit
		$a_00_3 = {63 61 6d 70 61 69 67 6e 2d 66 69 78 2e 78 79 7a 2f 61 70 69 2f 6d 61 70 4f 74 70 } //1 campaign-fix.xyz/api/mapOtp
		$a_00_4 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getOriginatingAddress
		$a_00_5 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}