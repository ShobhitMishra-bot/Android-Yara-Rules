
rule TrojanSpy_AndroidOS_SmsTheif_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsTheif.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6b 68 69 6e 73 2e 6a 74 65 78 70 72 65 73 73 } //1 com.khins.jtexpress
		$a_03_1 = {61 70 69 2e 78 6a 61 6b 75 76 2e 74 6b 2f [0-20] 2f 69 6e 73 74 61 6c 6c 65 64 2e 70 68 70 3f 64 65 76 3d } //1
		$a_03_2 = {61 70 69 2e 78 6a 61 6b 75 76 2e 74 6b 2f [0-20] 3f 6d 73 67 3d } //1
		$a_00_3 = {52 65 63 65 69 76 65 53 6d 73 } //1 ReceiveSms
		$a_00_4 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getOriginatingAddress
		$a_00_5 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_00_6 = {61 6e 64 72 6f 69 64 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 52 45 43 45 49 56 45 5f 53 4d 53 } //1 android.permission.RECEIVE_SMS
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}