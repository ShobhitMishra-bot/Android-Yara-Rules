
rule Trojan_AndroidOS_Fakeapp_F{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.F,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 56 69 63 74 69 6d 20 52 65 63 69 65 76 65 64 20 53 4d 53 20 66 72 6f 6d } //1 Your Victim Recieved SMS from
		$a_01_1 = {61 63 63 65 73 73 24 67 65 74 53 6d 73 4d 61 6e 61 67 65 72 24 63 70 } //1 access$getSmsManager$cp
		$a_01_2 = {4c 63 79 62 65 72 2f 70 74 68 6b 2f 73 6d 73 66 6f 72 77 61 72 64 65 72 2f 73 65 72 76 69 63 65 73 2f 53 6d 73 4c 69 73 74 65 6e 65 72 } //1 Lcyber/pthk/smsforwarder/services/SmsListener
		$a_01_3 = {70 64 75 4f 62 6a 65 63 74 73 } //1 pduObjects
		$a_01_4 = {68 61 63 6b 5f 62 61 61 63 6b } //1 hack_baack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}