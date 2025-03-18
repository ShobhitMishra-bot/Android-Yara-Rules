
rule Trojan_AndroidOS_Saiva_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Saiva.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 6c 61 63 6b 4e 75 6d 62 65 72 73 } //1 blackNumbers
		$a_01_1 = {73 65 6e 64 74 69 6d 65 72 } //1 sendtimer
		$a_01_2 = {2f 64 6f 77 6e 6c 6f 61 64 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 /downloader/SmsReceiver
		$a_01_3 = {64 65 6c 69 76 65 72 65 64 50 49 } //1 deliveredPI
		$a_01_4 = {41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //1 AppDownloaderActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}