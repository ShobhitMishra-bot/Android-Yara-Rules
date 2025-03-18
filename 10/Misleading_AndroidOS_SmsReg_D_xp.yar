
rule Misleading_AndroidOS_SmsReg_D_xp{
	meta:
		description = "Misleading:AndroidOS/SmsReg.D!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 75 6d 70 61 79 2f 68 75 61 66 75 62 61 6f 2f 64 6f 77 6e 6c 6f 61 64 } //1 /umpay/huafubao/download
		$a_00_1 = {6d 6e 73 70 2e 6a 75 7a 69 78 69 61 6e 67 73 68 75 69 2e 63 6f 6d 2f 3f } //1 mnsp.juzixiangshui.com/?
		$a_00_2 = {73 6d 73 32 2e 75 70 61 79 33 36 30 2e 63 6f 6d 2f 67 65 74 4d 6f 62 69 6c 65 2e 70 68 70 } //1 sms2.upay360.com/getMobile.php
		$a_02_3 = {78 71 32 2e 31 32 37 37 35 32 37 2e 63 6f 6d 2f 30 39 30 31 3f ?? ?? ?? ?? 3a 2f 2f 31 31 31 2e 31 33 2e 34 37 2e 37 36 3a 38 31 2f 6f 70 65 6e 5f 67 61 74 65 2f 77 65 62 5f 67 61 6d 65 5f 66 65 65 2e 70 68 70 } //1
		$a_00_4 = {63 6f 6d 2e 75 70 61 79 2e 70 61 79 2e 75 70 61 79 5f 73 6d 73 2e 73 65 72 76 69 63 65 2e 41 6c 61 72 6d 53 65 72 76 69 63 65 } //1 com.upay.pay.upay_sms.service.AlarmService
		$a_00_5 = {53 6d 73 49 6e 69 74 4f 62 73 65 72 76 65 72 } //1 SmsInitObserver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}