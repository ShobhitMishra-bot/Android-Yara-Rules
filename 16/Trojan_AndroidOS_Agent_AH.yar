
rule Trojan_AndroidOS_Agent_AH{
	meta:
		description = "Trojan:AndroidOS/Agent.AH,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 63 6b 4d 65 4e 6f 77 } //1 lockMeNow
		$a_01_1 = {43 41 4c 4c 5f 4c 4f 47 5f } //1 CALL_LOG_
		$a_01_2 = {49 6e 73 74 61 6c 6c 69 6e 67 } //1 Installing
		$a_01_3 = {48 49 44 45 20 49 43 4f 4e 20 4e 4f 57 } //1 HIDE ICON NOW
		$a_01_4 = {42 6f 74 69 6d 4c 61 75 6e 63 68 65 72 41 6c 69 61 73 } //1 BotimLauncherAlias
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}