rule Android_Backdoor
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		reference = "https://github.com/dana-at-cp/backdoor-apk"

	strings:
		// Static patterns commonly found in backdoor-apk samples
		$str_1 = "cnlybnq.qrk" // Obfuscated/encrypted string "payload.dex"
		$str_2 = "payload.dex" // Reference to malicious payload
		$str_3 = "/system/bin/.AppBoot" // Suspicious file path
		$str_4 = "app_process32_original" // Original app process path
		$str_5 = "com.metasploit.stage" // Metasploit payload package name

	condition:
		any of ($str_*)
}
