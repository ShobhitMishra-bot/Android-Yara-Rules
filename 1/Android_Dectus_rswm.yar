rule Android_Dogspectus_Ransomware
{
	meta:
		author = "https://twitter.com/5h1vang"
		description = "Yara rule for detecting Dogspectus ransomware APK"
		sample = "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	strings:
		// Strings commonly associated with Dogspectus ransomware
		$str_1 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_2 = "Tap ACTIVATE to continue with software update"
		$str_3 = "System update"
		$str_4 = "net.prospectus"
		$str_5 = "PanickedActivity"
		$str_cert = "180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E"

	condition:
		// Trigger rule if these strings are found
		all of ($str_1, $str_2) or
		any of ($str_3, $str_4, $str_5, $str_cert)
}
