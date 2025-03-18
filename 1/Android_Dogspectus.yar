rule Android_Dogspectus
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "20-July-2016"
		description = "Detects Dogspectus ransomware APK"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	strings:
		// Strings commonly associated with Dogspectus ransomware
		$str_1 = "PanickedActivity"
		$str_2 = "android.permission.RECEIVE_BOOT_COMPLETED"
		$str_3 = "android.permission.INTERNET"
		$str_4 = "android.permission.WAKE_LOCK"
		$str_5 = "Tap ACTIVATE to continue with software update"
		$str_6 = "android.app.action.ADD_DEVICE_ADMIN"

	condition:
		// Trigger rule if evidence of Dogspectus is found
		all of ($str_1, $str_2, $str_3, $str_4) or $str_5 or $str_6
}
