rule Android_Overlayer
{
	meta:
		description = "Detects banker trojan with overlaying functionality"
		source =  "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
		author = "https://twitter.com/5h1vang"

	strings:
		// Strings commonly found in overlaying banker Trojans
		$str_1 = "tel:" ascii
		$str_2 = "lockNow" nocase
		$str_3 = "android.app.action.ADD_DEVICE_ADMIN" ascii
		$str_4 = "Cmd_conf" nocase
		$str_5 = "Sms_conf" nocase
		$str_6 = "filter2" ascii
		$cert_sha1 = "6994ED892E7F0019BCA74B5847C6D5113391D127" ascii
		$perm_internet = "android.permission.INTERNET" ascii
		$perm_read_sms = "android.permission.READ_SMS" ascii
		$perm_read_phone_state = "android.permission.READ_PHONE_STATE" ascii

	condition:
		// Condition matches either by certificate SHA1 or permissions and strings
		$cert_sha1 or
		(
			$perm_internet and
			$perm_read_sms and
			$perm_read_phone_state and
			all of ($str_*)
		)
}
