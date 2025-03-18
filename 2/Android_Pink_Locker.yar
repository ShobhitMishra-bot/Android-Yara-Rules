rule Android_PinkLocker
{
	meta:
		description = "Detects Android Locker app named Pink Club"
		author = "@5h1vang"
		ref1 = "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/"
		ref2 = "https://analyst.koodous.com/rulesets/1186"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
		
	strings:
		// Detect key strings in malicious APK
		$str_1 = "arnrsiec sisani" ascii
		$str_2 = "rhguecisoijng ts" ascii
		$str_3 = "assets/data.db" ascii
		$str_4 = "res/xml/device_admin_sample.xmlPK" ascii
		$url = "lineout.pw" ascii
		$cert_sha1 = "D88B53449F6CAC93E65CA5E224A5EAD3E990921E" ascii
		$perm_internet = "android.permission.INTERNET" ascii
		$perm_disable_keyguard = "android.permission.DISABLE_KEYGUARD" ascii

	condition:
		// Check for certificate, permissions, and key strings
		$url or
		$cert_sha1 or
		($perm_internet and $perm_disable_keyguard and all of ($str_*))
}
