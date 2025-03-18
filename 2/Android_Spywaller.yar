rule android_spywaller
{
	meta:
		description = "Rule for detection of Android Spywaller samples"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		source = "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking"

	strings:
		$str_1 = "droid.png"
		$str_2 = "getSrvAddr"
		$str_3 = "getSrvPort"
		$str_4 = "android.intent.action.START_GOOGLE_SERVICE"
		$cert_sha1 = "165F84B05BD33DA1BA0A8E027CEF6026B7005978"
		$permission_internet = "android.permission.INTERNET"
		$permission_read_phone_state = "android.permission.READ_PHONE_STATE"

	condition:
		$cert_sha1 or
		($permission_internet and $permission_read_phone_state and all of ($str_*))
}
