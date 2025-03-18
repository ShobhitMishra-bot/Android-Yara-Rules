rule android_mazarBot_z : android
{
	meta:
		author = "https://twitter.com/5h1vang"
		reference_1 = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
		description = "Yara detection for MazarBOT"
		sample = "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8"

	strings:
		$str_1 = "android.app.extra.ADD_EXPLANATION"
		$str_2 = "device_policy"
		$str_3 = "content://sms/"
		$str_4 = "#admin_start"
		$str_5 = "kill call"
		$str_6 = "unstop all numbers"
		$cert_sha1 = "50FD99C06C2EE360296DCDA9896AD93CAE32266B"

	condition:
		4 of ($str_*) or $cert_sha1
}
