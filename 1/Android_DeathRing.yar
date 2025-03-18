rule Android_DeathRing
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "Detects DeathRing Trojan pre-installed on smartphones"
		source = "https://blog.lookout.com/blog/2014/12/04/deathring/"
		samples = "Example hash: e9d5d58ea2c5de8fd1bd15e18e8270cb"

	strings:
		// Static patterns commonly found in DeathRing samples
		$str_1 = "MainOsService"                     // Service name
		$str_2 = "ApkUninstallReceiver"              // Receiver name
		$str_3 = "/system/app/DeathRing"             // Path to malicious APK
		$str_4 = "com.example.deathring"             // Package name
		$str_5 = "android.permission.RECEIVE_SMS"    // Permission used by DeathRing

	condition:
		all of ($str_*)
}

