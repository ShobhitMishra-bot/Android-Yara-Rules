rule Android_Triada
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/03/04"
		description = "This rule detects Android.Triada.Malware"
		sample = "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"
		source = "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/"
		
	strings:
		$string_1 = "android/system/PopReceiver"
		$perm_kill_process = "android.permission.KILL_BACKGROUND_PROCESSES"
		$perm_alert_window = "android.permission.SYSTEM_ALERT_WINDOW"
		$perm_get_tasks = "android.permission.GET_TASKS"

	condition:
		$string_1 and
		($perm_kill_process and $perm_alert_window and $perm_get_tasks)
}
