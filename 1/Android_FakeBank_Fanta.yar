rule Android_FakeBank_Fanta
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "Detects Android FakeBank_Fanta malware"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"

	strings:
		// Strings related to the suspicious services and receivers
		$s1 = "SocketService"
		$s2 = "MyAdmin"
		$s3 = "Receiver"
		$s4 = "NetworkChangeReceiver"

		// Additional strings (if known) can be added here
		// Example:
		// $s5 = "phishing_bank_example"

	condition:
		// Trigger if all key strings are present in the file
		all of ($s1, $s2, $s3, $s4)
}
