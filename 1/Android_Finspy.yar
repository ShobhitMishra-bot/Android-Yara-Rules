rule FinSpy_Android
{
	meta:
		description = "Detect Gamma/FinFisher FinSpy for Android (GovWare)"
		date = "2020/01/07"
		author = "Thorsten Schröder - ths @ ccc.de"
		reference1 = "https://github.com/devio/FinSpy-Tools"
		reference2 = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference3 = "https://www.ccc.de/de/updates/2019/finspy"
		sample = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"

	strings:
		// Central Directory Header Magic Number and common FinSpy obfuscation patterns
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/
		$s1 = "Gamma Group"           // Company associated with FinSpy
		$s2 = "FinSpy"                // Common name
		$s3 = "com.gamma.android"     // Known package name
		$s4 = "Agent.cmd"             // Suspicious component

	condition:
		($re and (#re > 50)) or any of ($s1, $s2, $s3, $s4)
}
