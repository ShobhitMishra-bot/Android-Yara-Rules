rule VikingBotnet
{
	meta:
		author = "https://twitter.com/koodous_project"
		description = "Rule to detect Viking Order Botnet."
		sample = "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"
		reference = "https://www.koodous.com/"

	strings:
		$a = "cv7obBkPVC2pvJmWSfHzXh" ascii
		$b = "http://joyappstech.biz:11111/knock/" ascii
		$c = "I HATE TESTERS onGlobalLayout" ascii
		$d = "http://144.76.70.213:7777/ecspectapatronum/" ascii

	condition:
		($a and $c) or ($b and $d)
}
