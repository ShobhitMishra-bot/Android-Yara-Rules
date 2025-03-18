rule joker_hunting {
	strings:
		$a1 = "libjiagu.so" nocase
                $a2 = "AIzaSyCbYzFgcrdhzOPAg8ft6C4Dv2c2Wh5Ybxs"
                $a3 = "1061725094952-bh559aphsk9ijifof7vei298hq8qt6rm.apps.googleusercontent.com"
                 
	condition:
		all of them
}
