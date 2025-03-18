rule packer_libjiagu {
	strings:
		$a1 = "libjiagu.so" nocase
	condition:
		all of them
}