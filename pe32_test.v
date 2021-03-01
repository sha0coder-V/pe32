import pe32 

fn test_pe32() {

	bin := pe32.load('pe32/calc.exe') or {
		panic('calc not found')
	}

	assert bin.image_dos_header.e_magic == pe32.IMAGE_DOS_SIGNATURE
	assert bin.image_dos_header.e_lfanew == 216

}