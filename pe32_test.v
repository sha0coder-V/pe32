import pe32 

fn test_pe32() {

	bin := pe32.load('pe32/calc.exe') or {
		panic('calc not found')
	}

	assert bin.dos.e_magic == pe32.image_dos_signature
	assert bin.dos.e_lfanew == 216
	assert bin.nt.signature == 17744


	bin.dos.print()
	bin.nt.print()
	bin.fh.print()
	bin.opt.print()

	
	assert 1==2
}

