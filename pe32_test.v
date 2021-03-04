import pe32 

fn test_pe32() {

	mut bin := pe32.load('pe32/calc.exe') or {
		panic('calc not found')
	}

	assert bin.dos.e_magic == pe32.image_dos_signature
	assert bin.dos.e_lfanew == 216
	assert bin.nt.signature == 17744
	assert bin.opt.magic == 267
	assert bin.opt.data_directory[pe32.image_directory_entry_debug].size == 56
	assert string(bin.sections[0].name) == '.text'


	bin.dos.print()
	bin.nt.print()
	bin.fh.print()
	bin.opt.print()

	for i in 0..pe32.image_numberof_directory_entries {
		bin.opt.data_directory[i].print()
	}

	for i in 0..bin.fh.number_of_sections {
		bin.sections[i].print()
	}
	
	assert 1==2

	bin.save('pe32/calc2.exe')
}

