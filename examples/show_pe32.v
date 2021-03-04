import pe32 
import os

fn main() {

	bin := pe32.load(os.args[1]) or {
		panic('file not found')
	}

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

}
