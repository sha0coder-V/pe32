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
}