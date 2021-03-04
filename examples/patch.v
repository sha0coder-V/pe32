import sha0coder_v.pe32
import os

fn main() {

	mut bin := pe32.load(os.args[1]) or {
		panic('file not found')
	}

	bin.sections[0].name[0] = `T`

	bin.save(os.args[1])
}

