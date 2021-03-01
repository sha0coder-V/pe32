import pe32 

fn test_pe32() {

	bin := pe32.load('calc.exe')

	println(bin.image_dos_header.e_magic)

}