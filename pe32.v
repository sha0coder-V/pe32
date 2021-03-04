module pe32

import os
import encoding.binary

/*
 https://blog.kowalczyk.info/articles/pefileformat.html
 https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
 https://github.com/dotnet/llilc/blob/master/include/clr/ntimage.h
*/


pub const (
	image_dos_signature = 0x5A4D     // MZ 
	image_os2_signature = 0x454E     // NE
	image_os2_signature_le = 0x454C  // LE
	iamge_nt_signature = 0x00004550  // PE00
	image_sizeof_file_header = 20
	image_numberof_directory_entries = 16

	section_header_sz = 40

	image_directory_entry_export = 0
	image_directory_entry_import = 1
	image_directory_entry_resource = 2
	iamge_directory_entry_exception = 3
	image_directory_entry_security = 4
	image_directory_entry_basereloc = 5
	image_directory_entry_debug = 6
	image_directory_entry_copyright = 7
	image_directory_entry_globalptr = 8
	image_directory_entry_tls = 9
	image_directory_entry_load_config = 10

	image_sizeof_short_name = 8
	image_debug_type_unknown = 0
	image_debug_type_coff = 1
	image_debug_type_codeview = 2
	image_debug_type_fpo = 3
	image_debug_type_misc = 4
)

////////////// STRUCTURES ////////////// 

pub struct IMAGE_DOS_HEADER {
pub mut:
	e_magic u16		// Magic number
	e_cblp u16 		// Bytes on last page of file
	e_cp u16		// Pages in file
	e_crlc u16 		// Relocations
	e_cparhdr u16	// Size of header in paragraphs
	e_minalloc u16	// Minimum extra paragraphs needed
	e_maxalloc u16	// Maximum extra paragraphs needed
	e_ss u16		// Initial (relative) SS value
	e_sp u16		// Initial SP value
	e_csum u16		// Checksum
	e_ip u16		// Initial IP value
	e_cs u16		// Initial (relative) CS value
	e_lfarlc u16	// File address of relocation table
	e_ovno u16		// Overlay number
	e_res [4]u16	// Reserved words
	e_oemid u16		// OEM identifier (for e_oeminfo)
	e_oeminfo u16	// OEM information; e_oemid specific
	e_res2	[10]u16	// Reserved words
	e_lfanew u32	// File address of new exe header
}

pub struct IMAGE_NT_HEADERS {
pub mut:
	signature u32
	//file_header u32 // IMAGE_FILE_HEADER
	//optional_header u32 // IMAGE_OPTIONAL_HEADER
}
     
pub struct IMAGE_FILE_HEADER {
pub mut:
	machine u16 
	number_of_sections u16 
	time_date_stamp u32
	pointer_to_symbol_table u32
	number_of_symbols u32 
	size_of_optional_header u16
    characteristics u16
}

pub struct IMAGE_DATA_DIRECTORY {
pub mut:
	virtual_address u32
	size u32
}

pub struct IMAGE_OPTIONAL_HEADER {
pub mut:	
	// Standard fields.
	magic u16
	major_linker_version byte 
	minor_linker_version byte 
	size_of_code u32 
	size_of_initialized_data u32 
	size_of_uninitialized_data u32
	address_of_entry_point u32 
	base_of_code u32 
	base_of_data u32
	// NT additional fields.
	image_base u32 
	section_alignment u32 
	file_alignment u32 
	major_operating_system_version u16 
	minor_operating_system_version u16 
	major_image_version u16 
	minor_image_version u16
	major_subsystem_version u16
	minor_subsystem_version u16 
	reserved1 u32 
    size_of_image u32
	size_of_headers u32 
	checksum u32 
	subsystem u16
 	dll_characteristics u16 
	size_of_stack_reserve u32 
	size_of_stack_commit u32 
	size_of_heap_reserve u32 
	size_of_heap_commit u32
	loader_flags u32 
	number_of_rva_and_sizes u32 	
	data_directory [image_numberof_directory_entries]IMAGE_DATA_DIRECTORY
}

pub struct IMAGE_SECTION_HEADER {
pub mut:
	name [image_sizeof_short_name]byte 
	physical_address u32
	//virtual_size u32
	virtual_address u32 
	size_of_raw_data u32 
	pointer_to_raw_data u32 
	pointer_to_relocations u32 
	pointer_to_linenumbers u32 
	number_of_relocations u16 
	number_of_linenumbers u16 
	characteristics u32 
}

pub struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
pub mut:
    name u32
    offset_to_data u32
}

pub struct IMAGE_RESOURCE_DIRECTORY {
pub mut:
    characteristics u32 
    time_date_stamp u32
    major_version u16 
    minor_version u16
    number_of_named_entries u16
    number_of_id_entries u16
}

pub struct IMAGE_RESOURCE_DATA_ENTRY {
pub mut:
    offset_to_data u32
    size u32
    code_page u32
    reserved u32
}

pub struct IMAGE_RESOURCE_DIR_STRING_U {
pub mut:
    length u16
    name_string [1]byte
}

pub struct IMAGE_EXPORT_DIRECTORY {
pub mut:
    characteristics u32
    time_date_stamp u32
    major_version u16
    minor_version u16
    name u32
    base u32
    number_of_functions u32
    number_of_names u32
    address_of_functions u32
    address_of_names u32
    address_of_name_ordinals u32
}

pub struct TagImportDirectory {
pub mut:
    dw_rva_function_name_list u32
    dw_useless1 u32
    dw_useless2 u32
    dw_rva_module_name u32
    dw_rva_function_address_list u32
}

pub struct IMAGE_DEBUG_DIRECTORY {
pub mut:
    characteristics u32
    time_date_stamp u32
    major_version u16
    minor_version u16
    types u32
    size_of_data u32
    address_of_raw_data u32
    pointer_to_raw_data u32
}

pub struct IMAGE_BASE_RELOCATION {
pub mut:
    virtual_address u32
    size_of_block u32
}


////////////// LOADERS ////////////// 

fn (mut dos IMAGE_DOS_HEADER) load(bin []byte) {
	dos.e_magic = binary.little_endian_u16(bin[0..2])
	dos.e_cblp = binary.little_endian_u16(bin[2..4])
	dos.e_cp = binary.little_endian_u16(bin[4..6])
	dos.e_crlc = binary.little_endian_u16(bin[6..8])
	dos.e_cparhdr = binary.little_endian_u16(bin[8..10])
	dos.e_minalloc = binary.little_endian_u16(bin[10..12])
	dos.e_maxalloc = binary.little_endian_u16(bin[12..14])
	dos.e_ss = binary.little_endian_u16(bin[14..16])
	dos.e_sp = binary.little_endian_u16(bin[16..18])
	dos.e_csum = binary.little_endian_u16(bin[18..20])
	dos.e_ip = binary.little_endian_u16(bin[20..22])
	dos.e_cs = binary.little_endian_u16(bin[22..24])
	dos.e_lfarlc = binary.little_endian_u16(bin[24..26])
	dos.e_ovno = binary.little_endian_u16(bin[26..28])
	dos.e_res[0] = binary.little_endian_u16(bin[28..30])
	dos.e_res[1] = binary.little_endian_u16(bin[30..32])
	dos.e_res[2] = binary.little_endian_u16(bin[32..34])
	dos.e_res[3] = binary.little_endian_u16(bin[34..36])
	dos.e_oemid = binary.little_endian_u16(bin[36..38])
	dos.e_oeminfo = binary.little_endian_u16(bin[38..40])
	dos.e_res2[0] = binary.little_endian_u16(bin[40..42])
	dos.e_res2[1] = binary.little_endian_u16(bin[42..44])
	dos.e_res2[2] = binary.little_endian_u16(bin[44..46])
	dos.e_res2[3] = binary.little_endian_u16(bin[46..48])
	dos.e_res2[4] = binary.little_endian_u16(bin[48..50])
	dos.e_res2[5] = binary.little_endian_u16(bin[50..52])
	dos.e_res2[6] = binary.little_endian_u16(bin[52..54])
	dos.e_res2[7] = binary.little_endian_u16(bin[54..56])
	dos.e_res2[8] = binary.little_endian_u16(bin[56..58])
	dos.e_res2[9] = binary.little_endian_u16(bin[58..60])
	dos.e_lfanew = binary.little_endian_u32(bin[60..64])
}

fn (mut nt IMAGE_NT_HEADERS) load(bin []byte) {
	nt.signature = binary.little_endian_u32(bin[0..4])
}

fn (mut fh IMAGE_FILE_HEADER) load(bin []byte) {
	fh.machine = binary.little_endian_u16(bin[0..2])
	fh.number_of_sections = binary.little_endian_u16(bin[2..4])
	fh.time_date_stamp = binary.little_endian_u32(bin[4..8])
	fh.pointer_to_symbol_table = binary.little_endian_u16(bin[8..12])
	fh.number_of_symbols = binary.little_endian_u32(bin[12..16])
	fh.size_of_optional_header = binary.little_endian_u16(bin[16..18])
	fh.characteristics = binary.little_endian_u16(bin[18..20])
}

fn (mut op IMAGE_OPTIONAL_HEADER) load(bin []byte) {
	op.magic = binary.little_endian_u16(bin[0..2])
	op.major_linker_version = bin[2]
	op.minor_linker_version = bin[3]
	op.size_of_code = binary.little_endian_u32(bin[4..8])
	op.size_of_initialized_data = binary.little_endian_u32(bin[8..12]) 
	op.size_of_uninitialized_data = binary.little_endian_u32(bin[12..16])
	op.address_of_entry_point = binary.little_endian_u32(bin[16..20]) 
	op.base_of_code = binary.little_endian_u32(bin[20..24]) 
	op.base_of_data = binary.little_endian_u32(bin[24..28])
	// NT additional fields.
	op.image_base = binary.little_endian_u32(bin[28..32]) 
	op.section_alignment = binary.little_endian_u32(bin[32..36]) 
	op.file_alignment = binary.little_endian_u32(bin[36..40]) 
	op.major_operating_system_version = binary.little_endian_u16(bin[40..42])
	op.minor_operating_system_version = binary.little_endian_u16(bin[42..44]) 
	op.major_image_version = binary.little_endian_u16(bin[44..46]) 
	op.minor_image_version = binary.little_endian_u16(bin[46..48])
	op.major_subsystem_version = binary.little_endian_u16(bin[48..50])
	op.minor_subsystem_version = binary.little_endian_u16(bin[50..52]) 
	op.reserved1 = binary.little_endian_u32(bin[52..56]) 
    op.size_of_image = binary.little_endian_u32(bin[56..60])
	op.size_of_headers = binary.little_endian_u32(bin[60..64]) 
	op.checksum = binary.little_endian_u32(bin[64..68]) 
	op.subsystem = binary.little_endian_u16(bin[68..70])
 	op.dll_characteristics = binary.little_endian_u16(bin[70..72]) 
	op.size_of_stack_reserve = binary.little_endian_u32(bin[72..76]) 
	op.size_of_stack_commit = binary.little_endian_u32(bin[76..80]) 
	op.size_of_heap_reserve = binary.little_endian_u32(bin[80..84]) 
	op.size_of_heap_commit = binary.little_endian_u32(bin[84..88]) 
	op.loader_flags = binary.little_endian_u32(bin[88..92])
	op.number_of_rva_and_sizes = binary.little_endian_u32(bin[92..96]) 	
	
	mut off := 96
	for i in 0..image_numberof_directory_entries {
		op.data_directory[i].virtual_address = binary.little_endian_u32(bin[off..off+4]) 
		op.data_directory[i].size = binary.little_endian_u32(bin[off+4..off+8])
		off += 8
	}
}

pub fn (mut sect IMAGE_SECTION_HEADER) load(bin []byte) {
	mut off := 0
	for off < image_sizeof_short_name {
		sect.name[off] = bin[off]
		off++
	}

	sect.physical_address = binary.little_endian_u32(bin[off..off+4])
	//sect.virtual_size = binary.little_endian_u32(bin[off+4..off+8])
	sect.virtual_address = binary.little_endian_u32(bin[off+4..off+8])
	sect.size_of_raw_data = binary.little_endian_u32(bin[off+8..off+12])
	sect.pointer_to_raw_data = binary.little_endian_u32(bin[off+12..off+16])
	sect.pointer_to_relocations = binary.little_endian_u32(bin[off+16..off+20])
	sect.pointer_to_linenumbers = binary.little_endian_u32(bin[off+20..off+24])
	sect.number_of_relocations = binary.little_endian_u16(bin[off+24..off+26])
	sect.number_of_linenumbers = binary.little_endian_u16(bin[off+26..off+28])
	sect.characteristics = binary.little_endian_u32(bin[off+28..off+32])
}

////////////// PRINTERS //////////////

pub fn (dos IMAGE_DOS_HEADER) print() {
	println('-= IMAGE_DOS_HEADER =-')
	println('Magic number: $dos.e_magic')
	println('Bytes on last page of file: $dos.e_cblp')
	println('Pages in file: $dos.e_cp')
	println('Relocations: $dos.e_crlc')
	println('Size of header in paragraphs: $dos.e_cparhdr')
	println('Minimum extra paragraphs needed: $dos.e_minalloc')
	println('Maximum extra paragraphs needed: $dos.e_maxalloc')
	println('Initial relative SS value: $dos.e_ss')
	println('Initial SP value: $dos.e_sp')
	println('Checksum: $dos.e_csum')
	println('Initial IP Value: $dos.e_ip')
	println('Initial relative CS value: $dos.e_cs')
	println('File address of relocation table: $dos.e_lfarlc')
	println('Overlay number: $dos.e_ovno')
	println('OEM identifier: $dos.e_oemid')
	println('OEM information: $dos.e_oeminfo')
	println('File address of new exe header: 0x$dos.e_lfanew.hex()')
	println('')
}

pub fn (nt IMAGE_NT_HEADERS) print() {
	println('-= IMAGE_NT_HEADERS =-')
	println('Signature: $nt.signature')
	println('')
}

pub fn (fh IMAGE_FILE_HEADER) print() {
	println('-= IMAGE_FILE_HEADER =-')
	println('Machine: $fh.machine')
	println('Number of sections: $fh.number_of_sections')
	println('Time Date stamp: $fh.time_date_stamp')
	println('Ptr to symbol table: 0x$fh.pointer_to_symbol_table.hex()')
	println('Number of symbols: $fh.number_of_symbols')
	println('Size of optional header: $fh.size_of_optional_header')
	println('Characteristics: $fh.characteristics')
	println('')
}

pub fn (op IMAGE_OPTIONAL_HEADER) print() {
	println('-= IMAGE_OPTIONAL_HEADER =-')
	println('Magic: $op.magic')
	println('Major linker version: $op.major_linker_version')
	println('Minor linker version: $op.minor_linker_version')
	println('Size of code: $op.size_of_code')
	println('Size of initialized data: $op.size_of_initialized_data')
	println('Size of uninitialized data: $op.size_of_uninitialized_data')
	println('Entry point: 0x$op.address_of_entry_point.hex()')
	println('Base of code: $op.base_of_code')
	println('Base of data: $op.base_of_data')

	println('Image base: $op.image_base')
	println('Section alignment: $op.section_alignment')
	println('File alignment: $op.file_alignment')
	println('Major operating system version: $op.major_operating_system_version')
	println('Minor operating system version: $op.minor_operating_system_version')
	println('Major image version: $op.major_image_version')
	println('Minor image version: $op.minor_image_version')
	println('Major subsystem version: $op.major_subsystem_version')
	println('Minor subsystem version: $op.minor_subsystem_version')
	println('Reserved1: $op.reserved1')
    println('Size of image: $op.size_of_image')
	println('Size of headers: $op.size_of_headers')
	println('Checksum: $op.checksum')
	println('Subsystem: $op.subsystem')
 	println('Dll characteristics: $op.dll_characteristics')
	println('Size of stack reserve: $op.size_of_stack_reserve')
	println('Size of stack commit: $op.size_of_stack_commit')
	println('Size of heap reserve: $op.size_of_heap_reserve')
	println('Size of heap commit: $op.size_of_heap_commit')
	println('Loader flags: $op.loader_flags')
	println('Number of rva and sizes: $op.number_of_rva_and_sizes')
	println('')
}

pub fn (dir IMAGE_DATA_DIRECTORY) print() {
	println('-= IMAGE_DATA_DIRECTORY =-')
	println('Virtual address: $dir.virtual_address')
	println('Size: $dir.size')
	println('')
}

pub fn (sect IMAGE_SECTION_HEADER) print() {
	println('-= IMAGE_SECTION_HEADER =-')
	println('name: $sect.name')
	name := string(sect.name)
	println('Section name: $name')
	println('Physical address: 0x$sect.physical_address.hex()')
	//println('Virtual size: $sect.virtual_size')
	println('Virtual address: 0x$sect.virtual_address.hex()')
	println('Size of raw data: $sect.size_of_raw_data')
	println('Ptr to raw data: 0x$sect.pointer_to_raw_data.hex()')
	println('Ptr to relocs: 0x$sect.pointer_to_relocations.hex()')
	println('Ptr to line numbers: 0x$sect.pointer_to_linenumbers.hex()')
	println('Number of relocations: $sect.number_of_relocations')
	println('Number of line numbers: $sect.number_of_linenumbers')
	println('Characteristics: $sect.characteristics')
	println('')
}

////////////// SAVE STRUCTURES //////////////

fn (dos IMAGE_DOS_HEADER) save(mut bin []byte) {

	binary.little_endian_put_u16(mut bin[0..2], dos.e_magic)
	binary.little_endian_put_u16(mut bin[2..4], dos.e_cblp)
	binary.little_endian_put_u16(mut bin[4..6], dos.e_cp)
	binary.little_endian_put_u16(mut bin[6..8], dos.e_crlc)
	binary.little_endian_put_u16(mut bin[8..10], dos.e_cparhdr)
	binary.little_endian_put_u16(mut bin[10..12], dos.e_minalloc)
	binary.little_endian_put_u16(mut bin[12..14], dos.e_maxalloc)
	binary.little_endian_put_u16(mut bin[14..16], dos.e_ss)
	binary.little_endian_put_u16(mut bin[16..18], dos.e_sp)
	binary.little_endian_put_u16(mut bin[18..20], dos.e_csum)
	binary.little_endian_put_u16(mut bin[20..22], dos.e_ip)
	binary.little_endian_put_u16(mut bin[22..24], dos.e_cs)
	binary.little_endian_put_u16(mut bin[24..26], dos.e_lfarlc)
	binary.little_endian_put_u16(mut bin[26..28], dos.e_ovno)

	binary.little_endian_put_u16(mut bin[28..30], dos.e_res[0])
	binary.little_endian_put_u16(mut bin[30..32], dos.e_res[1])
	binary.little_endian_put_u16(mut bin[32..34], dos.e_res[2])
	binary.little_endian_put_u16(mut bin[34..36], dos.e_res[3])

	binary.little_endian_put_u16(mut bin[36..38], dos.e_oemid)
	binary.little_endian_put_u16(mut bin[38..40], dos.e_oeminfo)

	binary.little_endian_put_u16(mut bin[40..42], dos.e_res2[0])
	binary.little_endian_put_u16(mut bin[42..44], dos.e_res2[1])
	binary.little_endian_put_u16(mut bin[44..46], dos.e_res2[2])
	binary.little_endian_put_u16(mut bin[46..48], dos.e_res2[3])
	binary.little_endian_put_u16(mut bin[48..50], dos.e_res2[4])
	binary.little_endian_put_u16(mut bin[50..52], dos.e_res2[5])
	binary.little_endian_put_u16(mut bin[52..54], dos.e_res2[6])
	binary.little_endian_put_u16(mut bin[54..56], dos.e_res2[7])
	binary.little_endian_put_u16(mut bin[56..58], dos.e_res2[8])
	binary.little_endian_put_u16(mut bin[58..60], dos.e_res2[9])

	binary.little_endian_put_u32(mut bin[60..64], dos.e_lfanew)
}

fn (nt IMAGE_NT_HEADERS) save(mut bin []byte) {
	binary.little_endian_put_u32(mut bin[0..4], nt.signature)
}

fn (fh IMAGE_FILE_HEADER) save(mut bin []byte) {
	binary.little_endian_put_u16(mut bin[0..2], fh.machine)
	binary.little_endian_put_u16(mut bin[2..4], fh.number_of_sections)
	binary.little_endian_put_u32(mut bin[4..8], fh.time_date_stamp)
	binary.little_endian_put_u32(mut bin[8..12], fh.pointer_to_symbol_table)
	binary.little_endian_put_u32(mut bin[12..16], fh.number_of_symbols)
	binary.little_endian_put_u16(mut bin[16..18], fh.size_of_optional_header)
	binary.little_endian_put_u16(mut bin[18..20], fh.characteristics)
}

fn (op IMAGE_OPTIONAL_HEADER) save(mut bin []byte) {
	binary.little_endian_put_u16(mut bin[0..2], op.magic)
	bin[2] = op.major_linker_version
	bin[3] = op.minor_linker_version
	binary.little_endian_put_u32(mut bin[4..8], op.size_of_code)
	binary.little_endian_put_u32(mut bin[8..12], op.size_of_initialized_data)
	binary.little_endian_put_u32(mut bin[12..16], op.size_of_uninitialized_data)
	binary.little_endian_put_u32(mut bin[16..20], op.address_of_entry_point)
	binary.little_endian_put_u32(mut bin[20..24], op.base_of_code)
	binary.little_endian_put_u32(mut bin[24..28], op.base_of_data)

	binary.little_endian_put_u32(mut bin[28..32], op.image_base)
	binary.little_endian_put_u32(mut bin[32..36], op.section_alignment)
	binary.little_endian_put_u32(mut bin[36..40], op.file_alignment)

	binary.little_endian_put_u16(mut bin[40..42], op.major_operating_system_version)
	binary.little_endian_put_u16(mut bin[42..44], op.minor_operating_system_version)
	binary.little_endian_put_u16(mut bin[44..46], op.major_image_version)
	binary.little_endian_put_u16(mut bin[46..48], op.minor_image_version)
	binary.little_endian_put_u16(mut bin[48..50], op.major_subsystem_version)
	binary.little_endian_put_u16(mut bin[50..52], op.minor_subsystem_version)

	binary.little_endian_put_u32(mut bin[52..56], op.reserved1)
	binary.little_endian_put_u32(mut bin[56..60], op.size_of_image)
	binary.little_endian_put_u32(mut bin[60..64], op.size_of_headers)
	binary.little_endian_put_u32(mut bin[64..68], op.checksum)

	binary.little_endian_put_u16(mut bin[68..70], op.subsystem)
	binary.little_endian_put_u16(mut bin[70..72], op.dll_characteristics)
	binary.little_endian_put_u32(mut bin[72..76], op.size_of_stack_reserve)
	binary.little_endian_put_u32(mut bin[76..80], op.size_of_stack_commit)
	binary.little_endian_put_u32(mut bin[80..84], op.size_of_heap_reserve)
	binary.little_endian_put_u32(mut bin[84..88], op.size_of_heap_commit)

	binary.little_endian_put_u32(mut bin[88..92], op.loader_flags)
	binary.little_endian_put_u32(mut bin[92..96], op.number_of_rva_and_sizes)

	mut off := 96
	for i in 0..image_numberof_directory_entries {
		binary.little_endian_put_u32(mut bin[off..off+4], op.data_directory[i].virtual_address)
		binary.little_endian_put_u32(mut bin[off+4..off+8], op.data_directory[i].size)
		off += 8
	}
}


pub fn (sect IMAGE_SECTION_HEADER) save(mut bin []byte) {
	mut off := 0
	for off < image_sizeof_short_name {
		bin[off] = sect.name[off]
		off++
	}

	binary.little_endian_put_u32(mut bin[off..off+4], sect.physical_address)
	binary.little_endian_put_u32(mut bin[off+4..off+8], sect.virtual_address)
	binary.little_endian_put_u32(mut bin[off+8..off+12], sect.size_of_raw_data)
	binary.little_endian_put_u32(mut bin[off+16..off+20], sect.pointer_to_relocations)
	binary.little_endian_put_u32(mut bin[off+20..off+24], sect.pointer_to_linenumbers)
	binary.little_endian_put_u16(mut bin[off+24..off+26], sect.number_of_relocations)
	binary.little_endian_put_u16(mut bin[off+26..off+28], sect.number_of_linenumbers)
	binary.little_endian_put_u32(mut bin[off+28..off+32], sect.characteristics)
}


////////////// BINARY BASE OBJECT //////////////

pub struct Binary  {
pub mut:
	size int
	filename string 
	data []byte	
	dos IMAGE_DOS_HEADER
	nt IMAGE_NT_HEADERS
	fh IMAGE_FILE_HEADER
	opt IMAGE_OPTIONAL_HEADER
	sections []IMAGE_SECTION_HEADER
}

pub fn load(filename string) ?&Binary {
	mut bin := &Binary{}

	bin.size = os.file_size(filename)
	mut f := os.open(filename) or { return error('bad filename') }
	bin.data = f.read_bytes(bin.size)
	f.close()

	bin.dos = IMAGE_DOS_HEADER{}
	bin.dos.load(bin.data)

	bin.nt = IMAGE_NT_HEADERS{}
	bin.nt.load(bin.data[bin.dos.e_lfanew..bin.dos.e_lfanew+4])

	bin.fh = IMAGE_FILE_HEADER{}
	bin.fh.load(bin.data[bin.dos.e_lfanew+4..bin.dos.e_lfanew+24])

	bin.opt = IMAGE_OPTIONAL_HEADER{}
	bin.opt.load(bin.data[bin.dos.e_lfanew+24..bin.dos.e_lfanew+248])

	// load sections
	mut off := bin.dos.e_lfanew+248
	for _ in 0..bin.fh.number_of_sections {
		mut sect := IMAGE_SECTION_HEADER{}

		sect.load(bin.data[off..])

		bin.sections << sect
		off += section_header_sz
	}

	return bin
}

pub fn (mut bin Binary) save(filename string) {
	bin.dos.save(mut bin.data)
	bin.nt.save(mut bin.data[bin.dos.e_lfanew..bin.dos.e_lfanew+4])
	bin.fh.save(mut bin.data[bin.dos.e_lfanew+4..bin.dos.e_lfanew+24])
	bin.opt.save(mut bin.data[bin.dos.e_lfanew+24..bin.dos.e_lfanew+248])

	mut off := bin.dos.e_lfanew+248
	for sect in bin.sections { 
		sect.save(mut bin.data[off..])
		off += section_header_sz
	}

	mut f := os.open_file(filename, 'w+') or { panic('cant save to file $filename') }
	f.write_to(0, bin.data) or { panic('cant save the data') }
	f.close()
}

