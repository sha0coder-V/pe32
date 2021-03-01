module pe32

import os
import encoding.binary


// https://blog.kowalczyk.info/articles/pefileformat.html

const (
	IMAGE_DOS_SIGNATURE = 0x5A4D     // MZ
	IMAGE_OS2_SIGNATURE = 0x454E     // NE
	IMAGE_OS2_SIGNATURE_LE = 0x454C  // LE
	IMAGE_NT_SIGNATURE = 0x00004550  // PE00
	IMAGE_SIZEOF_FILE_HEADER = 20
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
	IMAGE_DIRECTORY_ENTRY_IMPORT = 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
	IMAGE_DIRECTORY_ENTRY_SECURITY = 4
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
	IMAGE_DIRECTORY_ENTRY_DEBUG = 6
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
	IMAGE_DIRECTORY_ENTRY_TLS = 9
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
	IMAGE_SIZEOF_SHORT_NAME = 8
	IMAGE_DEBUG_TYPE_UNKNOWN = 0
	IMAGE_DEBUG_TYPE_COFF = 1
	IMAGE_DEBUG_TYPE_CODEVIEW = 2
	IMAGE_DEBUG_TYPE_FPO = 3
	IMAGE_DEBUG_TYPE_MISC = 4
)

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
	data_directory [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
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
	size_of_stack_reserve u16 
	size_of_stack_commit u16 
	size_of_heap_reserve u16 
	size_of_heap_commit u16 
	loader_flags u32 
	number_of_rva_and_sizes u32 	
}

pub struct IMAGE_SECTION_HEADER {
pub mut:
	name [IMAGE_SIZEOF_SHORT_NAME]byte 
	physical_address u32
	virtual_size u32
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

pub struct Binary  {
pub mut:
	size int
	filename string 
	data []byte	
	image_dos_header IMAGE_DOS_HEADER
}

pub fn load(filename string) ?&Binary {
	mut bin := &Binary{}

	bin.size = os.file_size(filename)
	mut f := os.open(filename) or { return error('bad filename') }
	bin.data = f.read_bytes(bin.size)
	f.close()

	bin.image_dos_header = IMAGE_DOS_HEADER{}
	bin.image_dos_header.load(bin.data)

	return bin
}

