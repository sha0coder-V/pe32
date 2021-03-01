module pe32

import binary
import os

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

struct IMAGE_DOS_HEADER {
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

struct IMAGE_FILE_HEADER {
	Machine u16 
	NumberOfSections u16 
	TimeDateStamp u32
	PointerToSymbolTable u32
	NumberOfSymbols u32 
	SizeOfOptionalHeader u16
    Characteristics u16;
}

type IMAGE_DATA_DIRECTORY {
	VirtualAddress u32
	Size u32
}

struct IMAGE_OPTIONAL_HEADER {
	// Standard fields.
	Magic u16
	MajorLinkerVersion byte 
	MinorLinkerVersion byte 
	SizeOfCode u32 
	SizeOfInitializedData u32 
	SizeOfUninitializedData u32
	AddressOfEntryPoint u32 
	BaseOfCode u32 
	BaseOfData u32
	// NT additional fields.
	ImageBase u32 
	SectionAlignment u32 
	FileAlignment u32 
	MajorOperatingSystemVersion u16 
	MinorOperatingSystemVersion u16 
	MajorImageVersion u16 
	MinorImageVersion u16
	MajorSubsystemVersion u16
	MinorSubsystemVersion u16 
	Reserved1 u32 
    SizeOfImage u32
	SizeOfHeaders u32 
	CheckSum u32 
	Subsystem u16
 	DllCharacteristics u16 
	SizeOfStackReserve u16 
	SizeOfStackCommit u16 
	SizeOfHeapReserve u16 
	SizeOfHeapCommit u16 
	LoaderFlags u32 
	NumberOfRvaAndSizes u32 
	DataDirectory [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

struct IMAGE_SECTION_HEADER {
	Name [IMAGE_SIZEOF_SHORT_NAME]byte 
	PhysicalAddress u32
	VirtualSize u32
	VirtualAddress u32 
	SizeOfRawData u32 
	PointerToRawData u32 
	PointerToRelocations u32 
	PointerToLinenumbers u32 
	NumberOfRelocations u16 
	NumberOfLinenumbers u16 
	Characteristics u32 
}

struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    Name u32
    OffsetToData u32
}

struct IMAGE_RESOURCE_DIRECTORY {
    Characteristics u32 
    TimeDateStamp u32
    MajorVersion u16 
    MinorVersion u16
    NumberOfNamedEntries u16
    NumberOfIdEntries u16
}

struct IMAGE_RESOURCE_DATA_ENTRY {
    OffsetToData u32
    Size u32
    CodePage u32
    Reserved u32
}

struct IMAGE_RESOURCE_DIR_STRING_U {
    Length u16
    NameString [1]byte
}

struct IMAGE_EXPORT_DIRECTORY {
    Characteristics u32
    TimeDateStamp u32
    MajorVersion u16
    MinorVersion u16
    Name u32
    Base u32
    NumberOfFunctions u32
    NumberOfNames u32
    AddressOfFunctions u32
    AddressOfNames u32
    AddressOfNameOrdinals u32
}

struct tagImportDirectory {
    dwRVAFunctionNameList u32
    dwUseless1 u32
    dwUseless2 u32
    dwRVAModuleName u32
    dwRVAFunctionAddressList u32
}


struct IMAGE_DEBUG_DIRECTORY {
    ULONG   Characteristics u32
    ULONG   TimeDateStamp u32
    USHORT  MajorVersion u16
    USHORT  MinorVersion u16
    ULONG   Type u32
    ULONG   SizeOfData u32
    ULONG   AddressOfRawData u32
    ULONG   PointerToRawData u32
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

struct Binary  {
	size int
	filename string 
	data []byte	
	image_dos_header IMAGE_DOS_HEADER
}

fn load(filename string) Binary {
	mut bin := &Binary{}

	bin.size = os.file_size()
	mut f := os.open(filename)
	bin.data := f.read_bytes(bin.size)
	f.close()

	bin.image_dos_header = IMAGE_DOS_HEADER{}
	bin.image_dos_header.load(bin.data)
}

