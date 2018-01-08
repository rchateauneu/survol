import pefile
import capstone

def TestHeavy():
	CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	for i in md.disasm(CODE, 0x1000):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def TestLight():
	CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, 0x1000):
		print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

def TestThree():
	CODE = b"\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
	md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
	md.detail = True

	for i in md.disasm(CODE, 0x1000):
		if i.id in (capstone.arm.ARM_INS_BL, capstone.arm.ARM_INS_CMP):
			print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

		if len(i.regs_read) > 0:
			print("\tImplicit registers read: "),
			for r in i.regs_read:
				print("%s " %i.reg_name(r)),
			print

		if len(i.groups) > 0:
			print("\tThis instruction belongs to groups:"),
			for g in i.groups:
				print("%u" %g),
			print


# https://stackoverflow.com/questions/37439627/which-bytes-should-i-pass-to-capstone-to-disassemble-the-executable-code-of-a-pe
def TestDisassembleFile(file_path):
	print("File=%s"%file_path)
	pe = pefile.PE(file_path)

	eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	code_section = pe.get_section_by_rva(eop)

	code_dump = code_section.get_data()

	code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

	for i in md.disasm(code_dump, code_addr):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def SplitPE(file_path):
	pe = pefile.PE(file_path)

	# TODO: Extraire les noms des fonctions.

	# Possible values:
	# http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
	#
	# ('.bss\x00\x00\x00\x00', '0xf000', '0x14c', 0)		Uninitialised data segment.
	# ('.data\x00\x00\x00', '0x5e000', '0x3a24', 11264)	 Initialised data segment
	# ('.edata\x00\x00', '0x10000', '0x2067', 8704)		 Export Data Section
	# ('.idata\x00\x00', '0x18000', '0x76c', 2048)		  Initialized Data Section  (Borland)
	# ('.rdata\x00\x00', '0x15000', '0x1972', 6656)		 Read-only initialized Data Section  (MS and Borland)
	# ('.reloc\x00\x00', '0x63000', '0x53c0', 21504)		Relocations Section
	# ('.rsrc\x00\x00\x00', '0x62000', '0x3d8', 1024)	   Resource section
	# ('.stab\x00\x00\x00', '0x15000', '0x33660', 210944)   Created by Haskell compiler (GHC)
	# ('.stabstr', '0x49000', '0xa2d5f', 667136)			Created by Haskell compiler (GHC)
	# ('.text\x00\x00\x00', '0x1000', '0x5cd75', 380416)	Code, vector table plus constants.
	# ('.textbss', '0x1000', '0x10000', 0)				  Section used by incremental linking

	# typedef struct _IMAGE_SECTION_HEADER {
	#   BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	#   union {
	#	 DWORD PhysicalAddress;
	#	 DWORD VirtualSize;
	#   } Misc;
	#   DWORD VirtualAddress;
	#   DWORD SizeOfRawData;
	#   DWORD PointerToRawData;
	#   DWORD PointerToRelocations;
	#   DWORD PointerToLinenumbers;
	#   WORD  NumberOfRelocations;
	#   WORD  NumberOfLinenumbers;
	#   DWORD Characteristics;
	# } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
	print("Name, VirtualAddress, Misc_VirtualSize, SizeOfRawData")
	for section in pe.sections:
		print (section.Name, hex(section.VirtualAddress), section.Misc_VirtualSize, section.SizeOfRawData )


def DumpFromAddr(md, code_dump, code_addr):
	def PrintInstr(instr):
		print("0x%x: %10s:\t%-20s\t%-40s\t%10s\t%10s" %(
			instr.address,
			instr.address - code_addr,
			instr.mnemonic,
			instr.op_str,
			instr.id,
			instr.groups))


	# x86 constants here:
	# https://github.com/aquynh/capstone/blob/master/bindings/python/capstone/x86_const.py
	for instr in md.disasm(code_dump, code_addr):
		# address, bytes, errno, group, group_name, groups, id, insn_name, mnemonic, op_count, op_find, op_str,
		#  reg_name, reg_read, reg_write, regs_read, regs_write, size]

		# 'groups' = [2, 145], or [1] or [] for example.
		if capstone.x86.X86_GRP_JUMP in instr.groups:
			# jbe					 0x401018
			PrintInstr(instr)
		elif capstone.x86.X86_GRP_CALL in instr.groups:
			if instr.id == capstone.x86.X86_INS_CALL:
				# Calculated function called are supposed to be "significant": However,
				# we do not know what is called.
				# call					rdi	  # Cannot do anything for this one.
				# call					rsi	  # Cannot do anything for this one.
				# call					0x401ac4 # Only here the information is usable.
				PrintInstr(instr)
			else:
				# call					qword ptr [rip + 0x4020b4]
				PrintInstr(instr)
		else:
			pass
			# print("0x%x:\t%-20s\t%-40s\t%10s\t%10s" %(i.address, i.mnemonic, i.op_str, i.id, i.groups))




# https://stackoverflow.com/questions/37439627/which-bytes-should-i-pass-to-capstone-to-disassemble-the-executable-code-of-a-pe
def TestDisassembleFileGroups(file_path):
	print("File=%s"%file_path)
	pe = pefile.PE(file_path)

	eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint

	print("Entry point:0x%x"%eop)

	# Get the section containing the given address.
	# TODO: Print the name of the section.
	# TODO: What happens for a DLL ? Which entry point is it ?

	code_section = pe.get_section_by_rva(eop)

	# code_section.name = "IMAGE_SECTION_HEADER"
	# code_section.Name = ".text"
	print("code_section.Name:%s"%code_section.Name)
	# print(dir(code_section))

	print("ImageBase       :0x%x"%pe.OPTIONAL_HEADER.ImageBase)
	print("VirtualAddress  :0x%x"%code_section.VirtualAddress)
	print("Misc_VirtualSize:%s 0x%x"%(code_section.Misc_VirtualSize,code_section.Misc_VirtualSize))
	print("SizeOfRawData   :%s 0x%x"%(code_section.SizeOfRawData,code_section.SizeOfRawData))

	code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
	print("code_addr:0x%x"%code_addr)

	# A very long binary string.
	code_dump = code_section.get_data()
	print("code_dump len:%d"%len(code_dump))

	# https://github.com/erocarrera/pefile/blob/master/pefile.py
	dictMachineTypes = {}
	for keyMachTyp,valMachTyp in pefile.machine_types:
		dictMachineTypes[keyMachTyp] = valMachTyp

	if pe.FILE_HEADER.Machine == dictMachineTypes['IMAGE_FILE_MACHINE_I386']: # 0x014c
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	elif pe.FILE_HEADER.Machine == dictMachineTypes['IMAGE_FILE_MACHINE_IA64']: # 0x0200
		md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	else:
		raise "Unknown machine type"

	md.detail = True

	# This fails.
	# md.skipdata = True
    # raise CsError(CS_ERR_SKIPDATA)
	# capstone.CsError: Information irrelevant for 'data' instruction in SKIPDATA mode (CS_ERR_SKIPDATA)

	# First pass to extract the start addresses and their destination addresses.
	# Each of these are nodes, linked by the call or the jump.
	# Jumps shorter than a given threshold are not taken into account,
	# and considered as too local to reflect the large-scale of the program logic.
	#
	# Accordingly, we might consider that:
	# - calls made in tiny segments of code could be neglected (DISCUSS THIS).
	# - Routines shorted than a given threshold, and without calls, could be neglected.
	DumpFromAddr(md, code_dump, code_addr)


if False:
	TestHeavy()
	TestLight()
	TestThree()

for file_path in [
	#r"C:\Program Files (x86)\Git\bin\libaprutil-0-0.dll",
	#r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\ClearSysReg.exe",
	#r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\msvcr100d.dll",
	#r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\Estar.dll",
	r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\msvcp100.dll",
]:
	#SplitPE(file_path)
	#TestDisassembleFile(file_path)
	TestDisassembleFileGroups(file_path)

rr = raw_input("Press return:")

#name = input("What's your name? ")
#print("Nice to meet you " + name + "!")
#age = input("Your age? ")
#print("So, you are already " + str(age) + " years old, " + name + "!")

# ['Characteristics', 'IMAGE_SCN_ALIGN_1024BYTES', 'IMAGE_SCN_ALIGN_128BYTES', 'IMAGE_SCN_ALIGN_16BYTES',
# 'IMAGE_SCN_ALIGN_1BYTES', 'IMAGE_SCN_ALIGN_2048BYTES', 'IMAGE_SCN_ALIGN_256BYTES', 'IMAGE_SCN_ALIGN_2BYTES',
# 'IMAGE_SCN_ALIGN_32BYTES', 'IMAGE_SCN_ALIGN_4096BYTES', 'IMAGE_SCN_ALIGN_4BYTES', 'IMAGE_SCN_ALIGN_512BYTES',
# 'IMAGE_SCN_ALIGN_64BYTES', 'IMAGE_SCN_ALIGN_8192BYTES', 'IMAGE_SCN_ALIGN_8BYTES', 'IMAGE_SCN_ALIGN_MASK',
# 'IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_CNT_INITIALIZED_DATA', 'IMAGE_SCN_CNT_UNINITIALIZED_DATA',
# 'IMAGE_SCN_LNK_COMDAT', 'IMAGE_SCN_LNK_INFO', 'IMAGE_SCN_LNK_NRELOC_OVFL', 'IMAGE_SCN_LNK_OTHER',
# 'IMAGE_SCN_LNK_REMOVE', 'IMAGE_SCN_MEM_16BIT', 'IMAGE_SCN_MEM_DISCARDABLE', 'IMAGE_SCN_MEM_EXECUTE',
# 'IMAGE_SCN_MEM_FARDATA', 'IMAGE_SCN_MEM_LOCKED', 'IMAGE_SCN_MEM_NOT_CACHED', 'IMAGE_SCN_MEM_NOT_PAGED',
# 'IMAGE_SCN_MEM_PRELOAD', 'IMAGE_SCN_MEM_PURGEABLE', 'IMAGE_SCN_MEM_READ', 'IMAGE_SCN_MEM_SHARED',
# 'IMAGE_SCN_MEM_WRITE', 'Misc', 'Misc_PhysicalAddress', 'Misc_VirtualSize', 'Name', 'NumberOfLinenumbers',
# 'NumberOfRelocations', 'PointerToLinenumbers', 'PointerToRawData', 'PointerToRelocations', 'SizeOfRawData',
# 'VirtualAddress', '__all_zeroes__', '__doc__', '__field_offsets__', '__file_offset__', '__format__',
# '__format_length__', '__get_format__', '__init__', '__keys__', '__module__', '__pack__', '__repr__',
# '__set_format__', '__setattr__', '__str__', '__unpack__', '__unpacked_data_elms__', 'all_zeroes', 'contains',
# 'contains_offset', 'contains_rva', 'dump', 'entropy_H', 'get_data', 'get_entropy', 'get_field_absolute_offset',
# 'get_field_relative_offset', 'get_file_offset', 'get_hash_md5', 'get_hash_sha1', 'get_hash_sha256', 'get_hash_sha512',
# 'get_offset_from_rva', 'get_rva_from_offset', 'name', 'pe', 'set_file_offset', 'sizeof', 'sizeof_type']

# ['DIRECTORY_ENTRY_BASERELOC', 'DIRECTORY_ENTRY_EXPORT', 'DIRECTORY_ENTRY_IMPORT', 'DOS_HEADER', 'FILE_HEADER',
# 'NT_HEADERS', 'OPTIONAL_HEADER', 'PE_TYPE', 'RICH_HEADER', '_PE__from_file', '_PE__warnings',
# '__IMAGE_BASE_RELOCATION_ENTRY_format__', '__IMAGE_BASE_RELOCATION_format__', '__IMAGE_BOUND_FORWARDER_REF_format__',
# '__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__', '__IMAGE_DATA_DIRECTORY_format__', '__IMAGE_DEBUG_DIRECTORY_format__',
# '__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__', '__IMAGE_DOS_HEADER_format__', '__IMAGE_EXPORT_DIRECTORY_format__',
# '__IMAGE_FILE_HEADER_format__', '__IMAGE_IMPORT_DESCRIPTOR_format__', '__IMAGE_LOAD_CONFIG_DIRECTORY64_format__',
# '__IMAGE_LOAD_CONFIG_DIRECTORY_format__', '__IMAGE_NT_HEADERS_format__', '__IMAGE_OPTIONAL_HEADER64_format__',
# '__IMAGE_OPTIONAL_HEADER_format__', '__IMAGE_RESOURCE_DATA_ENTRY_format__', '__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__',
# '__IMAGE_RESOURCE_DIRECTORY_format__', '__IMAGE_SECTION_HEADER_format__', '__IMAGE_THUNK_DATA64_format__',
# '__IMAGE_THUNK_DATA_format__', '__IMAGE_TLS_DIRECTORY64_format__', '__IMAGE_TLS_DIRECTORY_format__',
# '__StringFileInfo_format__', '__StringTable_format__', '__String_format__', '__VS_FIXEDFILEINFO_format__',
# '__VS_VERSIONINFO_format__', '__Var_format__', '__data__', '__doc__', '__init__', '__module__', '__parse__',
# '__str__', '__structures__', '__unpack_data__', 'adjust_FileAlignment', 'adjust_SectionAlignment', 'close',
# 'dump_info', 'dword_align', 'fileno', 'full_load', 'generate_checksum', 'get_data', 'get_data_from_dword',
# 'get_data_from_qword', 'get_data_from_word', 'get_dword_at_rva', 'get_dword_from_data', 'get_dword_from_offset',
# 'get_import_table', 'get_memory_mapped_image', 'get_offset_from_rva', 'get_overlay', 'get_overlay_data_start_offset',
# 'get_physical_by_rva', 'get_qword_at_rva', 'get_qword_from_data', 'get_qword_from_offset', 'get_resources_strings',
# 'get_rva_from_offset', 'get_section_by_offset', 'get_section_by_rva', 'get_string_at_rva', 'get_string_from_data',
# 'get_string_u_at_rva', 'get_warnings', 'get_word_at_rva', 'get_word_from_data', 'get_word_from_offset', 'header',
# 'is_dll', 'is_driver', 'is_exe', 'merge_modified_section_data', 'parse_data_directories', 'parse_debug_directory',
# 'parse_delay_import_directory', 'parse_directory_bound_imports', 'parse_directory_load_config', 'parse_directory_tls',
# 'parse_export_directory', 'parse_import_directory', 'parse_imports', 'parse_relocations', 'parse_relocations_directory',
# 'parse_resource_data_entry', 'parse_resource_entry', 'parse_resources_directory', 'parse_rich_header', 'parse_sections',
# 'parse_version_information', 'print_info', 'relocate_image', 'sections', 'set_bytes_at_offset', 'set_bytes_at_rva',
# 'set_dword_at_offset', 'set_dword_at_rva', 'set_qword_at_offset', 'set_qword_at_rva', 'set_word_at_offset',
# 'set_word_at_rva', 'show_warnings', 'trim', 'verify_checksum', 'write']
# print(dir(pe))

