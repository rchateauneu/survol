#!/usr/bin/python

"""
PEFile information
"""

import sys
import pefile
import lib_common

from sources_types.CIM_DataFile.portable_executable import section as survol_pe_section

def Main():
	cgiEnv = lib_common.CgiEnv(	)

	win_module = cgiEnv.GetId()

	sys.stderr.write("win_module=%s\n"%win_module)

	grph = cgiEnv.GetGraph()

	filNode = lib_common.gUriGen.FileUri(win_module)

	try:
		pe = pefile.PE(win_module)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("File: %s. Exception:%s:" % ( win_module, str(exc)))

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

	propSection = lib_common.MakeProp("Section")
	propVirtualAddress = lib_common.MakeProp("Virtual address")
	propSizeOfRawData = lib_common.MakeProp("Raw data size")
	propNumberOfRelocations = lib_common.MakeProp("Relocations")
	propNumberOfLinenumbers = lib_common.MakeProp("Line numbers")

	try:
		grph.add( ( filNode, lib_common.MakeProp("Is a dll"), lib_common.NodeLiteral(pe.is_dll() )) )
		grph.add( ( filNode, lib_common.MakeProp("Is a driver"), lib_common.NodeLiteral(pe.is_driver() )) )
		grph.add( ( filNode, lib_common.MakeProp("Is an executable"), lib_common.NodeLiteral(pe.is_exe() )) )
		grph.add( ( filNode, lib_common.MakeProp("Overlay data start offset"), lib_common.NodeLiteral(pe.get_overlay_data_start_offset() )) )
		grph.add( ( filNode, lib_common.MakeProp("Resources strings"), lib_common.NodeLiteral(pe.get_resources_strings() )) )
		grph.add( ( filNode, lib_common.MakeProp("Warnings"), lib_common.NodeLiteral(pe.get_warnings() ) ) )
		grph.add( ( filNode, lib_common.MakeProp("DOS header"), lib_common.NodeLiteral(pe.DOS_HEADER) ) )
		grph.add( ( filNode, lib_common.MakeProp("File header"), lib_common.NodeLiteral(pe.FILE_HEADER) ) )

		for peSect in pe.sections:
			# <Structure: [IMAGE_SECTION_HEADER] 0x178 0x0
			# Name: .text 0x180 0x8
			# Misc: 0xC4D8 0x180 0x8
			# Misc_PhysicalAddress: 0xC4D8 0x180 0x8
			# Misc_VirtualSize: 0xC4D8 0x184 0xC
			# VirtualAddress: 0x1000 0x188 0x10
			# SizeOfRawData: 0xC600 0x18C 0x14
			# PointerToRawData: 0x400 0x190 0x18
			# PointerToRelocations: 0x0 0x194 0x1C
			# PointerToLinenumbers: 0x0 0x198 0x20
			# NumberOfRelocations: 0x0 0x19A 0x22
			# NumberOfLinenumbers: 0x0 0x19C 0x24
			# Characteristics: 0x60000020>
			# sys.stderr.write("peSect.Name=%s\n"%peSect.Name)

			# Without the string: "Section=.data\0\0\0"
			nodeSect = survol_pe_section.MakeUri(win_module,peSect.Name.rstrip("\0"))

			grph.add( ( filNode, propSection, nodeSect ) )
			grph.add( ( nodeSect, propVirtualAddress, lib_common.NodeLiteral(peSect.VirtualAddress)) )
			grph.add( ( nodeSect, propSizeOfRawData, lib_common.NodeLiteral(peSect.SizeOfRawData)) )
			grph.add( ( nodeSect, propNumberOfRelocations, lib_common.NodeLiteral(peSect.NumberOfRelocations)) )
			grph.add( ( nodeSect, propNumberOfLinenumbers, lib_common.NodeLiteral(peSect.NumberOfLinenumbers)) )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("File: %s. Exception:%s:" % ( win_module, str(exc)))

	# cgiEnv.OutCgiRdf()
	cgiEnv.OutCgiRdf("LAYOUT_RECT",[propSection])

if __name__ == '__main__':
	Main()

