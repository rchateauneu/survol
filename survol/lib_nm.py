import os
import os.path
import sys
import socket
import urllib
import platform
import lib_util
import lib_common

def GetSymbols(fileSharedLib):

	if os.path.isfile(fileSharedLib):
		DEBUG("File %s exists", fileSharedLib)
	else:
		lib_common.ErrorMessageHtml("File %s does not exist" % fileSharedLib)

	if not lib_util.isPlatformLinux:
		lib_common.ErrorMessageHtml("NM on Linux platform only")
	nmCmd = "nm -DC " + fileSharedLib
	sys.stderr.write("Running %s\n" % nmCmd)
	stream = os.popen(nmCmd)

	# Just to have a sort of clean switch.

	# 0001d75c A __bss_start
	#         U __cxa_allocate_exception

	# Fedora 64 bits:
	#                 w _ITM_registerTMCloneTable
	#                 w _Jv_RegisterClasses
	#0000000000000000 A LIBPAM_1.0
	#0000000000000000 A LIBPAM_EXTENSION_1.0
	if platform.architecture()[0] == "64bit":
		addrWidth = 16
	else:
		addrWidth = 8

	#"A" The symbol's value is absolute, and will not be changed by further linking.
	#"B"
	#"b" The symbol is in the uninitialized data section (known as BSS).
	#"C" The symbol is common.  Common symbols are uninitialized data.  When linking, multiple common
	#    symbols may appear with the same name.  If the symbol is defined anywhere, the common symbols
	#    are treated as undefined references.
	#"D"
	#"d" The symbol is in the initialized data section.
	#"G"
	#"g" The symbol is in an initialized data section for small objects.  Some object file formats
	#    permit more efficient access to small data objects, such as a global int variable as opposed to
	#    a large global array.
	#"I" The symbol is an indirect reference to another symbol.  This is a GNU extension to the a.out
	#    object file format which is rarely used.
	#"i" The symbol is in a section specific to the implementation of DLLs.
	#"N" The symbol is a debugging symbol.
	#"p" The symbols is in a stack unwind section.
	#"R"
	#"r" The symbol is in a read only data section.
	#"S"
	#"s" The symbol is in an uninitialized data section for small objects.
	#"T"
	#"t" The symbol is in the text (code) section.
	#"U" The symbol is undefined.
	#"V"
	#"v" The symbol is a weak object.  When a weak defined symbol is linked with a normal defined
	#    symbol, the normal defined symbol is used with no error.  When a weak undefined symbol is
	#    linked and the symbol is not defined, the value of the weak symbol becomes zero with no erro
	#    On some systems, uppercase indicates that a default value has been specified.
	#"W"
	#"w" The symbol is a weak symbol that has not been specifically tagged as a weak object symbol.
	#    When a weak defined symbol is linked with a normal defined symbol, the normal defined symbol is
	#    used with no error.  When a weak undefined symbol is linked and the symbol is not defined, the
	#    value of the symbol is determined in a system-specific manner without error.  On some systems,
	#    uppercase indicates that a default value has been specified.
	#"-" The symbol is a stabs symbol in an a.out object file.  In this case, the next values printed
	#    are the stabs other field, the stabs desc field, and the stab type.  Stabs symbols are used to
	#    hold debugging information.
	#"?" The symbol type is unknown, or object file format specific.
	for line in stream:
		type = line[addrWidth + 1].upper()
		tail = line[addrWidth + 3:-1]

		yield ( type,tail)
	return
