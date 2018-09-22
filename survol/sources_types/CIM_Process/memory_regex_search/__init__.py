#!/usr/bin/python
"""
Regex matching in heap
"""

import ctypes
import platform
import mmap
import sys
import six
import os
import re
import socket

from six.moves import builtins
from sources_types import CIM_Process

# This module allows to search for regular expressions, in the memory of a running
# process. Indeed, some specific strings give a hint of what a process is doing:
# HTTP urls, SQL queries, ODBC connection strings (and passwords), file names etc...

# There are plans to allow searching for specific data structures,
# it is at least partly implemented, but was never succesfully tested yet.
# The concept is to search for strctures, that is, contiguous set of specific values ranges
# and specific sizes, in raw binary memory.
# These structures would be taken from C/C++ data types actually used by the process.

# TODO: Extend this feature to scanning a raw data file, or a block of shared memory.

# TODO: Other specific strings to search for:
#   Oracle connection strings such as: "scott/tiger@database"
#   IPV4 or IPV6 addresses, in text.
#   Emails, various URLs.
#   Investigate LDAP.
#   Any script code: Javascript etc...

# required to access _ctypes
import _ctypes

ctypes._pointer_t_type_cache64 = {}
def POINTER_64_T(pointee):
	# a pointer should have the same length as LONG
	fake_ptr_base_type = ctypes.c_uint64
	# specific case for c_void_p
	if pointee is None: # VOID pointer type. c_void_p.
		pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
		clsname = 'c_void'
	else:
		clsname = pointee.__name__
	if clsname in ctypes._pointer_t_type_cache64:
		return ctypes._pointer_t_type_cache64[clsname]
	# make template
	class _T(_ctypes._SimpleCData,):
		# https://docs.python.org/2/library/ctypes.html?highlight=structure
		# AttributeError: class must define a '_type_' attribute which must be
		# a single character string containing one of 'cbBhHiIlLdfuzZqQPXOv?g'.
		# http://svn.python.org/projects/python/branches/py3k/Modules/_ctypes/cfield.c
		# _type_ = 'L'
		_type_ = 'Q' # { 'Q', Q_set, Q_get, &ffi_type_uint64, Q_set_sw, Q_get_sw},
		_subtype_ = pointee
		def _sub_addr_(self):
			return self.value
		def __repr__(self):
			return '%s(%d)'%(clsname, self.value)
		def contents(self):
			raise TypeError('This is not a ctypes pointer.')
		def __init__(self, **args):
			raise TypeError('This is not a ctypes pointer. It is not instanciable.')
	_class = type('LP_%d_%s'%(8, clsname), (_T,),{})
	ctypes._pointer_t_type_cache64[clsname] = _class
	return _class

ctypes._pointer_t_type_cache32 = {}
def POINTER_32_T(pointee):
	# a pointer should have the same length as LONG
	fake_ptr_base_type = ctypes.c_uint32
	# specific case for c_void_p
	if pointee is None: # VOID pointer type. c_void_p.
		pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
		clsname = 'c_void'
	else:
		clsname = pointee.__name__
	if clsname in ctypes._pointer_t_type_cache32:
		return ctypes._pointer_t_type_cache32[clsname]
	# make template
	class _T(_ctypes._SimpleCData,):
		_type_ = 'L'
		_subtype_ = pointee
		def _sub_addr_(self):
			return self.value
		def __repr__(self):
			return '%s(%d)'%(clsname, self.value)
		def contents(self):
			raise TypeError('This is not a ctypes pointer.')
		def __init__(self, **args):
			raise TypeError('This is not a ctypes pointer. It is not instanciable.')
	_class = type('LP_%d_%s'%(4, clsname), (_T,),{})
	ctypes._pointer_t_type_cache32[clsname] = _class
	return _class

c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
	c_long_double_t = ctypes.c_longdouble
else:
	c_long_double_t = ctypes.c_ubyte*16

# These structs are made to be applied to 32bits or 64 bits processes.
iPtr64Platform = ctypes.sizeof(ctypes.c_void_p) == 8
if hasattr(builtins, "CTYPES_POINTER_TARGET_64"):
	isPtr64Target = builtins.CTYPES_POINTER_TARGET_64
else:
	# This should not happen, although we have a backup solution.
	# TODO: Why ???????????????????????
	# TODO: Et ca n affiche plus comme avant !!!!!!!!!
	isPtr64Target = iPtr64Platform

if isPtr64Target == iPtr64Platform:
	POINTER_T = ctypes.POINTER
else:
	if isPtr64Target:
		POINTER_T = POINTER_64_T
	else:
		POINTER_T = POINTER_32_T

#print("iPtr64Platform=%d isPtr64Target=%d" % ( iPtr64Platform, isPtr64Target ) )
#print("Pointer size:%d" % ctypes.sizeof(POINTER_T(None)) )
#print("ctypes.c_uint8 size:%d" % ctypes.sizeof(ctypes.c_uint8) )
#print("ctypes.c_uint64 size:%d" % ctypes.sizeof(ctypes.c_uint64) )
#print("POINTER_64_T size:%d" % ctypes.sizeof(POINTER_64_T(None)) )
#print("POINTER_32_T size:%d" % ctypes.sizeof(POINTER_32_T(None)) )
#print("POINTER_32_T =%s" % str(dir(POINTER_32_T(None))) )
# exit(0)

# Return the pointed type if this is a pointer, otherwise None.
def PointedType(tp):
	tpNam = tp.__name__

	if tpNam.startswith("LP_"):
		if tpNam.startswith("LP_c_") or tpNam.startswith("LP_4_") or tpNam.startswith("LP_8_"):
			# print("TRUE:"+tpNam[ 5: ])
			return tpNam[ 5: ]
		return None

	if tpNam == "c_void_p":
		return "void"

	return None

# 32 or 64 bits. Pointer size in bytes, on this platform.
def PointerSize():
	if isPtr64Target == iPtr64Platform:
		return ctypes.sizeof(ctypes.c_void_p)
	else:
		if isPtr64Target:
			return 8
		else:
			return 4

################################################################################

# This transforms a range of integer values into a regular expression
# matching them in a binary buffer.
# Width is typically one, two or four, but can be anything.
def ValuesListToRegexp( valList, width ):
	maxVals = max(valList)
	if maxVals < 256:
		subRegEx = "".join( r"\x%02x" % val for val in valList )
		pad = r"\x00" * ( width - 1 )
		# Maybe the values are contiguous but we do not care.
		return "[" + subRegEx + "]" + pad

	# For the moment, the other cases are not treated.
	raise Exception("Not implemented now")
################################################################################

# This transform a ctype class into a binary regular expression.
# TODO: Quand un des champs est un tableau, on devrait aller chercher la classe correspondante de ses elements.
def ConcatRegexes(theClass):
	pattern = ""
	try:
		clsRegex = theClass._regex_
	except AttributeError:
		clsRegex = {}

	for fld in theClass._fields_:
		fldNam = fld[0]
		fldOffset = getattr(theClass,fldNam).offset
		fldSize = getattr(theClass,fldNam).size

		try:
			# If there is a specific regular expression for this field.
			cnstrs = theClass._regex_[ fldNam ]
			# We do not know the content of the regular expression, so better enclose it.
			# pattern += "(" + cnstrs + ")"
			pattern += cnstrs
		except Exception: # AttributeError or KeyError
			# Otherwise we add a general pattern based on the field data type.
			if fld[1] in [ctypes.c_ushort,ctypes.c_short,ctypes.c_ulong,ctypes.c_long] :
				pattern += "." * fldSize
			else:
				pattern += "." * fldSize

	return pattern

class MemoryProcessorStructs:
	# We can have: re_flags=re.IGNORECASE
	def __init__(self,is64Bits,lstStructs,re_flags):
		# CA MARCHE AVEC PYTHON3
		from six.moves import builtins
		builtins.CTYPES_POINTER_TARGET_64 = is64Bits
		# print("Importing")
		# import CTypesStructs
		# print("Imported modules:"+str(sorted(sys.modules.keys())))

		class DefStruct:
			# We can have flags=re.IGNORECASE
			def __init__(self,structPatt,re_flags):
				self.m_rgxText = ConcatRegexes(structPatt)
				self.m_rgxComp = re.compile(self.m_rgxText.encode('utf-8'),re_flags)
				self.m_foundStructs = {}
				# TODO: On pourrait fabriquer une validation supplementaire si on connait
				# le sens ses types de donnees: Adresse IP, nom d utilisateur etc...
				try:
					self.m_validation = structPatt._validation_
				except AttributeError:
					self.m_validation = None

			# TODO: Should work with a ctypes struct
			def ValidDict(self,objDict):
				if self.m_validation:
					for keyMember in self.m_validation:
						funcPtr = self.m_validation[keyMember]
						# Should be there otherwise the validation is wrong.
						objMember = objDict[keyMember]
						if not funcPtr( objMember ):
							return False
				# All members validated, or not validation needed.
				return True

		self.m_byStruct = { theStr : DefStruct(theStr,flags) for theStr in lstStructs }


	# TODO: ON VOUDRAIT AJOUTER LA CONTRAINTE QUE LA MEMOIRE EST ALIGNEE COMME LA STRUCT. COMMENT FAIRE ??
	def ParseSegment(self,addr_beg, bytes_array):
		# print("Imported modules:"+str(sorted(sys.modules.keys())))
		# TODO: Fix this strange behaviour, when instantiating a class of this module.
		# Exception:global name 'CTypesStructs' is not defined
		# if sys.version_info < (3,):
		# import CTypesStructs
		# print("Processing %d bytes" % len(arr) )
		# namDisp = ",".join( str(theStr) for theStr in self.m_mapStructs )

		# print("Parse Segment")
		for keyStr in self.m_byStruct:
			structDefinition = self.m_byStruct[ keyStr ]
			structRegex = structDefinition.m_rgxComp

			# TODO: Performances:
			# TODO: Check only aligned addresses.
			# TODO: Use finditer
			matches = structRegex.findall( bytes_array )

			if not matches:
				continue

			#print("Structure=%s" % str(keyStr) )
			#print("Pattern=%s" % patt )
			# Pour chacun des elements, extraire les pointeurs et voir si les elements pointes
			# correspondent aux types.
			# Si ce n est pas une classe predefinie, on cherche dans notre dictionnaire
			# l'expression reguliere.

			for mtch in matches:
				# TODO: Reject non-aligned addresses.
				anObj = keyStr()
				fit = min(len(mtch), ctypes.sizeof(anObj))
				ctypes.memmove(ctypes.addressof(anObj), mtch, fit)

				# Maybe this object contains pointers.
				# TODO: Do that once only.
				# LE METTRE DANS UNE LISTE QUI CONTIENT LA DEFINITION DES FIELDS POINTEURS.
				for fld in keyStr._fields_:
					fieldNam = fld[0]
					fieldTyp = fld[1]

					# print("Nam="+fieldNam)

					# TODO: Check that the type of the pointer is compatible with its alignment.
					# TODO: The address just needs to be a multiple of the object size.
					# pointedTypNam = CTypesStructs.PointedType( fieldTyp )
					pointedTypNam = PointedType( fieldTyp )
					# MARCHEPAS ENCORE. VOYPNS D ABORD DES CAS FACILES.
					if False and pointedTypNam is not None:
						print("pointedTypNam="+str(pointedTypNam))
						pointedAddr = getattr( anObj, fieldNam )
						print("Pointer="+str(pointedAddr))
						print("Pointer="+str(dir(pointedAddr)))
						print("Pointer="+str(pointedAddr.from_param(pointedAddr)))

						if pointedTypNam == "char":
							# Specific processing for a char pointer because this is probably a string.
							rgb_buffer = ctypes.create_string_buffer(buffer_size)
							ctypes.memmove(rgb_buffer, getRgbBuffer(), buffer_size)
						else:
							# pointedTypSiz = CTypesStructs.PointerSize()
							pointedTypSiz = PointerSize()
							print("pointedTypSiz="+str(pointedTypSiz	))
							pointedTyp = type(pointedTypNam)
							pointedObj = pointedTyp()
							ctypes.memmove(ctypes.addressof(pointedObj), mtch, pointedTypSiz )

						# Prendre l object avec le bon type et refaire ca recursivement.
						# Faut mettre dans un cache les listes de champs pointeurs, par classe.
						# Tolerer despointeurs invalides surtout au debut.
						continue

				# TODO: Should use the validation functions immediately.
				structDefinition.m_foundStructs[ ctypes.addressof(anObj) ] = anObj

			# print("Total NbMatches=%d after filter=%d" % ( len(matches), len(dictResult) ) )

################################################################################

class MemoryProcessorRegex:
	# We can have: flags=re.IGNORECASE
	def __init__(self,is64Bits,aRegex, re_flags):
		DEBUG("aRegex=%s",aRegex)
		self.m_rgxComp = re.compile(aRegex.encode('utf-8'),re_flags)
		# self.m_matches = set()
		self.m_matches = dict()

	def ParseSegment(self,addr_beg, bytes_array):

		# TODO: Use finditer
		# mtch = self.m_rgxComp.findall( bytes_array )
		# self.m_matches.update( mtch )

		# The result is a dictionary whose key is the offset.
		# We assume that this offset can only be unique in the segment.
		for mtch in self.m_rgxComp.finditer(bytes_array):
			memOffset = addr_beg + mtch.start()
			self.m_matches[ memOffset ] = mtch.group()


################################################################################

# re flags=re.IGNORECASE
def MemoryProcessor(is64Bits,lstStructs_or_regex,re_flags):
	if isinstance(lstStructs_or_regex,list ):
		return MemoryProcessorStructs(is64Bits,lstStructs_or_regex,re_flags)
	else:
		return MemoryProcessorRegex(is64Bits,lstStructs_or_regex,re_flags)


################################################################################


if sys.platform == "win32":

	def WindowsError():
		errWin = ctypes.GetLastError()
		print("Err="+str(errWin))
		print("Err="+str(ctypes.WinError(errWin)))

		errKnl = kernel32.GetLastError()
		print("Err="+str(errKnl))
		print("Err="+str(ctypes.WinError(errKnl)))

		return str(ctypes.WinError(ctypes.GetLastError()))

	from ctypes import wintypes
	import win32con

	kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

	MEMORY_STATES = {0x1000: "MEM_COMMIT", 0x10000: "MEM_FREE", 0x2000: "MEM_RESERVE"}
	MEMORY_PROTECTIONS = {0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
						  0x40: "PAGEEXECUTE_READWRITE",
						  0x80: "PAGE_EXECUTE_WRITECOPY", 0x01: "PAGE_NOACCESS", 0x04: "PAGE_READWRITE",
						  0x08: "PAGE_WRITECOPY"}
	MEMORY_TYPES = {0x1000000: "MEM_IMAGE", 0x40000: "MEM_MAPPED", 0x20000: "MEM_PRIVATE"}

	# TODO: Cleanup.
	if ctypes.sizeof(ctypes.c_void_p) == 8:
		ctypes_SIZE_T = ctypes.c_ulonglong
	else:
		ctypes_SIZE_T = wintypes.UINT

	class MEMORY_BASIC_INFORMATION(ctypes.Structure):
		_fields_ = [
			("BaseAddress",       ctypes.c_void_p),
			("AllocationBase",    ctypes.c_void_p),
			("AllocationProtect", wintypes.DWORD),
			("RegionSize",        ctypes_SIZE_T),
			("State",             wintypes.DWORD),
			("Protect",           wintypes.DWORD),
			("Type",              wintypes.DWORD)
		]

	class PyMEMORY_BASIC_INFORMATION:
		def __init__(self, MBI):
			self.MBI = MBI
			self.BaseAddress = self.MBI.BaseAddress
			self.AllocationBase = self.MBI.AllocationBase
			self.AllocationProtect = MEMORY_PROTECTIONS.get(self.MBI.AllocationProtect, self.MBI.AllocationProtect)
			self.RegionSize = self.MBI.RegionSize
			self.State = MEMORY_STATES.get(self.MBI.State, self.MBI.State)
			# uncomment this and comment next line if you want to do a bitwise check on Protect.
			# self.Protect = self.MBI.Protect
			self.Protect = MEMORY_PROTECTIONS.get(self.MBI.Protect, self.MBI.Protect)
			self.Type = MEMORY_TYPES.get(self.MBI.Type, self.MBI.Type)

	def VirtualQueryEx(process_handle, address):
		# print("VirtualQueryEx Address=%0.16X" % address)
		MBI = MEMORY_BASIC_INFORMATION()
		MBI_pointer = ctypes.byref(MBI)
		size = ctypes.sizeof(MBI)

		success = kernel32.VirtualQueryEx(
			process_handle,
			address,
			MBI_pointer,
			size)

		if not success:
			errKnl = kernel32.GetLastError()
			errTxt = str(ctypes.WinError(errKnl))
			raise Exception("VirtualQueryEx Failed address=%0x size=%d error = %s" % ( address, size, errTxt))

		if success != size:
			raise Exception("VirtualQueryEx Failed because not all data was written.")

		#print("Leaving VirtualQueryEx")
		return PyMEMORY_BASIC_INFORMATION(MBI)

	# Returns an array of bytes
	def ReadMemory(process_handle, address, size):
		cbuffer = ctypes.c_buffer(size)

		zero = ctypes.c_ulong(0)
		czero = ctypes.byref(zero)

		success = kernel32.ReadProcessMemory( process_handle, address, cbuffer, size, czero)

		assert success, "ReadMemory Failed with success == %s and address == %s and size == %s.\n%s" % (
			success, address, size, ctypes.WinError(ctypes.GetLastError())[1])
		return cbuffer.raw

	def ScanFromPage(process_handle, page_address, mem_proc_functor ):
		#print("Entering ScanFromPage")
		information = VirtualQueryEx(process_handle, page_address)
		base_address = information.BaseAddress
		region_size = information.RegionSize
		next_region = base_address + region_size
		# print("Scanning from %0.16X next_region=%0.16X bytes=%s" % ( base_address, next_region, str(region_size) ) )

		# Filter out any pages that are not readable by returning the next_region address
		# and an empty list to represent no addresses found."""
		if information.Type != "MEM_PRIVATE" or \
						information.State != "MEM_COMMIT" or \
						information.Protect != "PAGE_READWRITE":
						# information.Protect not in ["PAGE_EXECUTE_READ", "PAGEEXECUTE_READWRITE", "PAGE_READWRITE"]:
			# print("Return next_region=%s"% str(next_region))
			return next_region

		# print("Before ReadMemory")
		# TODO: read the whole page into buffer. Should access memory without copy.
		page_bytes = ReadMemory(process_handle, base_address, region_size)
		#print("After ReadMemory")

		mem_proc_functor.ParseSegment(base_address,page_bytes)

		del page_bytes  # free the buffer
		# print("ScanFromPage leaving")
		return next_region

	def IsProcess64Bits(phandle):
		isOS64bits = platform.architecture()[0] == '64bit'

		# if ctypes.sizeof(ctypes.c_void_p) == 8:
		if isOS64bits:
			retVal = ctypes.c_int()
			kernel32.IsWow64Process(phandle, ctypes.byref(retVal))
			isWow64bit = (retVal.value != 0)
			return not isWow64bit
		else:
			return False

	def GetAddressRange():
		# So we can check if ctypes works as expected.
		class SYSTEM_INFO(ctypes.Structure):
			_fields_ = [
				("wProcessorArchitecture",      wintypes.WORD),
				("wReserved",                   wintypes.WORD),
				("dwPageSize",                  wintypes.DWORD),
				("lpMinimumApplicationAddress", wintypes.LPVOID),
				("lpMaximumApplicationAddress", wintypes.LPVOID),
				("dwActiveProcessorMask",       wintypes.LPVOID),
				("dwNumberOfProcessors",        wintypes.DWORD),
				("dwProcessorType",             wintypes.DWORD),
				("dwAllocationGranularity",     wintypes.DWORD),
				("wProcessorLevel",             wintypes.WORD),
				("wProcessorRevision",          wintypes.WORD)]

		si = SYSTEM_INFO()
		psi = ctypes.byref(si)
		kernel32.GetSystemInfo(psi)

		if False:
			print("System Info")
			for ksi in si._fields_:
				toto = getattr(si,ksi[0])
				# print("    %-30s %20s %s", (ksi[0], str(getattr(si,ksi[0])), str(dir(getattr(si,ksi[0]) ) ) ) )
				print("    %-30s %20s %d" % (ksi[0], str(getattr(si,ksi[0])), getattr(SYSTEM_INFO,ksi[0]).size ) )
			print("")

			try:
				arch = {
					9:"PROCESSOR_ARCHITECTURE_AMD64",
					5:"PROCESSOR_ARCHITECTURE_ARM",
					6:"PROCESSOR_ARCHITECTURE_IA64",
					0:"PROCESSOR_ARCHITECTURE_INTEL",
					0xffff:"PROCESSOR_ARCHITECTURE_UNKNOWN"
				}[ getattr(si,"wProcessorArchitecture") ]
			except KeyError:
				arch = "Unknown"
			print("Architecture=%s" % arch )

			try:
				procType = {
					386: "PROCESSOR_INTEL_386",
					486: "PROCESSOR_INTEL_486",
					586: "PROCESSOR_INTEL_PENTIUM",
					2200: "PROCESSOR_INTEL_IA64",
					8664: "PROCESSOR_AMD_X8664"
				}[ getattr(si,"dwProcessorType") ]
			except KeyError:
				# PROCESSOR_ARM (Reserved)
				prcType = "Unknown"
			print("Processor type=%s" % procType )
			print("")

		return ( si.lpMinimumApplicationAddress, si.lpMaximumApplicationAddress )

	def MemMachine(pidint,lstStructs,re_flags):
		kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

		# PROCESS_ALL_ACCESS, # alternative access right for debugging.
		# TODO: NOT SURE I NEED PROCESS_VM_WRITE !
		ACCESS = win32con.PROCESS_VM_READ | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_VM_WRITE | win32con.PROCESS_QUERY_INFORMATION
		# ACCESS = win32con.PROCESS_VM_READ | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_QUERY_INFORMATION

		# kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

		DEBUG("MemMachine pidint=%s", str(pidint) )
		phandle = kernel32.OpenProcess( ACCESS, False, pidint)
		DEBUG("MemMachine phandle=%s", str(phandle) )
		sys.stderr.write("MemMachine GetLastError=%s\n" % str(ctypes.GetLastError()) )

		# No need to prefix with ctypes on Python 3. Why ?
		assert phandle, "Failed to open process!\n%s" % ctypes.WinError(ctypes.GetLastError())[1]


		is64bits = IsProcess64Bits(phandle)
		DEBUG("MemMachine is64bits=%d", is64bits)
		mem_proc_functor = MemoryProcessor(is64bits,lstStructs,re_flags)

		# First address of the first page, and last address to scan.
		( base_address , max_address ) = GetAddressRange()

		allFound = list()
		page_address = base_address

		while page_address < max_address:

			try:
				next_page = ScanFromPage(phandle, page_address, mem_proc_functor)
			except ctypes.ArgumentError:
				DEBUG("MemMachine Address overflow: %s", str(page_address) )
				break
			except Exception:
				t, e = sys.exc_info()[:2]
				sys.stderr.write("MemMachine Other exception:%s\n"%str(e).replace("\n"," "))
				break

			page_address = next_page

			if not is64bits and page_address == 0x7FFF0000:
				sys.stderr.write("MemMachine End of 32bits process memory on Windows\n")
				break

			if len(allFound) >= 1000000:
				sys.stderr.write("[Warning] Scan ended early because too many addresses were found to hold the target data.\n")
				break
		sys.stderr.write("MemMachine leaving\n")
		return mem_proc_functor

else:
	## Partial interface to ptrace(2), only for PTRACE_ATTACH and PTRACE_DETACH.
	c_ptrace = ctypes.CDLL("libc.so.6").ptrace
	c_pid_t = ctypes.c_int32 # This assumes pid_t is int32_t
	c_ptrace.argtypes = [ctypes.c_int, c_pid_t, ctypes.c_void_p, ctypes.c_void_p]

	def ptrace(attach, pid):
		op = ctypes.c_int(16 if attach else 17) #PTRACE_ATTACH or PTRACE_DETACH
		c_pid = c_pid_t(pid)
		null = ctypes.c_void_p()
		err = c_ptrace(op, c_pid, null, null)
		if err != 0: raise Exception('ptrace' + str(err) )


	def GetMemoryFromProc(pidint,addr_beg,addr_end, mem_proc_functor):
		ptrace(True, pidint)
		try:
			# http://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
			# waitpid(pid, NULL, 0);
			# time.sleep(0.1)
			filnam = "/proc/%d/mem" % pidint
			statinfo = os.stat(filnam)
			sys.stderr.write("filnam="+filnam+" stats="+str(statinfo)+"\n")
			# mem_file = open(filnam, 'r+b', 0)
			mem_file = open(filnam, 'r', 0)
			lenAddr = addr_end - addr_beg
			DEBUG("len=%d",lenAddr)
			if False:
				# Exception:mmap length is greater than file size
				# Je crois me souvenir qu on peut empecher un controle de taille ??
				mm = mmap.mmap(mem_file.fileno(), lenAddr, access=mmap.ACCESS_READ, offset = addr_beg)
				mem_proc_functor.ParseSegment(addr_beg, mm.something)
			else:
				# Must read exactly the section, otherwise "Input/output error"
				mem_file.seek(addr_beg)  # seek to region start
				chunk = mem_file.read(lenAddr)  # read region contents
				mem_proc_functor.ParseSegment(addr_beg, chunk )

		except Exception as exc:
			WARNING("Exception:%s",str(exc))
			pass
		ptrace(False, pidint)


	def GetMemMaps(pidint):
		# TODO: Replace this by scanning /proc/<pid>/mmaps
		p = CIM_Process.PsutilGetProcObj(pidint)

		# Depending on psutil version.
		try:
			return p.get_memory_maps(grouped=False)
		except AttributeError:
			# New version.
			return p.memory_maps(grouped=False)

	def MemMachine(pidint,lstStructs,re_flags):
		# TODO: 64 bits by default :):):) ... Fix this !
		DEBUG("MemMachine pidint=%d",pidint)
		mem_proc_functor = MemoryProcessor(True,lstStructs,re_flags)
		memmaps = GetMemMaps(pidint)
		# Typical content for map.path
		#
		# pmmap_ext(addr='7f1650f5f000-7f1650f60000', perms='rw-p', path='/usr/lib64/ld-2.21.so', 
		#    rss=4096, size=4096, pss=4096, shared_clean=0, shared_dirty=0, private_clean=0, 
		#    private_dirty=4096, referenced=4096, anonymous=4096, swap=0)
		# pmmap_ext(addr='7f1650f60000-7f1650f61000', perms='rw-p', path='[anon]', 
		#    rss=4096, size=4096, pss=4096, shared_clean=0, shared_dirty=0, private_clean=0, 
		#    private_dirty=4096, referenced=4096, anonymous=4096, swap=0)
		# pmmap_ext(addr='7ffd18c38000-7ffd18d20000', perms='rw-p', path='[stack]', 
		#    rss=946176, size=954368, pss=946176, shared_clean=0, shared_dirty=0, private_clean=0, 
		#    private_dirty=946176, referenced=946176, anonymous=946176, swap=0)
		# pmmap_ext(addr='7ffd18de1000-7ffd18de3000', perms='r--p', path='[vvar]', 
		#    rss=0, size=8192, pss=0, shared_clean=0, shared_dirty=0, private_clean=0, 
		#    private_dirty=0, referenced=0, anonymous=0, swap=0)

		# /dev/dri/card0
		# [heap]
		# [stack]
		# [stack:10025]
		# /SYSV00000000 (deleted)
		# [vdso]
		# [vsyscall]
		# [vvar]

		# Path is blank for anonymous mapped regions.
		# There are also special regions with names like [heap], [stack], or [vdso]. 
		# [vdso] stands for virtual dynamic shared object. 
		# It is used by system calls to switch to kernel mode.

		# Memory mapping is not only used to map files into memory 
		# but is also a tool to request RAM from kernel. 
		# These are those inode 0 entries - stack, heap, bss segments and more

		# r = read
		# w = write
		# x = execute
		# s = shared
		# p = private (copy on write)

		for map in memmaps:

			# sys.stderr.write("MemMachine map.path=%s\n"%str(map))

			if map.path in ["[heap]",""] or map.path.startswith("[stack"):
				addr_beg, addr_end = ( int( ad, 16 ) for ad in map.addr.split("-") )
				# sys.stderr.write("MemMachine %d %d %s\n" % (addr_beg, addr_end, map.path) )
				GetMemoryFromProc(pidint, addr_beg, addr_end, mem_proc_functor )
		DEBUG("MemMachine pidint=%d leaving",pidint)
		return mem_proc_functor

# TODO: Should apply the extra validation before creating the dict.
def CTypesStructToDict(struct):
	def get_value(value):
		if (type(value) in lib_util.six_integer_types + ( float, bool ) ):
			return value

		if hasattr(value, "_length_") and hasattr(value, "_type_"):
			if getattr(value, "_type_") in [ ctypes.c_ubyte, ctypes.c_char ]:
				strLen = getattr(value, "_length_")
				ar = ""
				for vv in value:
					gvv = get_value(vv)
					if gvv == 0:
						break
					ar += chr(gvv)
				# Optionaly extends the string
				ar += " " * ( strLen - len(ar))
				# return "[" + ar + "]"
				return ar
			else:
				return [ get_value(elt) for elt in value ]

		if hasattr(value, "_type_"):
			if getattr(value, "_type_") == ctypes.c_char:
				return ctypes.string_at(ctypes.addressof(value))
			else:
				return "Pointer=" + str(getattr(value, "_type_"))

		if hasattr(value, "_fields_"):
			# Probably another struct
			return CTypesStructToDict(value)

		return value

	result = {}
	for fld in struct._fields_:
		fieldNam = fld[0]
		valAttr = getattr(struct, fieldNam)
		# if the type is not a primitive and it evaluates to False ...
		value = get_value(valAttr)
		result[fieldNam] = value
	return result

################################################################################

# This returns all the strings matching the regular expression.
def GetRegexMatches(pidint,the_regex,re_flags=0):
	mem_proc_functor = MemMachine( pidint, the_regex,re_flags)
	return mem_proc_functor.m_matches

################################################################################


def ProcessMemoryScan(pidint, lstStructs, maxDisplay,verbose):
	if verbose:
		ProcessMemoryScanVerbose(pidint, lstStructs, maxDisplay)
	else:
		ProcessMemoryScanNonVerbose(pidint, lstStructs, maxDisplay)

def ProcessMemoryScanNonVerbose(pidint, lstStructs, maxDisplay,re_flags=0):
	mem_proc_functor = MemMachine( pidint, lstStructs, re_flags )
	byStruct = mem_proc_functor.m_byStruct

	dictByStructs = dict()

	# sys.stderr.write("Keys number:%d\n" % len(byStruct) )
	for keyStr in byStruct:
		structDefinition = byStruct[keyStr]
		objsSet = structDefinition.m_foundStructs
		sys.stderr.write("%0.60s : %d occurences before validation\n" % (keyStr, len( objsSet ) ) )

		maxCnt = maxDisplay

		# Sorted by address.
		dictByAddrs = dict()
		for addrObj in sorted(objsSet):
			# In case of too many data.
			maxCnt -= 1
			if maxCnt == 0:
				break

			anObj = objsSet[addrObj]

			objDict = CTypesStructToDict(anObj)

			# TODO: Should be done before creating the object.
			if structDefinition.ValidDict(objDict):
				dictByAddrs[addrObj] = objDict
		dictByStructs[keyStr] = dictByAddrs

	sys.stderr.write(str(dictByStructs) + "\n")

def ProcessMemoryScanVerbose(pidint, lstStructs, maxDisplay, re_flags = 0):
	mem_proc_functor = MemMachine( pidint, lstStructs, re_flags )
	byStruct = mem_proc_functor.m_byStruct

	# print("Keys number:%d" % len(byStruct) )
	for keyStr in byStruct:
		structDefinition = byStruct[keyStr]
		objsSet = structDefinition.m_foundStructs
		print("%0.60s : %d occurences before validation" % (keyStr, len( objsSet ) ) )

		maxCnt = maxDisplay

		# Sorted by address.
		for addrObj in sorted(objsSet):
			# In case of too many data.
			maxCnt -= 1
			if maxCnt == 0:
				break

			anObj = objsSet[addrObj]

			def PrintDict(margin,ddd):
				for k in ddd:
					v = ddd[k]
					if isinstance( v, dict ):
						print("%s %-20s:" % ( margin, k ) )
						PrintDict(margin+"      ",v)
					else:
						print("%s %-20s: %-60s" % ( margin, k , v ) )

			objDict = CTypesStructToDict(anObj)

			# TODO: Should be done before creating the object.
			if structDefinition.ValidDict(objDict):
				# print("Valid")
				print("Address:%0.16X"%addrObj)
				PrintDict("      ",objDict)

################################################################################

# Entry point for testing scripts.
def DoAll(lstStructs,verbose=True):
	print("Starting")
	if len(sys.argv) > 1:
		maxDisplay = int(sys.argv[2])
	else:
		maxDisplay = 10

	# python -m cProfile mmapregex.py
	if len(sys.argv) > 2:
		pidint = int(sys.argv[1])
		ProcessMemoryScan(pidint, lstStructs, maxDisplay,verbose)
	else:
		for i in CIM_Process.ProcessIter():
			print("Pid=%d name=%s" % ( i.pid, i.name() ) )
			try:
				ProcessMemoryScan(i.pid, lstStructs, maxDisplay,verbose)
				print("")
			except Exception:
				t, e = sys.exc_info()[:2]
				print("    Caught:"+str(e).replace("\n"," "))
				print("")



# Not used yet but kept as informaitonal purpose.
# if sys.platform == "win32":
# 	# http://stackoverflow.com/questions/12712585/readprocessmemory-with-ctypes
#
# 	from ctypes import wintypes
# 	kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
# 	rPM = kernel32.ReadProcessMemory
# 	rPM.argtypes = [wintypes.HANDLE,wintypes.LPCVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
# 	rPM.restype = wintypes.BOOL
#
# 	class PROCESS_HEAP_ENTRY_BLOCK(ctypes.Structure):
# 		_fields_ = [("hMem", wintypes.HANDLE),
# 					("dwReserved", wintypes.DWORD * 3)]
#
# 	class PROCESS_HEAP_ENTRY_REGION(ctypes.Structure):
# 		_fields_ = [("dwCommittedSize", wintypes.DWORD),
# 					("dwUnCommittedSize", wintypes.DWORD),
# 					("lpFirstBlock", wintypes.LPVOID),
# 					("lpLastBlock", wintypes.LPVOID)]
#
# 	class PROCESS_HEAP_ENTRY_UNION(ctypes.Union):
# 		_fields_ = [("Block", PROCESS_HEAP_ENTRY_BLOCK),
# 					("Region", PROCESS_HEAP_ENTRY_REGION)]
#
# 	class PROCESS_HEAP_ENTRY (ctypes.Structure):
# 		_anonymous_ = ("u",)
# 		_fields_ = [("lpData", wintypes.LPVOID),
# 					("cbData", wintypes.DWORD),
# 					("cbOverhead", wintypes.BYTE),
# 					("iRegionIndex", wintypes.BYTE),
# 					("wFlags", wintypes.WORD),
# 					("u", PROCESS_HEAP_ENTRY_UNION)]
#
# 	def GetHeapsLocal():
# 		global kernel32
#
# 		GetProcessHeaps = kernel32.GetProcessHeaps
# 		GetProcessHeaps.restype = wintypes.DWORD
# 		GetProcessHeaps.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
#
# 		HeapWalk = kernel32.HeapWalk
# 		HeapWalk.restype = wintypes.BOOL
# 		HeapWalk.argtypes = [ wintypes.HANDLE, ctypes.POINTER(PROCESS_HEAP_ENTRY)]
#
# 		heapCount = GetProcessHeaps(0, None)
# 		if not heapCount:
# 			print( "Failed to get heap count:" + str( ctypes.get_last_error()) )
# 			return None  # Failed; don't care
# 		heaps = (wintypes.HANDLE * heapCount)()
# 		heapCount = GetProcessHeaps(len(heaps), heaps)
# 		if heapCount == 0:
# 			print( "Failed to get heaps:" + str( ctypes.get_last_error()) )
# 			return None
#
# 		result = []
#
# 		for heap in heaps[:heapCount]:
# 			entry = PROCESS_HEAP_ENTRY()
# 			entry.lpData = None
# 			while HeapWalk(heap, entry):
# 				result.append( entry )
# 				#print("dir="+str(dir(entry)))
# 				#print("_fields_="+str(entry._fields_))
# 				print("lpData="+str(entry.lpData))
# 				print("cbData="+str(entry.cbData))
# 				#print("cbOverhead="+str(entry.cbOverhead))
# 				#print("iRegionIndex="+str(entry.iRegionIndex))
# 				#print("u="+str(entry.u))
# 				#print("wFlags="+str(entry.wFlags))
#
# 		return result
#



# re.match(b"\0x0000|\0x1000","\0x1000")
# _sre.SRE_Match object at 0x0000000002A6F098>

# "|".join(("0x%04x" % x for x in range(0,3)))
# '0x0000|0x0001|0x0002'

# re.match( "|".join(("0x%04x" % x for x in range(0,3))) , "\0x1000")

# print("|".join("\\0x%04x" % i for i in range(0,3))+"|\\0xF008")
# \0x0000|\0x0001|\0x0002|\0xF008
#
# Ca marche.
# re.match( "|".join("\\0x%04x" % i for i in range(0,1000))+"|\\0xF008", b"\0x2100")

# Exmples d expressions regulieres:
# pat = re.compile(b'[a-f]+\d+')
# If you want to check that the string contains only characters between chr(0) and chr(10), simply use
# re.match('^[\0-\x0A]*$',data)
# For Python3, you can do the same with byte strings:
# re.match(b'^[\0-\x0A]*$',b'\x01\x02\x03\x04')

