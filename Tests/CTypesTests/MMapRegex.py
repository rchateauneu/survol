#!/usr/bin/python

import ctypes
import time
import mmap
import sys
import six
import os
import re

################################################################################

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

# TODO: Quand un des champs est un tableau, on devrait aller chercher la classe correspondante de ses elements.
def MakePattern(theClass,extraConstraints={}):
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
			pattern += "(" + cnstrs + ")"
		except Exception: # AttributeError or KeyError
			# Otherwise we add a general pattern based on the field data type.
			if fld[1] in [ctypes.c_ushort,ctypes.c_short,ctypes.c_ulong,ctypes.c_long] :
				pattern += "." * fldSize
			else:
				pattern += "." * fldSize

			# print( fldNam )
			# print( str(fld[1]) )
	return pattern





# ATTENTION PROBLEMES DE PORTABILITE !!!

# Sinon: Exception:global name 'StructDict64_ctypes' is not defined
#from six.moves import builtins
#builtins.CTYPES_POINTER_TARGET_64 = True
#import StructDict64_ctypes
# Sinon: Exception:global name 'POINTER_T' is not defined
# POINTER_T = ctypes.POINTER







class MemoryProcessor:
	def __init__(self,is64Bits):
		# CA MARCHE AVEC PYTHON3
		from six.moves import builtins
		builtins.CTYPES_POINTER_TARGET_64 = is64Bits
		# print("Importing")
		import StructDict64_ctypes
		# print("Imported modules:"+str(sorted(sys.modules.keys())))

		for theStr in StructDict64_ctypes.lstStructs:
			print("%s Size=%d type=%s %s ]" % (theStr, ctypes.sizeof(theStr), type(theStr), str(dir(theStr))  ) )

		# exit(0)

		self.m_mapStructs = { theStr : MakePattern(theStr) for theStr in StructDict64_ctypes.lstStructs }

	def ParseSegment(self,arr):
		# print("Imported modules:"+str(sorted(sys.modules.keys())))
		# TODO: Fix this strange behaviour, when instantiating a class of this module.
		# Exception:global name 'StructDict64_ctypes' is not defined
		if sys.version_info < (3,):
			import StructDict64_ctypes
		print("Processing %d bytes" % len(arr) )
		# namDisp = ",".join( str(theStr) for theStr in self.m_mapStructs )
		for keyStr in self.m_mapStructs:
			patt = self.m_mapStructs[ keyStr ]
			print("Struct=%s" % str(keyStr) )

			matches = re.findall( patt.encode('utf-8'), arr )

			print("NbMatches=%d" % len(matches) )
			# Pour chacun des elements, extraire les pointeurs et voir si les elements pointes
			# correspondent aux types.
			# Si ce n est pas une classe predefinie, on cherche dans notre dictionnaire
			# l'expression reguliere.

			objsList = []
			for mtch in matches:
				# print("Object creation")
				# print("type=%s" % type(keyStr))
				# print("typeAs=%s" % str(keyStr))
				# anObj = StructDict64_ctypes.keyStr()
				anObj = keyStr()
				# print("After creation")
				fit = min(len(mtch), ctypes.sizeof(anObj))
				# print("fit=%d" % fit)
				ctypes.memmove(ctypes.addressof(anObj), mtch, fit)

				# Maybe this object contains pointers.
				# TODO: Do that once only.
				# LE METTRE DANS UNE LISTE QUI CONTIENT LA DEFINITION DES FIELDS POINTEURS.
				for fld in keyStr._fields_:
					fieldNam = fld[0]
					fieldTyp = fld[1]

					print("Nam="+fieldNam)
					pointedTypNam = StructDict64_ctypes.PointedType( fieldTyp )
					if pointedTypNam is not None:
						pointedAddr = getattr( anObj, fieldNam )
						print("Pointer="+str(pointedAddr))
						print("Pointer="+str(dir(pointedAddr)))
						print("Pointer="+str(pointedAddr.from_param(pointedAddr)))
						pointedTypSiz = StructDict64_ctypes.PointerSize()
						pointedTyp = type(pointedTypNam)
						pointedObj = pointedTyp()
						ctypes.memmove(ctypes.addressof(pointedObj), mtch, pointedTypSiz )

						# Prendre l object avec le bon type et refaire ca recursivement.
						# Faut mettre dans un cache les listes de champs pointeurs, par classe.
						# Tolerer despointeurs invalides surtout au debut.
						continue


				objsList.append( ( mtch, anObj ) )

			print("Matched %d times" % len(objsList) )
			for mtch, anObj in objsList[:3]:
				print(str((mtch,anObj)))
				print(str(mtch))
				print(type(mtch))
				# print("  "+str(anObj.path))
				# print("  "+str(anObj._fields_))
				print(dir(anObj))
				for fld in anObj._fields_:
					fldNam = fld[0]
					print("    " + fldNam + ":" + str(getattr(anObj, fldNam ) ) )
				print("  "+str(getdict(anObj)))
			# print(str(objsList[:3]))
		#if keyStr in [ struct_iobuf ]:
		#	print(str(matches[:3]))
		#if keyStr in [ struct_FixedString, struct_Url]:
		# if keyStr in [ struct_FixedString]:
		#	print(str(matches[:3]))



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

if sys.platform == "win32":

	from ctypes import wintypes
	import win32con

	kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

	MEMORY_STATES = {0x1000: "MEM_COMMIT", 0x10000: "MEM_FREE", 0x2000: "MEM_RESERVE"}
	MEMORY_PROTECTIONS = {0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
						  0x40: "PAGEEXECUTE_READWRITE",
						  0x80: "PAGE_EXECUTE_WRITECOPY", 0x01: "PAGE_NOACCESS", 0x04: "PAGE_READWRITE",
						  0x08: "PAGE_WRITECOPY"}
	MEMORY_TYPES = {0x1000000: "MEM_IMAGE", 0x40000: "MEM_MAPPED", 0x20000: "MEM_PRIVATE"}

	class MEMORY_BASIC_INFORMATION(ctypes.Structure):
		_fields_ = [
			("BaseAddress",       ctypes.c_void_p),
			("AllocationBase",    ctypes.c_void_p),
			("AllocationProtect", wintypes.DWORD),
			("RegionSize",        wintypes.UINT),
			("State",             wintypes.DWORD),
			("Protect",           wintypes.DWORD),
			("Type",              wintypes.DWORD)
		]

	class PyMEMORY_BASIC_INFORMATION:
		def __init__(self, MBI):
			self.MBI = MBI
			self.set_attributes()

		def set_attributes(self):
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
		MBI = MEMORY_BASIC_INFORMATION()
		MBI_pointer = ctypes.byref(MBI)
		size = ctypes.sizeof(MBI)

		success = kernel32.VirtualQueryEx(
			process_handle,
			address,
			MBI_pointer,
			size)

		if not success:
			print("VirtualQueryEx Failed address=%s, error = %s" % ( str(address), str(ctypes.WinError(ctypes.GetLastError())[1])))
			return 0

		if success != size:
			print("VirtualQueryEx Failed because not all data was written.")
			return 0
		return PyMEMORY_BASIC_INFORMATION(MBI)


	def ReadMemory(process_handle, address, size):
		cbuffer = ctypes.c_buffer(size)

		zero = ctypes.c_ulong(0)
		czero = ctypes.byref(zero)

		# ctypes.ArgumentError: argument 5: <class 'TypeError'>: expected LP_c_ulong instance instead of int
		success = kernel32.ReadProcessMemory(
			process_handle,
			address,
			cbuffer,
			size,
			czero)

		assert success, "ReadMemory Failed with success == %s and address == %s and size == %s.\n%s" % (
			success, address, size, ctypes.WinError(ctypes.GetLastError())[1])
		return cbuffer.raw

	def scan_page(process_handle, page_address, mem_proc_functor):
		information = VirtualQueryEx(process_handle, page_address)
		base_address = information.BaseAddress
		region_size = information.RegionSize
		next_region = base_address + region_size
		found = []

		# Filter out any pages that are not readable by returning the next_region address
		# and an empty list to represent no addresses found."""
		if information.Type != "MEM_PRIVATE" or \
						information.State != "MEM_COMMIT" or \
						information.Protect not in ["PAGE_EXECUTE_READ", "PAGEEXECUTE_READWRITE", "PAGE_READWRITE"]:
			return next_region, []

		# read the whole page into buffer.
		page_bytes = ReadMemory(process_handle, base_address, region_size)

		mem_proc_functor.ParseSegment(page_bytes)

		del page_bytes  # free the buffer
		return next_region, found

	def IsProcess64Bits(phandle):
		retVal = ctypes.c_int()
		kernel32.IsWow64Process(phandle, ctypes.byref(retVal))
		is64bit = (retVal.value != 0)
		return is64bit

	def MemMachine(pidint):
		kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)



		# PROCESS_ALL_ACCESS, # alternative access right for debugging.
		# TODO: NOT SURE I NEED PROCESS_VM_WRITE !
		# ACCESS = win32con.PROCESS_VM_READ | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_VM_WRITE | win32con.PROCESS_QUERY_INFORMATION
		ACCESS = win32con.PROCESS_VM_READ | win32con.PROCESS_VM_OPERATION | win32con.PROCESS_QUERY_INFORMATION

		# kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

		print("pidint=%s" % str(pidint) )
		phandle = kernel32.OpenProcess( ACCESS, False, pidint)
		print("phandle=%s" % str(phandle) )
		# print("GetLastError=%s" % str(ctypes.GetLastError()) )

		# No need to prefix with ctypes on Python 3. Why ?
		assert phandle, "Failed to open process!\n%s" % ctypes.WinError(ctypes.GetLastError())[1]


		is64bits = IsProcess64Bits(phandle)
		print("is64bits=%d" % is64bits)
		mem_proc_functor = MemoryProcessor(is64bits)

		class SYSTEM_INFO(ctypes.Structure):
			_fields_ = [
				("wProcessorArchitecture",      wintypes.WORD),
				("wReserved",                   wintypes.WORD),
				("dwPageSize",                  wintypes.DWORD),
				("lpMinimumApplicationAddress", wintypes.DWORD),
				("lpMaximumApplicationAddress", wintypes.DWORD),
				("dwActiveProcessorMask",       wintypes.DWORD),
				("dwNumberOfProcessors",        wintypes.DWORD),
				("dwProcessorType",             wintypes.DWORD),
				("dwAllocationGranularity",     wintypes.DWORD),
				("wProcessorLevel",             wintypes.WORD),
				("wProcessorRevision",          wintypes.WORD)]

		si = SYSTEM_INFO()
		psi = ctypes.byref(si)
		kernel32.GetSystemInfo(psi)

		print("System Info")
		# print("%s" % dir(si))
		for ksi in si._fields_:
			print("    %-30s %20s" % (ksi[0],str(getattr(si,ksi[0]))) )
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

		# First address of the first page to scan.
		base_address = si.lpMinimumApplicationAddress
		# Last address to scan.
		max_address = si.lpMaximumApplicationAddress

		# TEMP
		base_address = 65536
		max_address = 1000000


		found = list()
		page_address = base_address

		while page_address < max_address:

			next_page, f = scan_page(phandle, page_address, mem_proc_functor)
			found.extend(f)
			page_address = next_page

			if len(found) >= 60000000:
				print("[Warning] Scan ended early because too many addresses were found to hold the target data.")
				break
		return

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
			print("filnam="+filnam+" stats="+str(statinfo))
			# mem_file = open(filnam, 'r+b', 0)
			mem_file = open(filnam, 'r', 0)
			lenAddr = addr_end - addr_beg
			print("len=%d"%lenAddr)
			if False:
				# Exception:mmap length is greater than file size
				# Je crois me souvenir qu on peut empecher un controle de taille ??
				mm = mmap.mmap(mem_file.fileno(), lenAddr, access=mmap.ACCESS_READ, offset = addr_beg)
				mem_proc_functor.ParseSegment( mm.something )
			else:
				# Must read exactly the section, otherwise "Input/output error"
				mem_file.seek(addr_beg)  # seek to region start
				chunk = mem_file.read(lenAddr)  # read region contents
				mem_proc_functor.ParseSegment( chunk )

		except Exception as exc:
			print("Exception:"+str(exc))
			pass
		ptrace(False, pidint)


	def GetMemMaps(pidint):
		# TODO: Replace this by scanning /proc/<pid>/mmaps
		import psutil
		p = psutil.Process(pidint)

		# Depending on psutil version.
		try:
			return p.get_memory_maps(grouped=False)
		except AttributeError:
			return p.memory_maps(grouped=False)

	def MemMachine(pidint):
		# TODO: 64 bits by default :):):) ... Fix this !
		mem_proc_functor = MemoryProcessor(True)
		memmaps = GetMemMaps(pidint)
		for map in memmaps:
			if '[heap]' in map.path:
				#	print(map.addr)
				addr_beg, addr_end = ( int( ad, 16 ) for ad in map.addr.split("-") )
				# print("%d %d %s" % (addr_beg, addr_end, map.path) )
				GetMemoryFromProc(pidint, addr_beg, addr_end, mem_proc_functor)

def getdict(struct):
	result = {}
	#print struct
	def get_value(value):
		# if (type(value) not in [int, long, float, bool]) and not bool(value):
		if (type(value) not in six.integer_types + ( float, bool ) ) and not bool(value):
			# it's a null pointer
			value = None
		elif hasattr(value, "_length_") and hasattr(value, "_type_"):
			# Probably an array
			#print value
			value = get_array(value)
		elif hasattr(value, "_fields_"):
			# Probably another struct
			value = getdict(value)
		return value
	def get_array(array):
		ar = []
		for value in array:
			value = get_value(value)
			ar.append(value)
		return ar
	for fld in struct._fields_:
		fieldNam = fld[0]
		value = getattr(struct, fieldNam)
		# if the type is not a primitive and it evaluates to False ...
		value = get_value(value)
		result[fieldNam] = value
	return result

if sys.platform == "win32":
	# JUSTE POUR LES TESTS !!!!!
	pidint = 12572 # Ramp
	pidint = 8864 # Ramp
else:
	pidint = 3272

if len(sys.argv) > 0:
	pidint = int(sys.argv[1])

MemMachine( pidint )

